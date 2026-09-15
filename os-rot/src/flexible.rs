// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::alloc::{Layout, alloc_zeroed, handle_alloc_error};

use crate::Error;
use crate::ffi::OsRotCerts;

/// Upper bound (arbitrarily chosen) on the trailing array we'll allocate for.
pub(crate) const MAX_FLEXIBLE_BYTES: usize = 16 * 1024 * 1024;

/// This trait is meant to be implemented for a C structure that contains an
/// error field, followed by a count field and ends with a flexible array member
/// like so:
///
/// ```c
/// struct {
///     uint32_t error;
///     uint32_t count;
///     Item items[];
/// }
/// ```
///
/// Once implemented, users can call [`alloc_flexible_struct`] to get back a
/// `Box<Self>` that contains the error and count header followed by a trailing
/// `[Self::Item]` array (a dynamically-sized type) sized for the supplied
/// `capacity`.
///
/// # Safety
///
/// Implementers must guarantee that:
///
/// - `Self` is a `#[repr(C)]` DST whose only unsized field is a trailing
///   `[Self::Item]` prefixed by a `u32` error value at offset 0, a `u32` count
///   at offset 4, the field that [`alloc_flexible_struct`] writes `capacity`
///   into. Its layout must match
///   `Layout::new::<[u32; 2]>().extend(Layout::array::<Self::Item>(n)).pad_to_align()`
///   for every `n`, so the `Box`'s drop frees the same layout that was
///   allocated.
/// - [`Self::repair_vtable`] reinterprets the input pointer as `Self`. Both
///   pointers are "fat pointers" that contain an address and length so rust
///   allows us to "cast" between them, however attempting to use one type as
///   the other would be undefined behavior. This "fat pointer"/layout is used
///   by `Box` and its drop method. To better visualize this layout consider the
///   following:
///
/// ```text
///  *mut [Self::Item]
///     ┌── fat pointer ─┐
///  ┌───────────┬──────────────┐
///  │ data_ptr  │  len: usize  │
///  └───────────┴──────────────┘
///          │
///          ▼
///          ┌──────────┬──────────┬── ... ──┬─────────────┐
///          │  Item[0] │  Item[1] │         │ Item[len-1] │
///          └──────────┴──────────┴── ... ──┴─────────────┘
///
///     │
///     │ `p as *mut Self` cast
///     ▼
///
///  *mut Self
///     ┌── fat pointer ─┐
///  ┌───────────┬──────────────┐
///  │ data_ptr  │  len: usize  │
///  └───────────┴──────────────┘
///          │
///          ▼
///          ┌───────────┬───────────┬─────────┬─────────┬─ ... ─┬─────────────┐
///          │   error   │   count   │ Item[0] │ Item[1] │       │ Item[len-1] │
///          └───────────┴───────────┴─────────┴─────────┴─ ... ─┴─────────────┘
///          └─size_of::<[u32; 2]>()─┘└─────── len * size_of::<Item>() ────────┘
/// ```
pub(crate) unsafe trait FlexibleArrayMember {
    /// Element type of the trailing flexible array member.
    type Item;

    /// Reinterpret a slice pointer as a pointer to `Self`, preserving its
    /// address and length metadata. This implementation must *always* be
    /// `p as *mut Self`.
    ///
    /// NB: we don't have a default implementation in this trait because Rust's
    /// type system won't let us.
    fn repair_vtable(p: *mut [Self::Item]) -> *mut Self;
}

/// Create a memory layout that matches what the [`FlexibleArrayMember`] trait
/// expects, aka a `[u32; 2]` header followed by a trailing array of items.
/// This will be used by `Box` so the correct thing happens on `Drop`.
fn flexible_layout<D>(capacity: u32) -> Result<Layout, Error>
where
    D: FlexibleArrayMember + ?Sized,
{
    let array = Layout::array::<D::Item>(capacity as usize)
        .map_err(|_| Error::LayoutOverflow)?;
    if array.size() > MAX_FLEXIBLE_BYTES {
        return Err(Error::TooLarge { requested: array.size() });
    }

    // The header in the trait contract
    // error (u32)
    // count (u32)
    let (layout, _) = Layout::new::<[u32; 2]>()
        .extend(array)
        .map_err(|_| Error::LayoutOverflow)?;

    Ok(layout.pad_to_align())
}

pub(crate) fn alloc_flexible_struct<D>(capacity: u32) -> Result<Box<D>, Error>
where
    D: FlexibleArrayMember + ?Sized,
{
    let layout = flexible_layout::<D>(capacity)?;

    // SAFETY: layout.size() >= 8 (error and count headers always present).
    let raw = unsafe { alloc_zeroed(layout) };
    if raw.is_null() {
        handle_alloc_error(layout);
    }

    // SAFETY: trait contract puts the u32 count at offset 4.
    unsafe {
        (raw as *mut u32).add(1).write(capacity);
    }

    // This line should bring the most concern to future readers so let me
    // explain what is going on. As of stable rust 1.97.1 there is no way to set
    // the length of a fat pointer, so we are casting from one fat pointer to
    // another which rust happily lets us do even though the data ptr points
    // at different things between our types. So we create the slice of
    // `*mut [D::Item]` and abuse it by then casting it back to `*mut Self`.
    // One can use `std::mem::size_of_val_raw` with nightly rust to confirm the
    // right thing happens.
    let dst_ptr = D::repair_vtable(std::ptr::slice_from_raw_parts_mut(
        raw as *mut D::Item,
        capacity as usize,
    ));

    // SAFETY: dst_ptr matches the layout Box::drop will compute from
    // the fat pointer's metadata.
    Ok(unsafe { Box::from_raw(dst_ptr) })
}

/// Implements [`FlexibleArrayMember`] for a given `#[repr(C)]` struct.
///
/// Naming the header and tail fields lets us confirm the trait's safety
/// contract at compile time. Two parts of the contract can't be checked
/// here: `#[repr(C)]`, and the tail's offset.
macro_rules! impl_flex {
    ($struct:ty, $item:ty, $error:ident, $count:ident, $tail:ident) => {
        const _: () = {
            use ::core::mem::offset_of;

            assert!(
                offset_of!($struct, $error) == 0,
                concat!(
                    stringify!($error),
                    " must be at the start of ",
                    stringify!($struct)
                )
            );
            assert!(
                offset_of!($struct, $count) == 4,
                concat!(
                    stringify!($count),
                    " must come after the error field of ",
                    stringify!($struct)
                )
            );
        };

        // Another safety check that ensures our fields are of the right type
        // when calling the macro.
        const _: fn(&$struct) -> (&u32, &u32, &[$item]) =
            |s| (&s.$error.0, &s.$count, &s.$tail);

        unsafe impl FlexibleArrayMember for $struct {
            type Item = $item;

            fn repair_vtable(p: *mut [Self::Item]) -> *mut Self {
                p as *mut Self
            }
        }
    };
}

// This is the preferred way implementations should be defined in this crate.
impl_flex!(OsRotCerts, u8, error, chain_size, chain);

#[cfg(test)]
mod tests {
    use crate::ffi::RawOsRotError;

    use super::*;

    // It's unfortunate that there's no easy way to test this macro rejects the
    // wrong things since the macro provides compile time checks.
    #[test]
    fn impl_flex_works() {
        #[repr(C)]
        pub struct Flex {
            pub error: RawOsRotError,
            pub chain_size: u32,
            pub chain: [u8],
        }

        impl_flex!(Flex, u8, error, chain_size, chain);
    }

    #[test]
    fn zero_capacity_is_valid() {
        let certs: Box<OsRotCerts> = alloc_flexible_struct(0).unwrap();
        assert_eq!(certs.chain_size, 0);
        assert_eq!(certs.chain.len(), 0);
    }

    #[test]
    fn count_field_set_to_capacity() {
        let certs: Box<OsRotCerts> = alloc_flexible_struct(42).unwrap();
        assert_eq!(certs.chain_size, 42);
        assert_eq!(certs.chain.len(), 42);
    }

    #[test]
    fn error_field_is_zeroed() {
        let certs: Box<OsRotCerts> = alloc_flexible_struct(8).unwrap();
        assert_eq!(certs.error.0, 0);
    }

    #[test]
    fn tail_is_zeroed_and_writable() {
        let mut certs: Box<OsRotCerts> = alloc_flexible_struct(3).unwrap();
        assert_eq!(certs.chain, [0u8; 3]);
        certs.chain[1] = 0xAB;
        assert_eq!(certs.chain[1], 0xAB);
    }

    fn mock_kernel_fill(certs: &mut OsRotCerts, reported_size: u32) {
        let cap = certs.chain.len();
        certs.chain_size = reported_size;
        let to_write = (reported_size as usize).min(cap);
        for i in 0..to_write {
            certs.chain[i] = (i as u8).wrapping_add(1);
        }
    }

    #[test]
    fn kernel_fill_within_capacity_is_sound() {
        let mut certs: Box<OsRotCerts> = alloc_flexible_struct(4).unwrap();
        mock_kernel_fill(&mut certs, 4);

        for (i, b) in certs.chain.iter().enumerate() {
            assert_eq!(*b, (i as u8).wrapping_add(1));
        }
    }

    #[test]
    fn layout_matches_c_struct() {
        for items in [0u32, 1, 4, 5, 8] {
            let certs: Box<OsRotCerts> = alloc_flexible_struct(items).unwrap();
            let allocated = flexible_layout::<OsRotCerts>(items).unwrap();
            assert_eq!(std::mem::size_of_val(&*certs), allocated.size());
            assert_eq!(std::mem::align_of_val(&*certs), allocated.align());

            // The error and count u32s must be at offsets 0 and 4, and the
            // tail must start right after them.
            let base = &*certs as *const OsRotCerts as *const u8;
            let error = &certs.error as *const _ as *const u8;
            let count = &certs.chain_size as *const u32 as *const u8;
            assert_eq!(unsafe { error.offset_from(base) }, 0);
            assert_eq!(unsafe { count.offset_from(base) }, 4);
            assert_eq!(unsafe { certs.chain.as_ptr().offset_from(base) }, 8);
        }
    }
}
