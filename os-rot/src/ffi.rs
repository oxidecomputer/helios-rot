// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::mem::offset_of;

use rustix::ioctl::Opcode;

/// The set of errors returned to os_rot ioctl consumers (os_rot_error_t).
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawOsRotError(pub u32);

/// `os_rot_error_t` discriminants.
pub const OS_ROT_E_OK: u32 = 0;
pub const OS_ROT_E_SIZE: u32 = 1;
pub const OS_ROT_E_DPE: u32 = 2;
pub const OS_ROT_E_NO_PROVIDER: u32 = 3;

/// The path to the os_rot device to issue ioctls.
pub const OS_ROT_DEV: &str = "/dev/os_rot";

/// Measurements are assumed to be SHA2-384 digests.
pub const OS_ROT_HASH_SIZE: usize = 48;

/// Attestations are assumed to be 384-bit ECDSA signatures.
pub const OS_ROT_SIG_SIZE: usize = 96;

/// os_rot IOCTLs.
const OS_ROT_IOC: Opcode = ((b'R' as Opcode) << 24)
    | ((b'O' as Opcode) << 16)
    | ((b'T' as Opcode) << 8);

/// Retrieve the certificate chain that links our attestation signing keys to
/// a trusted PKI root (os_rot_certs_t).
pub const OS_ROT_IOC_GET_CERTS: Opcode = OS_ROT_IOC | 0x01;

/// When `chain_size` is 0 on input, the driver returns the required size.
/// Otherwise it fills `chain` with the certificate chain data.
#[repr(C)]
#[derive(Debug)]
pub struct OsRotCerts {
    pub error: RawOsRotError,
    pub chain_size: u32,
    pub chain: [u8],
}

/// Provides an attestation over the current set of measurements with a given
/// nonce for freshness and returns the resulting signature (os_rot_attest_t).
///
/// The attestation is a signature over the SHA2-384 digest of the
/// caller-provided nonce (which should be random).
pub const OS_ROT_IOC_ATTEST: Opcode = OS_ROT_IOC | 0x02;

/// The caller provides `nonce` which the driver uses to provide an attestation
/// signature.
#[repr(C)]
#[derive(Debug)]
pub struct OsRotAttest {
    pub error: RawOsRotError,
    pub nonce: [u8; OS_ROT_HASH_SIZE],
    pub sig: [u8; OS_ROT_SIG_SIZE],
}

// Test the kernel ABI at compile time.
const _: () = {
    assert!(size_of::<RawOsRotError>() == 4);
    assert!(align_of::<RawOsRotError>() == 4);

    assert!(
        size_of::<OsRotAttest>()
            == size_of::<u32>() + OS_ROT_HASH_SIZE + OS_ROT_SIG_SIZE
    );
    assert!(offset_of!(OsRotAttest, error) == 0);
    assert!(offset_of!(OsRotAttest, nonce) == 4);
    assert!(
        offset_of!(OsRotAttest, sig) == size_of::<u32>() + OS_ROT_HASH_SIZE
    );

    // alloc_flexible_struct zeroes the error at offset 0 and writes the count
    // at offset 4 of each DST.
    assert!(offset_of!(OsRotCerts, error) == 0);
    assert!(offset_of!(OsRotCerts, chain_size) == 4);
};
