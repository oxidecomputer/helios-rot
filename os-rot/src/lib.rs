// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Communication with the helios AMD RoT (PSP).
//!
//! The OS driver makes use of the DICE Protection Environment (DPE) present on
//! the AMD CPU to measure and attest to the phase 1 and 2 images. In the future
//! we may extend that to include zones, processes, VMs, services, etc.

use std::os::fd::OwnedFd;

use rustix::ioctl::ioctl;

use crate::{
    ffi::{
        OS_ROT_HASH_SIZE, OS_ROT_SIG_SIZE, OsRotAttest, OsRotCerts,
        RawOsRotError,
    },
    flexible::alloc_flexible_struct,
    ioctls::{Attest, GetCerts},
};

mod ffi;
mod flexible;
mod ioctls;

/// An error talking to the os_rot driver.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("failed to open os_rot device `{}`", ffi::OS_ROT_DEV)]
    DevicePath(#[source] std::io::Error),

    #[error("OS_ROT_IOC_GET_CERTS ioctl call failed: {errno}")]
    GetCertsIoctl { errno: rustix::io::Errno },

    #[error("cert chain size changed, retry request")]
    CertChainSize,

    #[error("OS_ROT_IOC_ATTEST ioctl call failed: {errno}")]
    AttestIoctl { errno: rustix::io::Errno },

    #[error("flexible array layout overflowed")]
    LayoutOverflow,

    #[error(
        "kernel reported an implausibly large size: {requested} bytes \
         (limit {} bytes)",
        crate::flexible::MAX_FLEXIBLE_BYTES
    )]
    TooLarge { requested: usize },

    #[error(transparent)]
    RotError(#[from] OsRotErrorCode),
}

/// An `os_rot_error_t` value reported by the driver in the error field of an
/// ioctl struct.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OsRotErrorCode {
    /// Not enough space to write result, the necessary size is returned
    /// (e.g., as `osrc_chain_size` in `os_rot_certs_t`).
    #[error("bad buffer size")]
    Size,

    /// Encountered an unexpected DPE error.
    #[error("DPE operation failed")]
    Dpe,

    /// No DPE provider backing the driver is available (yet).  The DPE
    /// provider driver attaches asynchronously relative to os_rot; the
    /// caller may retry later.
    #[error("no DPE provider is available (yet)")]
    NoProvider,

    /// Unknown error from the driver, note that the driver is free to add new
    /// enum members in the future to `os_rot_error_t`.
    #[error("unknown os_rot error: {0}")]
    Unknown(u32),
}

impl RawOsRotError {
    fn check_err(&self) -> Result<(), OsRotErrorCode> {
        match self.0 {
            ffi::OS_ROT_E_OK => Ok(()),
            ffi::OS_ROT_E_SIZE => Err(OsRotErrorCode::Size),
            ffi::OS_ROT_E_DPE => Err(OsRotErrorCode::Dpe),
            ffi::OS_ROT_E_NO_PROVIDER => Err(OsRotErrorCode::NoProvider),
            _ => Err(OsRotErrorCode::Unknown(self.0)),
        }
    }
}

#[derive(Debug)]
pub struct OsRotHandle {
    fd: OwnedFd,
}

impl OsRotHandle {
    pub fn new() -> Result<Self, Error> {
        let dev =
            std::fs::File::open(ffi::OS_ROT_DEV).map_err(Error::DevicePath)?;

        Ok(Self { fd: dev.into() })
    }

    /// Retrieve the certificate chain that links the RoT's attestation signing
    /// keys to a trusted PKI root.
    ///
    /// The driver is first queried with a zero-length buffer to learn the
    /// required chain size, then queried again with a buffer of that size to
    /// receive the chain data.
    pub fn get_certs(&self) -> Result<Vec<u8>, Error> {
        let mut probe: Box<OsRotCerts> = alloc_flexible_struct(0)?;

        unsafe {
            ioctl(&self.fd, GetCerts(&mut probe))
                .map_err(|e| Error::GetCertsIoctl { errno: e })?;
        }

        probe.error.check_err()?;

        // Kernel-reported certificate chain size, in bytes.
        let probe_chain_size = probe.chain_size;
        let mut certs: Box<OsRotCerts> =
            alloc_flexible_struct(probe_chain_size)?;

        match unsafe { ioctl(&self.fd, GetCerts(&mut certs)) } {
            Ok(_) => match certs.chain_bytes() {
                Err(Error::RotError(OsRotErrorCode::Size)) => {
                    Err(Error::CertChainSize)
                }
                res => res,
            },
            Err(e) => Err(Error::GetCertsIoctl { errno: e }),
        }
    }

    /// Attest over the current set of measurements, using `nonce` for
    /// freshness, and return the resulting signature.
    ///
    /// The driver signs the SHA2-384 digest of `nonce`, which should be
    /// random.
    pub fn attest(
        &self,
        nonce: &[u8; OS_ROT_HASH_SIZE],
    ) -> Result<Vec<u8>, Error> {
        let mut attest = OsRotAttest {
            error: RawOsRotError(0),
            nonce: *nonce,
            sig: [0u8; OS_ROT_SIG_SIZE],
        };

        match unsafe { ioctl(&self.fd, Attest(&mut attest)) } {
            Ok(_) => {
                attest.error.check_err()?;
                Ok(attest.sig.to_vec())
            }
            Err(e) => Err(Error::AttestIoctl { errno: e }),
        }
    }
}

impl OsRotCerts {
    /// Copy out the certificate chain bytes the driver wrote into this buffer.
    fn chain_bytes(&self) -> Result<Vec<u8>, Error> {
        self.error.check_err()?;
        let capacity = self.chain.len();
        let num_items = usize::try_from(self.chain_size)
            .expect("usize is at least 32 bits wide");
        assert!(
            num_items <= capacity,
            "driver reported {num_items} chain bytes in a {capacity} byte \
             buffer"
        );

        Ok(self.chain[..num_items].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::OsRotCerts;

    #[test]
    fn chain_bytes_returns_reported_prefix() {
        let mut certs: Box<OsRotCerts> = alloc_flexible_struct(8).unwrap();
        certs.chain_size = 3;
        certs.chain[..3].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(certs.chain_bytes().unwrap(), vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn chain_bytes_empty_chain() {
        let certs: Box<OsRotCerts> = alloc_flexible_struct(0).unwrap();
        assert!(certs.chain_bytes().unwrap().is_empty());
    }

    // The driver reports failures in the error field rather than through errno.
    #[test]
    fn chain_bytes_surfaces_driver_error() {
        let mut certs: Box<OsRotCerts> = alloc_flexible_struct(8).unwrap();
        certs.error = RawOsRotError(3);
        certs.chain_size = 3;

        assert!(matches!(
            certs.chain_bytes(),
            Err(Error::RotError(OsRotErrorCode::NoProvider))
        ));
    }

    #[test]
    #[should_panic]
    fn chain_bytes_over_report_aborts() {
        let mut certs: Box<OsRotCerts> = alloc_flexible_struct(2).unwrap();
        // Simulate the kernel filling in 2 slots but saying there are 3
        // available.
        certs.chain_size = 3;
        let _ = certs.chain_bytes();
    }
}
