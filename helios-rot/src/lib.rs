// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use os_rot::OsRotHandle;
use p384::{
    ecdsa::{
        self, Signature, SigningKey,
        signature::{SignatureEncoding, Signer},
    },
    pkcs8::{self, DecodePrivateKey},
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;
use x509_cert::{
    Certificate, PkiPath,
    der::{self, Reader},
};

const SIGNATURE_SIZE: usize =
    core::mem::size_of::<<Signature as SignatureEncoding>::Repr>();

#[derive(Debug, Error)]
pub enum ArrayError {
    #[error("slice is {actual} bytes, expected {expected}")]
    TryFromSliceError { expected: usize, actual: usize },
}

#[serde_as]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Array<const N: usize>(#[serde_as(as = "[_; N]")] pub [u8; N]);

impl<const N: usize> Array<N> {
    pub const LENGTH: usize = N;
}

impl<const N: usize> AsRef<[u8]> for Array<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl<const N: usize> TryFrom<&[u8]> for Array<N> {
    type Error = ArrayError;

    /// Attempt to create an `Array<N>` from the slice provided.
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        let item: [u8; N] = item.try_into().map_err(|_| {
            Self::Error::TryFromSliceError { expected: N, actual: item.len() }
        })?;
        Ok(Array::<N>(item))
    }
}

pub type P384Signature = Array<SIGNATURE_SIZE>;

/// An attestation from the Helios Rot
pub enum Attestation {
    P384(P384Signature),
}

#[derive(Debug, Error)]
pub enum NonceError {
    #[error("Only 48 byte Nonces are supported")]
    UnsupportedLength,
    #[error("Failed to pull 48 bytes from getrandom")]
    Rng(#[from] getrandom::Error),
}

pub type Nonce48 = Array<48>;

#[derive(
    Copy,
    Clone,
    Debug,
    Deserialize,
    PartialEq,
    // The current RoT Attest API takes the nonce bytes directly (i.e. a
    // `Nonce48`/`Array<48>`) rather than this more generic `Nonce` type.
    // To prevent accidentally accepting this type where it currently shouldn't
    // be accepted, we omit these for now until hubris#2375 is fixed.
    // Serialize, SerializedSize,
)]
pub enum Nonce {
    /// A 48-byte Nonce value.
    N48(Nonce48),
}

impl Nonce {
    pub fn from_platform_rng(len: usize) -> Result<Self, NonceError> {
        // We currently only support 32-byte Nonce's
        if len != Nonce48::LENGTH {
            return Err(NonceError::UnsupportedLength);
        }
        let mut nonce = Array([0u8; Nonce48::LENGTH]);
        getrandom::fill(nonce.0.as_mut_slice()).map_err(NonceError::Rng)?;
        Ok(Nonce::N48(nonce))
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        match self {
            Nonce::N48(n) => n.as_ref(),
        }
    }
}

/// The `HeliosRot` trait is the interface to the roT in the Helios kernel.
#[async_trait::async_trait]
pub trait HeliosRot {
    type Error: std::error::Error + Send + Sync;

    async fn get_certificates(&self) -> Result<PkiPath, Self::Error>;
    async fn attest(&self, nonce: &Nonce) -> Result<Attestation, Self::Error>;
}

#[derive(Debug, Error)]
pub enum HeliosOsRotError {
    #[error("OS RoT error")]
    OsRotError(#[from] os_rot::Error),

    #[error("Failed to decode DER certificate chain from OS RoT")]
    DerError(#[from] der::Error),

    #[error("Invalid attestation signature from OS RoT")]
    SignatureSize(#[from] ArrayError),
}

#[derive(Debug)]
pub struct HeliosOsRot {
    handle: Arc<OsRotHandle>,
}

impl HeliosOsRot {
    /// Creates a new `HeliosOsRot` instance, opening the os_rot device.
    pub fn new() -> Result<Self, HeliosOsRotError> {
        Ok(Self { handle: Arc::new(OsRotHandle::new()?) })
    }

    async fn do_rot_request<T, F>(&self, request: F) -> Result<T, os_rot::Error>
    where
        T: Send + 'static,
        F: FnOnce(&OsRotHandle) -> Result<T, os_rot::Error> + Send + 'static,
    {
        // We use `spawn_blocking` here because each request to the underlying
        // OS RoT is preformed via an IOCTL.
        let handle = Arc::clone(&self.handle);
        let req = tokio::task::spawn_blocking(move || request(&handle));
        req.await.expect("handle is not aborted, and we propagate panics")
    }
}

/// Parse the certificate chain returned by the os_rot driver, which is a
/// concatenation of DER-encoded certificates.
fn load_der_chain(raw: &[u8]) -> Result<PkiPath, der::Error> {
    let mut reader = der::SliceReader::new(raw)?;
    let mut certs = PkiPath::new();
    while !reader.is_finished() {
        certs.push(reader.decode()?);
    }
    Ok(certs)
}

#[async_trait::async_trait]
impl HeliosRot for HeliosOsRot {
    type Error = HeliosOsRotError;

    async fn get_certificates(&self) -> Result<PkiPath, Self::Error> {
        let raw = self.do_rot_request(|handle| handle.get_certs()).await?;
        Ok(load_der_chain(&raw)?)
    }

    async fn attest(&self, nonce: &Nonce) -> Result<Attestation, Self::Error> {
        let Nonce::N48(nonce) = *nonce;
        let raw =
            self.do_rot_request(move |handle| handle.attest(&nonce.0)).await?;
        let sig = P384Signature::from(raw.as_slice().try_into()?);
        Ok(Attestation::P384(sig))
    }
}

#[derive(Debug, Error)]
pub enum HeliosRotMockError {
    #[error("Failed to decode PEM certificate chain")]
    DerError(#[from] der::Error),
    #[error("Failed to read {}", path.display())]
    FileRead {
        path: PathBuf,
        #[source]
        error: io::Error,
    },
    #[error("Failed to load p384 signing key from {}", path.display())]
    SigningKeyDecode {
        path: PathBuf,
        #[source]
        error: pkcs8::Error,
    },
    #[error("Invalid attestation signature")]
    SignatureSize(#[from] ArrayError),
    #[error("Failed to sign nonce")]
    SigningError(#[from] ecdsa::Error),
}

#[derive(Debug)]
pub struct HeliosRotMock {
    certs: PkiPath,
    alias_key: SigningKey,
}

impl HeliosRotMock {
    pub fn load<P: AsRef<Path>, A: AsRef<Path>>(
        certs: P,
        alias: A,
    ) -> Result<Self, HeliosRotMockError> {
        let certs = fs::read_to_string(&certs).map_err(|error| {
            HeliosRotMockError::FileRead {
                path: certs.as_ref().to_path_buf(),
                error,
            }
        })?;
        let certs = Certificate::load_pem_chain(certs.as_bytes())?;

        let alias_key = fs::read_to_string(&alias).map_err(|error| {
            HeliosRotMockError::FileRead {
                path: alias.as_ref().to_path_buf(),
                error,
            }
        })?;

        let alias_key =
            SigningKey::from_pkcs8_pem(&alias_key).map_err(|error| {
                HeliosRotMockError::SigningKeyDecode {
                    path: alias.as_ref().to_path_buf(),
                    error,
                }
            })?;

        Ok(Self { certs, alias_key })
    }
}

#[async_trait::async_trait]
impl HeliosRot for HeliosRotMock {
    type Error = HeliosRotMockError;

    async fn get_certificates(&self) -> Result<PkiPath, Self::Error> {
        Ok(self.certs.clone())
    }

    async fn attest(&self, nonce: &Nonce) -> Result<Attestation, Self::Error> {
        let sig: Signature = self.alias_key.try_sign(nonce.as_ref())?;
        let sig = P384Signature::from(sig.to_bytes().as_slice().try_into()?);
        Ok(Attestation::P384(sig))
    }
}

#[cfg(test)]
mod test {
    use crate::*;
    use std::env;
    use x509_cert::der::Encode;

    const ROOT_CERT_PEM: &str =
        include_str!(concat!(env!("OUT_DIR"), "/root.cert.pem"));

    /// Build a chain of `count` root certs as concatenated DER, the format
    /// returned by the os_rot driver.
    fn der_chain(count: usize) -> (PkiPath, Vec<u8>) {
        let cert = Certificate::load_pem_chain(ROOT_CERT_PEM.as_bytes())
            .expect("load root cert")
            .remove(0);
        let certs = vec![cert; count];
        let mut raw = Vec::new();
        for cert in &certs {
            cert.encode_to_vec(&mut raw).expect("encode cert as DER");
        }
        (certs, raw)
    }

    #[test]
    fn load_der_chain_success() {
        let (certs, raw) = der_chain(2);
        assert_eq!(load_der_chain(&raw).expect("load DER chain"), certs);
    }

    #[test]
    fn load_der_chain_empty() {
        assert!(load_der_chain(&[]).expect("load empty chain").is_empty());
    }

    #[test]
    fn load_der_chain_truncated() {
        let (_, raw) = der_chain(2);
        assert!(load_der_chain(&raw[..raw.len() - 1]).is_err());
    }

    #[test]
    fn bad_path_to_key() {
        let res = HeliosRotMock::load("root.cert.pem", "foo");
        assert!(res.is_err());
    }

    #[test]
    fn bad_path_to_certs() {
        let res = HeliosRotMock::load("foo", "root.key.pem");
        assert!(res.is_err());
    }

    #[test]
    fn load_success() {
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());
        let cert_chain = out.join("root.cert.pem");
        let key = out.join("root.key.pem");

        let res = HeliosRotMock::load(&cert_chain, &key);
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn attest() {
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());
        let signing_key = out.join("root.key.pem");

        let mock = HeliosRotMock::load(out.join("root.cert.pem"), &signing_key)
            .expect("load cert chain & key");

        let nonce = Nonce::from_platform_rng(48).expect("get Nonce from RNG");
        let attestation = mock.attest(&nonce).await.expect("attest to nonce");
        let signing_key = fs::read_to_string(&signing_key)
            .expect("Read signing key from file to string");
        let signing_key = SigningKey::from_pkcs8_pem(&signing_key)
            .expect("signing_key from pkcs8 string");

        use p384::ecdsa::signature::Verifier;
        let verifying_key = p384::ecdsa::VerifyingKey::from(signing_key);
        match attestation {
            Attestation::P384(a) => {
                let sig = Signature::from_slice(a.as_ref())
                    .expect("signature from Attestation::P384 bytes");
                let ret = verifying_key.verify(nonce.as_ref(), &sig);
                assert!(ret.is_ok());
            }
        }
    }
}
