// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use sled_agent_client::Client as SledAgentClient;
use sled_agent_types_versions::latest::rot as SledAgentTypes;
use std::net::SocketAddrV6;
use x509_cert::{Certificate, PkiPath, der::DecodePem};

use crate::{Attestation, HeliosRot, QualifyingData};

pub struct HeliosRotSledAgent {
    client: SledAgentClient,
}

impl HeliosRotSledAgent {
    pub fn new(addr: SocketAddrV6, log: &slog::Logger) -> Self {
        let client = SledAgentClient::new(
            &format!("http://{addr}"),
            log.new(slog::o!("SledAgentClient" => addr.to_string())),
        );

        Self { client }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HeliosRotSledAgentError {
    #[error(transparent)]
    Certificate(#[from] der::Error),

    #[error(transparent)]
    SledAgent(
        #[from] sled_agent_client::Error<sled_agent_client::types::Error>,
    ),

    #[error(
        "SledAgent returned an unsupported signature type, this \
        shouldn't happen"
    )]
    Unsupported,
}

#[async_trait::async_trait]
impl HeliosRot for HeliosRotSledAgent {
    type Error = HeliosRotSledAgentError;

    async fn get_certificates(&self) -> Result<PkiPath, Self::Error> {
        let certs = self
            .client
            .rot_certificate_chain(&SledAgentTypes::Rot::Helios)
            .await?
            .into_inner();

        Ok(certs
            .0
            .into_iter()
            .map(Certificate::from_pem)
            .collect::<Result<Vec<_>, _>>()?)
    }

    async fn attest(&self, qdata: &QualifyingData) -> Result<Attestation, Self::Error> {
        let &QualifyingData::Q48(qdata) = qdata;
        let attestation = self
            .client
            .rot_attest(
                &SledAgentTypes::Rot::Helios,
                &SledAgentTypes::QualifyingData::Q48(qdata.0),
            )
            .await?
            .into_inner();

        match attestation {
            SledAgentTypes::Attestation::Ed25519(_) => {
                Err(Self::Error::Unsupported)
            }
            SledAgentTypes::Attestation::P384(s) => {
                Ok(Attestation::P384(s.0.into()))
            }
        }
    }
}
