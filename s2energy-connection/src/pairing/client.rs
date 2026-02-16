use std::sync::Arc;

use reqwest::{StatusCode, Url};
use rustls::pki_types::CertificateDer;

use crate::common::wire::{AccessToken, Deployment, PairingVersion, S2NodeId, S2Role, WirePairingVersion};
use crate::pairing::transport::{HashProvider, hash_providing_https_client};
use crate::pairing::{Pairing, PairingRole, SUPPORTED_PAIRING_VERSIONS};

use super::EndpointConfig;
use super::wire::*;
use super::{Error, Network, PairingResult};

/// Remote endpoint to pair with
pub struct PairingRemote {
    /// URL at which the remote endpoint can be reached
    pub url: String,
    /// S2 node id of the remote endpoint.
    pub id: S2NodeId,
}

/// Configuration for pairing clients.
pub struct ClientConfig {
    /// Additional roots of trust for TLS connections. Useful when testing during the development of WAN endpoints.
    ///
    /// When the remote is on the LAN, this is not used.
    pub additional_certificates: Vec<CertificateDer<'static>>,
    /// Where the pairing is deployed.
    pub pairing_deployment: Deployment,
}

/// Client for S2 pairing transactions.
///
/// Used as the client end of a pairing interaction.
pub struct Client {
    config: Arc<EndpointConfig>,
    additional_certificates: Vec<CertificateDer<'static>>,
    pairing_deployment: Deployment,
}

impl Client {
    /// Create a new client for pairing on an endpoint with the given configuration.
    pub fn new(config: Arc<EndpointConfig>, client_config: ClientConfig) -> PairingResult<Self> {
        Ok(Self {
            config,
            additional_certificates: client_config.additional_certificates,
            pairing_deployment: client_config.pairing_deployment,
        })
    }

    /// Pair with a given remote S2 node, using the provided token.
    pub async fn pair(&self, remote: PairingRemote, pairing_token: &[u8]) -> PairingResult<Pairing> {
        let url = Url::try_from(remote.url.as_str()).map_err(|_| Error::InvalidUrl)?;

        let (client, certhash) = if url.domain().map(|v| v.ends_with(".local")).unwrap_or_default() {
            let (client, certhash) = hash_providing_https_client()?;
            (client, Some(certhash))
        } else {
            (
                reqwest::Client::builder()
                    .tls_certs_merge(
                        self.additional_certificates
                            .iter()
                            .filter_map(|v| reqwest::Certificate::from_der(v).ok()),
                    )
                    .build()
                    .map_err(|_| Error::TransportFailed)?,
                None,
            )
        };
        let pairing_version = negotiate_version(&client, url.clone()).await?;

        match pairing_version {
            PairingVersion::V1 => {
                V1Session::new(client, url, &self.config)
                    .pair(certhash, self.pairing_deployment, remote.id, pairing_token)
                    .await
            }
        }
    }
}

async fn negotiate_version(client: &reqwest::Client, url: Url) -> Result<PairingVersion, Error> {
    let response = client.get(url).send().await.map_err(|_| Error::TransportFailed)?;
    let status = response.status();
    if status != StatusCode::OK {
        return Err(Error::ProtocolError);
    }

    let supported_versions = response.json::<Vec<WirePairingVersion>>().await.map_err(|_| Error::ProtocolError)?;

    for version in supported_versions.into_iter().filter_map(|v| v.try_into().ok()) {
        if SUPPORTED_PAIRING_VERSIONS.contains(&version) {
            return Ok(version);
        }
    }

    Err(Error::NoSupportedVersion)
}

struct V1Session<'a> {
    client: reqwest::Client,
    base_url: Url,
    config: &'a EndpointConfig,
}

impl<'a> V1Session<'a> {
    fn new(client: reqwest::Client, url: Url, config: &'a EndpointConfig) -> Self {
        V1Session {
            client,
            base_url: url.join("v1/").unwrap(),
            config,
        }
    }

    async fn pair(
        self,
        certhash: Option<HashProvider>,
        local_deployment: Deployment,
        id: S2NodeId,
        pairing_token: &[u8],
    ) -> PairingResult<Pairing> {
        let our_deployment = self.config.endpoint_description.deployment.unwrap_or(local_deployment);
        let our_role = self.config.node_description.role;

        let network = if self.base_url.domain().map(|v| v.ends_with(".local")).unwrap_or_default() {
            if let Some(hash) = certhash.as_ref().and_then(HashProvider::hash) {
                Network::Lan {
                    fingerprint: hash.try_into().unwrap(),
                }
            } else {
                return Err(Error::ProtocolError);
            }
        } else {
            Network::Wan
        };

        let client_hmac_challenge = HmacChallenge::new(&mut rand::rng());

        let request_pairing_response = self.request_pairing(id, &client_hmac_challenge).await?;
        let attempt_id = request_pairing_response.pairing_attempt_id;
        let remote_deployment = request_pairing_response
            .server_s2_endpoint_description
            .deployment
            .unwrap_or_else(|| network.as_deployment());
        let remote_role = request_pairing_response.server_s2_node_description.role;

        match request_pairing_response.selected_hmac_hashing_algorithm {
            HmacHashingAlgorithm::Sha256 => {
                let expected = client_hmac_challenge.sha256(&network, pairing_token);

                if expected != request_pairing_response.client_hmac_challenge_response {
                    let _ = self.finalize(&attempt_id, false).await;
                    return Err(Error::InvalidToken);
                }
            }
        }

        let server_hmac_challenge_response = match request_pairing_response.selected_hmac_hashing_algorithm {
            HmacHashingAlgorithm::Sha256 => request_pairing_response.server_hmac_challenge.sha256(&network, pairing_token),
        };

        enum CommunicationRole {
            CommunicationServer { initiate_connection_url: String },
            CommunicationClient,
        }

        let role = match (our_deployment, our_role, remote_deployment, remote_role) {
            (_, S2Role::Rm, _, S2Role::Rm) | (_, S2Role::Cem, _, S2Role::Cem) => {
                let _ = self.finalize(&attempt_id, false).await;
                return Err(Error::RemoteOfSameType);
            }
            (Deployment::Lan, _, Deployment::Wan, _) => CommunicationRole::CommunicationClient,
            // unwrap is okay here, as Deployment::Wan or S2Role::Cem locally means we will ALWAYS have a connection initiate url.
            (Deployment::Wan, _, Deployment::Lan, _) | (_, S2Role::Cem, _, S2Role::Rm) => CommunicationRole::CommunicationServer {
                initiate_connection_url: self.config.connection_initiate_url.as_ref().unwrap().into(),
            },
            (_, S2Role::Rm, _, S2Role::Cem) => CommunicationRole::CommunicationClient,
        };

        let pairing = match role {
            CommunicationRole::CommunicationServer { initiate_connection_url } => {
                let access_token = AccessToken::new(&mut rand::rng());
                if let Err(e) = self
                    .post_connection_details(
                        &attempt_id,
                        server_hmac_challenge_response,
                        initiate_connection_url.clone(),
                        access_token.clone(),
                    )
                    .await
                {
                    let _ = self.finalize(&attempt_id, false).await;
                    return Err(e);
                }
                Pairing {
                    remote_endpoint_description: request_pairing_response.server_s2_endpoint_description,
                    remote_node_description: request_pairing_response.server_s2_node_description,
                    token: access_token,
                    role: PairingRole::CommunicationServer,
                }
            }
            CommunicationRole::CommunicationClient => {
                let connection_details = match self.get_connection_details(&attempt_id, server_hmac_challenge_response).await {
                    Ok(connection_details) => connection_details,
                    Err(e) => {
                        let _ = self.finalize(&attempt_id, false).await;
                        return Err(e);
                    }
                };
                Pairing {
                    remote_endpoint_description: request_pairing_response.server_s2_endpoint_description,
                    remote_node_description: request_pairing_response.server_s2_node_description,
                    token: connection_details.access_token,
                    role: PairingRole::CommunicationClient {
                        initiate_url: connection_details.initiate_connection_url,
                    },
                }
            }
        };

        self.finalize(&attempt_id, true).await?;

        Ok(pairing)
    }

    async fn get_connection_details(
        &self,
        attempt_id: &PairingAttemptId,
        server_hmac_challenge_response: HmacChallengeResponse,
    ) -> PairingResult<ConnectionDetails> {
        let request = RequestConnectionDetailsRequest {
            server_hmac_challenge_response,
        };
        let response = self
            .client
            .post(self.base_url.join("requestConnectionDetails").unwrap())
            .header(PairingAttemptId::HEADER_NAME, attempt_id.header_value())
            .json(&request)
            .send()
            .await
            .map_err(|_| Error::TransportFailed)?;
        if response.status() != StatusCode::OK {
            return Err(Error::ProtocolError);
        }
        let connection_details = response.json::<ConnectionDetails>().await.map_err(|_| Error::ProtocolError)?;
        Ok(connection_details)
    }

    async fn post_connection_details(
        &self,
        attempt_id: &PairingAttemptId,
        server_hmac_challenge_response: HmacChallengeResponse,
        initiate_connection_url: String,
        access_token: AccessToken,
    ) -> PairingResult<()> {
        let request = PostConnectionDetailsRequest {
            server_hmac_challenge_response,
            connection_details: ConnectionDetails {
                initiate_connection_url,
                access_token,
            },
        };
        let response = self
            .client
            .post(self.base_url.join("postConnectionDetails").unwrap())
            .header(PairingAttemptId::HEADER_NAME, attempt_id.header_value())
            .json(&request)
            .send()
            .await
            .map_err(|_| Error::TransportFailed)?;
        if response.status() != StatusCode::NO_CONTENT {
            return Err(Error::ProtocolError);
        }

        Ok(())
    }

    async fn request_pairing(&self, id: S2NodeId, client_hmac_challenge: &HmacChallenge) -> PairingResult<RequestPairingResponse> {
        let request = RequestPairing {
            node_description: self.config.node_description.clone(),
            endpoint_description: self.config.endpoint_description.clone(),
            id,
            supported_protocols: self.config.supported_communication_protocols.clone(),
            supported_versions: self.config.supported_message_versions.clone(),
            supported_hashing_algorithms: vec![HmacHashingAlgorithm::Sha256],
            client_hmac_challenge: client_hmac_challenge.clone(),
            force_pairing: false,
        };
        let response = self
            .client
            .post(self.base_url.join("requestPairing").unwrap())
            .json(&request)
            .send()
            .await
            .map_err(|_| Error::TransportFailed)?;
        if response.status() != StatusCode::OK {
            return Err(Error::ProtocolError);
        }
        let request_pairing_response = response.json::<RequestPairingResponse>().await.map_err(|_| Error::ProtocolError)?;
        Ok(request_pairing_response)
    }

    async fn finalize(self, attempt_id: &PairingAttemptId, success: bool) -> PairingResult<()> {
        let response = self
            .client
            .post(self.base_url.join("finalizePairing").unwrap())
            .header(PairingAttemptId::HEADER_NAME, attempt_id.header_value())
            .json(&success)
            .send()
            .await
            .map_err(|_| Error::TransportFailed)?;
        if response.status() != StatusCode::NO_CONTENT {
            return Err(Error::ProtocolError);
        }

        Ok(())
    }
}
