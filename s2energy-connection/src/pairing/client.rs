use std::sync::Arc;

use reqwest::{StatusCode, Url};
use rustls::pki_types::CertificateDer;
use tracing::{debug, trace};

use crate::common::negotiate_version;
use crate::common::wire::{AccessToken, Deployment, PairingVersion, S2Role};
use crate::pairing::transport::{HashProvider, hash_providing_https_client};
use crate::pairing::{Error, Pairing, PairingRole};

use super::NodeConfig;
use super::wire::*;
use super::{ErrorKind, Network, PairingResult};

/// Remote node to pair with.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PairingRemote {
    /// URL at which the remote node can be reached
    pub url: String,
    /// S2 node id of the remote node.
    pub id: PairingS2NodeId,
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
    config: Arc<NodeConfig>,
    additional_certificates: Vec<CertificateDer<'static>>,
    pairing_deployment: Deployment,
}

impl Client {
    /// Create a new client for pairing on an node with the given configuration.
    pub fn new(config: Arc<NodeConfig>, client_config: ClientConfig) -> PairingResult<Self> {
        Ok(Self {
            config,
            additional_certificates: client_config.additional_certificates,
            pairing_deployment: client_config.pairing_deployment,
        })
    }

    /// Pair with a given remote S2 node, using the provided token.
    #[tracing::instrument(skip_all, fields(local = %self.config.node_description.id, remote = ?remote), level = tracing::Level::ERROR)]
    pub async fn pair(&self, remote: PairingRemote, pairing_token: &[u8]) -> PairingResult<Pairing> {
        trace!("Start pairing with new remote.");
        let url = Url::try_from(remote.url.as_str()).map_err(|e| Error::new(ErrorKind::InvalidUrl, e))?;

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
                    .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?,
                None,
            )
        };

        trace!("Prepared reqwest client.");

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

struct V1Session<'a> {
    client: reqwest::Client,
    base_url: Url,
    config: &'a NodeConfig,
}

impl<'a> V1Session<'a> {
    fn new(client: reqwest::Client, url: Url, config: &'a NodeConfig) -> Self {
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
        id: PairingS2NodeId,
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
                return Err(ErrorKind::ProtocolError.into());
            }
        } else {
            Network::Wan
        };

        trace!(?network, "Determined network type of remote.");

        const HMAC_CHALLENGE_BYTES: usize = 32;
        let client_hmac_challenge = HmacChallenge::new(&mut rand::rng(), HMAC_CHALLENGE_BYTES);

        let request_pairing_response = self.request_pairing(id, &client_hmac_challenge).await?;
        let attempt_id = request_pairing_response.pairing_attempt_id;
        let remote_deployment = request_pairing_response
            .server_s2_endpoint_description
            .deployment
            .unwrap_or_else(|| network.as_deployment());
        let remote_role = request_pairing_response.server_s2_node_description.role;

        trace!("Requested pairing from remote.");

        match request_pairing_response.selected_hmac_hashing_algorithm {
            HmacHashingAlgorithm::Sha256 => {
                let expected = client_hmac_challenge.sha256(&network, pairing_token);

                if expected != request_pairing_response.client_hmac_challenge_response {
                    let _ = self.finalize(&attempt_id, false).await;
                    return Err(ErrorKind::InvalidToken.into());
                }
            }
        }

        trace!("Validated remote has same pairing token.");

        debug_assert!(request_pairing_response.server_hmac_challenge.0.len() >= 32);
        let server_hmac_challenge_response = match request_pairing_response.selected_hmac_hashing_algorithm {
            HmacHashingAlgorithm::Sha256 => request_pairing_response.server_hmac_challenge.sha256(&network, pairing_token),
        };

        trace!("Computed pairing token challenge response.");

        enum CommunicationRole {
            CommunicationServer { initiate_connection_url: String },
            CommunicationClient,
        }

        let role = match (our_deployment, our_role, remote_deployment, remote_role) {
            (_, S2Role::Rm, _, S2Role::Rm) | (_, S2Role::Cem, _, S2Role::Cem) => {
                let _ = self.finalize(&attempt_id, false).await;
                return Err(ErrorKind::RemoteOfSameType.into());
            }
            (Deployment::Lan, _, Deployment::Wan, _) => CommunicationRole::CommunicationClient,
            // unwrap is okay here, as Deployment::Wan or S2Role::Cem locally means we will ALWAYS have a connection initiate url.
            (Deployment::Wan, _, Deployment::Lan, _) | (_, S2Role::Cem, _, S2Role::Rm) => CommunicationRole::CommunicationServer {
                initiate_connection_url: self.config.connection_initiate_url.as_ref().unwrap().into(),
            },
            (_, S2Role::Rm, _, S2Role::Cem) => CommunicationRole::CommunicationClient,
        };

        trace!("Determined communication role.");

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

        trace!("Exchanged communication details.");

        self.finalize(&attempt_id, true).await?;

        trace!("Confirmed pairing with remote.");

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
            .bearer_auth(&attempt_id.0)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;
        if response.status() != StatusCode::OK {
            debug!(status = ?response.status(), "Unexpected status code in response to requestConnectionDetails.");
            return Err(ErrorKind::ProtocolError.into());
        }
        let connection_details = response
            .json::<ConnectionDetails>()
            .await
            .map_err(|e| Error::new(ErrorKind::ProtocolError, e))?;
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
            .bearer_auth(&attempt_id.0)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;
        if response.status() != StatusCode::NO_CONTENT {
            debug!(status = ?response.status(), "Unexpected status code in response to postConnectionDetails.");
            return Err(ErrorKind::ProtocolError.into());
        }

        Ok(())
    }

    async fn request_pairing(&self, id: PairingS2NodeId, client_hmac_challenge: &HmacChallenge) -> PairingResult<RequestPairingResponse> {
        let request = RequestPairing {
            node_description: self.config.node_description.clone(),
            endpoint_description: self.config.endpoint_description.clone(),
            id: Some(id),
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
            .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;
        if response.status() == StatusCode::BAD_REQUEST {
            let error_response = response
                .json::<PairingResponseErrorMessage>()
                .await
                .map_err(|e| Error::new(ErrorKind::ProtocolError, e))?;
            match error_response {
                PairingResponseErrorMessage::InvalidCombinationOfRoles => {
                    return Err(Error::new(ErrorKind::RemoteOfSameType, error_response));
                }
                PairingResponseErrorMessage::IncompatibleS2MessageVersions
                | PairingResponseErrorMessage::IncompatibleHMACHashingAlgorithms
                | PairingResponseErrorMessage::IncompatibleCommunicationProtocols => {
                    return Err(Error::new(ErrorKind::NoSupportedVersion, error_response));
                }
                PairingResponseErrorMessage::S2NodeNotFound | PairingResponseErrorMessage::S2NodeNotProvided => {
                    return Err(Error::new(ErrorKind::UnknownNode, error_response));
                }
                PairingResponseErrorMessage::InvalidPairingToken => return Err(Error::new(ErrorKind::InvalidToken, error_response)),
                PairingResponseErrorMessage::ParsingError | PairingResponseErrorMessage::Other => {
                    return Err(Error::new(ErrorKind::ProtocolError, error_response));
                }
            }
        }
        if response.status() != StatusCode::OK {
            debug!(status = ?response.status(), "Unexpected status code in response to requestPairing.");
            return Err(ErrorKind::ProtocolError.into());
        }
        let request_pairing_response = response
            .json::<RequestPairingResponse>()
            .await
            .map_err(|e| Error::new(ErrorKind::ProtocolError, e))?;
        Ok(request_pairing_response)
    }

    async fn finalize(self, attempt_id: &PairingAttemptId, success: bool) -> PairingResult<()> {
        let response = self
            .client
            .post(self.base_url.join("finalizePairing").unwrap())
            .bearer_auth(&attempt_id.0)
            .json(&success)
            .send()
            .await
            .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;
        if response.status() != StatusCode::NO_CONTENT {
            debug!(status = ?response.status(), "Unexpected status code in response to finalize.");
            return Err(ErrorKind::ProtocolError.into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::{Arc, Mutex},
    };

    use crate::{
        Deployment, MessageVersion, S2EndpointDescription, S2Role,
        common::wire::test::{UUID_A, UUID_B, basic_node_description},
        pairing::{
            Client, ClientConfig, ErrorKind, Network, NodeConfig, Pairing, PairingRemote, PairingRole, PairingToken, Server, ServerConfig,
            wire::{
                HmacChallenge, HmacChallengeResponse, PairingAttemptId, PairingResponseErrorMessage, RequestPairing, RequestPairingResponse,
            },
        },
    };

    use axum::{Json, Router, routing::post};
    use axum_server::{Handle, tls_rustls::RustlsConfig};
    use http::StatusCode;
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    use tokio::task::JoinHandle;

    async fn setup_server(config: NodeConfig, overrides: Router<()>) -> (Handle<SocketAddr>, JoinHandle<Pairing>) {
        let server = Server::new(ServerConfig { root_certificate: None });
        let rustls_config = RustlsConfig::from_pem(
            include_bytes!("../../testdata/localhost.chain.pem").into(),
            include_bytes!("../../testdata/localhost.key").into(),
        )
        .await
        .unwrap();
        let app = server.get_router();
        let https_server_handle = Handle::new();
        let https_server_handle_clone = https_server_handle.clone();
        tokio::spawn(async move {
            axum_server::bind_rustls(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0), rustls_config)
                .handle(https_server_handle_clone)
                .serve(overrides.fallback_service(app).into_make_service())
                .await
                .unwrap();
        });
        let server_pair_handle = tokio::spawn(async move {
            server
                .pair_once(Arc::new(config), PairingToken(b"testtoken".as_slice().into()))
                .unwrap()
                .result()
                .await
                .unwrap()
        });

        (https_server_handle, server_pair_handle)
    }

    #[tokio::test]
    async fn pairing_ok_rm_initiates() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, S2Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, S2Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let (server_handle, server_pairing) = setup_server(server_config, Router::new()).await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: UUID_A.into(),
        };

        let client = Client::new(
            Arc::new(client_config),
            ClientConfig {
                additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
                pairing_deployment: Deployment::Wan,
            },
        )
        .unwrap();

        let client_pairing = client.pair(remote, b"testtoken").await.unwrap();
        let server_pairing = server_pairing.await.unwrap();
        assert_eq!(client_pairing.token, server_pairing.token);
        assert_ne!(client_pairing.role, server_pairing.role);
        assert!(matches!(client_pairing.role, PairingRole::CommunicationClient { .. }));

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn pairing_ok_cem_initiates() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, S2Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let (server_handle, server_pairing) = setup_server(server_config, Router::new()).await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: UUID_A.into(),
        };

        let client = Client::new(
            Arc::new(client_config),
            ClientConfig {
                additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
                pairing_deployment: Deployment::Wan,
            },
        )
        .unwrap();

        let client_pairing = client.pair(remote, b"testtoken").await.unwrap();
        let server_pairing = server_pairing.await.unwrap();
        assert_eq!(client_pairing.token, server_pairing.token);
        assert_ne!(client_pairing.role, server_pairing.role);
        assert!(matches!(client_pairing.role, PairingRole::CommunicationServer));

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn pairing_rejects_invalid_hmac() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, S2Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, S2Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let finalize_result = Arc::new(Mutex::new(None));
        let finalize_result_clone = finalize_result.clone();
        let (server_handle, _) = setup_server(
            server_config,
            Router::new()
                .route(
                    "/v1/requestPairing",
                    post(|| async {
                        Json(RequestPairingResponse {
                            pairing_attempt_id: PairingAttemptId("testid".into()),
                            server_s2_node_description: basic_node_description(UUID_A, S2Role::Cem),
                            server_s2_endpoint_description: S2EndpointDescription::default(),
                            selected_hmac_hashing_algorithm: crate::pairing::wire::HmacHashingAlgorithm::Sha256,
                            client_hmac_challenge_response: HmacChallengeResponse(vec![0; 64]),
                            server_hmac_challenge: HmacChallenge::new(&mut rand::rng(), 32),
                        })
                    }),
                )
                .route(
                    "/v1/finalizePairing",
                    post(|attempt_id: PairingAttemptId, Json(success): Json<bool>| async move {
                        assert_eq!(attempt_id.0, "testid");
                        *finalize_result_clone.lock().unwrap() = Some(success);
                    }),
                ),
        )
        .await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: UUID_A.into(),
        };

        let client = Client::new(
            Arc::new(client_config),
            ClientConfig {
                additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
                pairing_deployment: Deployment::Wan,
            },
        )
        .unwrap();

        let client_pairing = client.pair(remote, b"testtoken").await.unwrap_err();
        assert_eq!(client_pairing.kind(), ErrorKind::InvalidToken);
        assert_eq!(*finalize_result.lock().unwrap(), Some(false));

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn pairing_rejects_same_role() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, S2Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let finalize_result = Arc::new(Mutex::new(None));
        let finalize_result_clone = finalize_result.clone();
        let (server_handle, _) = setup_server(
            server_config,
            Router::new()
                .route(
                    "/v1/requestPairing",
                    post(|Json(request): Json<RequestPairing>| async move {
                        Json(RequestPairingResponse {
                            pairing_attempt_id: PairingAttemptId("testid".into()),
                            server_s2_node_description: basic_node_description(UUID_A, S2Role::Rm),
                            server_s2_endpoint_description: S2EndpointDescription::default(),
                            selected_hmac_hashing_algorithm: crate::pairing::wire::HmacHashingAlgorithm::Sha256,
                            client_hmac_challenge_response: request.client_hmac_challenge.sha256(&Network::Wan, b"testtoken"),
                            server_hmac_challenge: HmacChallenge::new(&mut rand::rng(), 32),
                        })
                    }),
                )
                .route(
                    "/v1/finalizePairing",
                    post(|attempt_id: PairingAttemptId, Json(success): Json<bool>| async move {
                        assert_eq!(attempt_id.0, "testid");
                        *finalize_result_clone.lock().unwrap() = Some(success);
                    }),
                ),
        )
        .await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: UUID_A.into(),
        };

        let client = Client::new(
            Arc::new(client_config),
            ClientConfig {
                additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
                pairing_deployment: Deployment::Wan,
            },
        )
        .unwrap();

        let client_pairing = client.pair(remote, b"testtoken").await.unwrap_err();
        assert_eq!(client_pairing.kind(), ErrorKind::RemoteOfSameType);
        assert_eq!(*finalize_result.lock().unwrap(), Some(false));

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn pairing_rejects_same_role_reported_by_server() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, S2Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let finalize_result = Arc::new(Mutex::new(None));
        let finalize_result_clone = finalize_result.clone();
        let (server_handle, _) = setup_server(
            server_config,
            Router::new()
                .route(
                    "/v1/requestPairing",
                    post(|| async {
                        (
                            StatusCode::BAD_REQUEST,
                            Json(PairingResponseErrorMessage::InvalidCombinationOfRoles),
                        )
                    }),
                )
                .route(
                    "/v1/finalizePairing",
                    post(|attempt_id: PairingAttemptId, Json(success): Json<bool>| async move {
                        assert_eq!(attempt_id.0, "testid");
                        *finalize_result_clone.lock().unwrap() = Some(success);
                    }),
                ),
        )
        .await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: UUID_A.into(),
        };

        let client = Client::new(
            Arc::new(client_config),
            ClientConfig {
                additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
                pairing_deployment: Deployment::Wan,
            },
        )
        .unwrap();

        let client_pairing = client.pair(remote, b"testtoken").await.unwrap_err();
        assert_eq!(client_pairing.kind(), ErrorKind::RemoteOfSameType);
        assert_eq!(*finalize_result.lock().unwrap(), None);

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn pairing_invokes_finalize_on_bad_request_connection_details() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, S2Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, S2Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let finalize_result = Arc::new(Mutex::new(None));
        let finalize_result_clone = finalize_result.clone();
        let (server_handle, _) = setup_server(
            server_config,
            Router::new()
                .route("/v1/requestConnectionDetails", post(|| async { StatusCode::BAD_GATEWAY }))
                .route(
                    "/v1/finalizePairing",
                    post(|Json(success): Json<bool>| async move {
                        *finalize_result_clone.lock().unwrap() = Some(success);
                    }),
                ),
        )
        .await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: UUID_A.into(),
        };

        let client = Client::new(
            Arc::new(client_config),
            ClientConfig {
                additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
                pairing_deployment: Deployment::Wan,
            },
        )
        .unwrap();

        let client_pairing = client.pair(remote, b"testtoken").await.unwrap_err();
        assert_eq!(client_pairing.kind(), ErrorKind::ProtocolError);
        assert_eq!(*finalize_result.lock().unwrap(), Some(false));

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn pairing_invokes_finalize_on_bad_post_connection_details() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, S2Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let finalize_result = Arc::new(Mutex::new(None));
        let finalize_result_clone = finalize_result.clone();
        let (server_handle, _) = setup_server(
            server_config,
            Router::new()
                .route("/v1/postConnectionDetails", post(|| async { StatusCode::BAD_GATEWAY }))
                .route(
                    "/v1/finalizePairing",
                    post(|Json(success): Json<bool>| async move {
                        *finalize_result_clone.lock().unwrap() = Some(success);
                    }),
                ),
        )
        .await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: UUID_A.into(),
        };

        let client = Client::new(
            Arc::new(client_config),
            ClientConfig {
                additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
                pairing_deployment: Deployment::Wan,
            },
        )
        .unwrap();

        let client_pairing = client.pair(remote, b"testtoken").await.unwrap_err();
        assert_eq!(client_pairing.kind(), ErrorKind::ProtocolError);
        assert_eq!(*finalize_result.lock().unwrap(), Some(false));

        server_handle.shutdown();
    }
}
