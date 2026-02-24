use std::sync::Arc;

use axum::http;
use reqwest::{StatusCode, Url};
use rustls::pki_types::CertificateDer;
use tokio_tungstenite::{Connector, connect_async_tls_with_config, tungstenite::ClientRequestBuilder};
use tracing::{debug, trace};

use crate::{
    AccessToken, CommunicationProtocol, S2EndpointDescription, S2NodeId,
    common::negotiate_version,
    communication::{
        CommunicationResult, ConnectionInfo, Error, ErrorKind, NodeConfig, WebSocketTransport,
        wire::{CommunicationDetails, InitiateConnectionRequest, InitiateConnectionResponse},
    },
};

/// Configuration for communication clients.
pub struct ClientConfig {
    /// Additional roots of trust for TLS connections. Useful when testing during the development of WAN endpoints.
    ///
    /// When the remote is on the LAN, this is not used.
    pub additional_certificates: Vec<CertificateDer<'static>>,
    /// Optional description of this endpoint, sent as update to the server.
    pub endpoint_description: Option<S2EndpointDescription>,
}

pub struct Client {
    config: Arc<NodeConfig>,
    additional_certificates: Vec<CertificateDer<'static>>,
    endpoint_description: Option<S2EndpointDescription>,
}

pub trait ClientPairing: Send {
    type Error: std::error::Error + 'static;

    fn client_id(&self) -> S2NodeId;
    fn server_id(&self) -> S2NodeId;
    fn access_tokens(&self) -> impl AsRef<[AccessToken]>;
    fn communication_url(&self) -> impl AsRef<str>;

    fn set_access_tokens(&mut self, tokens: Vec<AccessToken>) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

impl Client {
    pub fn new(config: ClientConfig, node_config: Arc<NodeConfig>) -> Self {
        Client {
            config: node_config,
            additional_certificates: config.additional_certificates,
            endpoint_description: config.endpoint_description,
        }
    }

    #[tracing::instrument(skip_all, fields(client = %pairing.client_id(), server = %pairing.server_id()), level = tracing::Level::ERROR)]
    pub async fn connect(&self, mut pairing: impl ClientPairing) -> CommunicationResult<ConnectionInfo> {
        trace!("Establishing new communication connection.");
        let client = reqwest::Client::builder()
            .tls_certs_merge(
                self.additional_certificates
                    .iter()
                    .filter_map(|v| reqwest::Certificate::from_der(v).ok()),
            )
            .build()
            .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;

        trace!("Prepared reqwest client.");

        let communication_url = Url::parse(pairing.communication_url().as_ref()).map_err(|e| Error::new(ErrorKind::InvalidUrl, e))?;

        let version = negotiate_version(&client, communication_url.clone()).await?;

        match version {
            crate::common::wire::PairingVersion::V1 => {
                let base_url = communication_url.join("v1/").unwrap();

                let request = InitiateConnectionRequest {
                    client_node_id: pairing.client_id(),
                    server_node_id: pairing.server_id(),
                    supported_message_versions: self.config.supported_message_versions.clone(),
                    supported_communication_protocols: vec![CommunicationProtocol("WebSocket".into())],
                    node_description: self.config.node_description().cloned(),
                    endpoint_description: self.endpoint_description.clone(),
                };

                let (initiate_response, current_token) = 'found: {
                    for token in pairing.access_tokens().as_ref() {
                        let response = client
                            .post(base_url.join("initiateConnection").unwrap())
                            .bearer_auth(&token.0)
                            .json(&request)
                            .send()
                            .await
                            .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;

                        if response.status() == StatusCode::UNAUTHORIZED {
                            debug!("Token was rejected by remote, assuming it is old.");
                            continue;
                        }
                        if response.status() != StatusCode::OK {
                            debug!(status = ?response.status(), "Unexpected status in response to initiateConnection request.");
                            return Err(ErrorKind::ProtocolError.into());
                        }

                        break 'found (
                            response
                                .json::<InitiateConnectionResponse>()
                                .await
                                .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?,
                            token.clone(),
                        );
                    }

                    // Exhausted all the possible options.
                    return Err(ErrorKind::NotPaired.into());
                };

                trace!("Initiated connection attempt.");

                pairing
                    .set_access_tokens(vec![current_token, initiate_response.access_token.clone()])
                    .await
                    .map_err(|e| Error::new(ErrorKind::Storage, Box::new(e) as Box<_>))?;

                trace!("Stored new access token.");

                let response = client
                    .post(base_url.join("confirmAccessToken").unwrap())
                    .bearer_auth(&initiate_response.access_token.0)
                    .send()
                    .await
                    .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;

                if response.status() != StatusCode::OK {
                    debug!(status = ?response.status(), "Unexpected response to confirmAccessToken request.");
                    return Err(ErrorKind::ProtocolError.into());
                }

                let communication_details = response
                    .json::<CommunicationDetails>()
                    .await
                    .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;

                trace!("Confirmed new access token to server.");

                match communication_details {
                    CommunicationDetails::WebSocket(web_socket_communication_details) => {
                        let tls_config_builder = rustls::ClientConfig::builder();
                        let cert_verifier = rustls_platform_verifier::Verifier::new_with_extra_roots(
                            self.additional_certificates.iter().cloned(),
                            tls_config_builder.crypto_provider().clone(),
                        )
                        .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;
                        let tls_config = tls_config_builder
                            .dangerous()
                            .with_custom_certificate_verifier(Arc::new(cert_verifier))
                            .with_no_client_auth();

                        let request = ClientRequestBuilder::new(
                            web_socket_communication_details
                                .websocket_url
                                .try_into()
                                .map_err(|e| Error::new(ErrorKind::ProtocolError, e))?,
                        )
                        .with_header(
                            http::header::AUTHORIZATION.as_str(),
                            format!("Bearer {}", web_socket_communication_details.websocket_token.0),
                        );

                        let (websocket, _) =
                            connect_async_tls_with_config(request, None, false, Some(Connector::Rustls(Arc::new(tls_config))))
                                .await
                                .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;

                        Ok(ConnectionInfo {
                            server_node_description: initiate_response.node_description,
                            server_endpoint_description: initiate_response.endpoint_description,
                            message_version: initiate_response.message_version,
                            transport: WebSocketTransport::new_client(websocket),
                        })
                    }
                }
            }
        }
    }
}
