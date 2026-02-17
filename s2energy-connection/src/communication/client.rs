use std::sync::Arc;

use reqwest::{StatusCode, Url};
use rustls::pki_types::CertificateDer;

use crate::{
    AccessToken, CommunicationProtocol, MessageVersion, S2EndpointDescription, S2NodeDescription, S2NodeId,
    common::negotiate_version,
    communication::{
        CommunicationResult, Error, NodeConfig,
        wire::{CommunicationDetails, CommunicationToken, InitiateConnectionRequest, InitiateConnectionResponse},
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

pub struct ConnectionInfo {
    pub server_node_description: Option<S2NodeDescription>,
    pub server_endpoint_description: Option<S2EndpointDescription>,
    pub message_version: MessageVersion,

    // TODO: replace with actual transport.
    pub communication_token: CommunicationToken,
    pub communication_url: String,
}

pub trait ClientPairing: Send {
    type Error: std::error::Error;

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

    pub async fn connect(&self, mut pairing: impl ClientPairing) -> CommunicationResult<ConnectionInfo> {
        let client = reqwest::Client::builder()
            .tls_certs_merge(
                self.additional_certificates
                    .iter()
                    .filter_map(|v| reqwest::Certificate::from_der(v).ok()),
            )
            .build()
            .map_err(|_| Error::TransportFailed)?;

        let communication_url = Url::parse(pairing.communication_url().as_ref()).map_err(|_| Error::InvalidUrl)?;

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

                let Some((initiate_response, current_token)) = ('found: {
                    for token in pairing.access_tokens().as_ref() {
                        let response = client
                            .post(base_url.join("initiateConnection").unwrap())
                            .bearer_auth(&token.0)
                            .json(&request)
                            .send()
                            .await
                            .map_err(|_| Error::TransportFailed)?;

                        if response.status() == StatusCode::UNAUTHORIZED {
                            continue;
                        }
                        if response.status() != StatusCode::OK {
                            return Err(Error::TransportFailed);
                        }

                        break 'found Some((
                            response
                                .json::<InitiateConnectionResponse>()
                                .await
                                .map_err(|_| Error::TransportFailed)?,
                            token.clone(),
                        ));
                    }
                    None
                }) else {
                    return Err(Error::NotPaired);
                };

                pairing
                    .set_access_tokens(vec![current_token, initiate_response.access_token.clone()])
                    .await
                    .map_err(|_| Error::Storage)?;

                let response = client
                    .post(base_url.join("confirmAccessToken").unwrap())
                    .bearer_auth(&initiate_response.access_token.0)
                    .send()
                    .await
                    .map_err(|_| Error::TransportFailed)?;

                if response.status() != StatusCode::OK {
                    return Err(Error::ProtocolError);
                }

                let communication_details = response.json::<CommunicationDetails>().await.map_err(|_| Error::TransportFailed)?;

                match communication_details {
                    CommunicationDetails::WebSocket(web_socket_communication_details) => Ok(ConnectionInfo {
                        server_node_description: initiate_response.node_description,
                        server_endpoint_description: initiate_response.endpoint_description,
                        message_version: initiate_response.message_version,
                        communication_token: web_socket_communication_details.websocket_token,
                        communication_url: web_socket_communication_details.websocket_url,
                    }),
                }
            }
        }
    }
}
