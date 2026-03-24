use axum::extract::FromRequestParts;
use axum_extra::{TypedHeader, headers};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tracing::info;

use crate::{CommunicationProtocol, EndpointDescription, MessageVersion, NodeDescription, NodeId, common::wire::AccessToken};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(tag = "communicationProtocol")]
pub(crate) enum CommunicationDetails {
    WebSocket(WebSocketCommunicationDetails),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub(crate) struct WebSocketCommunicationDetails {
    pub(crate) websocket_token: CommunicationToken,
    pub(crate) websocket_url: String,
}

#[derive(Serialize, Deserialize, Debug, Error, Clone, PartialEq, Eq, Hash)]
#[serde(tag = "errorMessage")]
pub(crate) enum CommunicationDetailsErrorMessage {
    #[error("Incompatible S2 message versions")]
    IncompatibleS2MessageVersions,
    #[error("Incompatible communication protocols")]
    IncompatibleCommunicationProtocols,
    #[error("No longer paired")]
    NoLongerPaired,
    #[error("Parsing error")]
    ParsingError,
    #[error("Other")]
    Other,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct InitiateConnectionRequest {
    #[serde(rename = "clientNodeId")]
    pub(crate) client_node_id: NodeId,
    #[serde(rename = "serverNodeId")]
    pub(crate) server_node_id: NodeId,
    #[serde(rename = "supportedS2MessageVersions")]
    pub(crate) supported_message_versions: Vec<MessageVersion>,
    #[serde(rename = "supportedCommunicationProtocols")]
    pub(crate) supported_communication_protocols: Vec<CommunicationProtocol>,
    #[serde(rename = "clientNodeDescription")]
    pub(crate) node_description: Option<NodeDescription>,
    #[serde(rename = "clientEndpointDescription")]
    pub(crate) endpoint_description: Option<EndpointDescription>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub(crate) struct InitiateConnectionResponse {
    #[serde(rename = "selectedCommunicationProtocol")]
    pub(crate) communication_protocol: CommunicationProtocol,
    #[serde(rename = "selectedS2MessageVersion")]
    pub(crate) message_version: MessageVersion,
    #[serde(rename = "accessToken")]
    pub(crate) access_token: AccessToken,
    #[serde(rename = "serverNodeDescription")]
    pub(crate) node_description: Option<NodeDescription>,
    #[serde(rename = "serverEndpointDescription")]
    pub(crate) endpoint_description: Option<EndpointDescription>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct UnpairRequest {
    #[serde(rename = "clientNodeId")]
    pub(crate) client_node_id: NodeId,
    #[serde(rename = "serverNodeId")]
    pub(crate) server_node_id: NodeId,
}

/// One-time access token for secure access to the S2 message communication channel. It must be renewed every time a client wants to access
/// the S2 message communication channel by calling the requestToken endpoint. This token is valid for one time login, with a maximum 5
/// years, and should have a minimum length of 32 bytes.
#[derive(Serialize, Deserialize, Clone, Eq)]
pub struct CommunicationToken(pub String);

impl PartialEq for CommunicationToken {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl std::hash::Hash for CommunicationToken {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl CommunicationToken {
    pub fn new(rng: &mut impl rand::CryptoRng) -> Self {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        let encoded = STANDARD.encode(bytes);
        Self(encoded)
    }
}

impl<S: Sync + Send> FromRequestParts<S> for CommunicationToken {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut axum::http::request::Parts, state: &S) -> Result<Self, Self::Rejection> {
        type BearerHeader = TypedHeader<headers::Authorization<headers::authorization::Bearer>>;
        let Some(token) = Option::<BearerHeader>::from_request_parts(parts, state).await.ok().flatten() else {
            info!(uri = ?parts.uri, "Missing or invalid authorization header.");
            return Err(StatusCode::UNAUTHORIZED);
        };

        Ok(CommunicationToken(token.token().into()))
    }
}
