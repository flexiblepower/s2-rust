use axum::{Json, extract::FromRequestParts, response::IntoResponse};
use axum_extra::{TypedHeader, headers};
use http::StatusCode;
use rand::distr::{Alphanumeric, SampleString};
use serde::{ser::SerializeMap, *};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tracing::info;

use crate::{
    CertificateHash, CertificateHashInner, NodeId,
    common::wire::{AccessToken, CommunicationProtocol, EndpointDescription, MessageVersion, NodeDescription},
};

#[derive(Error, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
#[serde(tag = "errorMessage")]
pub(crate) enum PairingResponseErrorMessage {
    #[error("Invalid combination of roles")]
    InvalidCombinationOfRoles,
    #[error("Incompatible S2 message versions")]
    IncompatibleS2MessageVersions,
    #[error("Incompatible HMAC hashing algorithms")]
    IncompatibleHMACHashingAlgorithms,
    #[error("Incompatible communication protocols")]
    IncompatibleCommunicationProtocols,
    #[error("S2Node not found")]
    S2NodeNotFound,
    #[error("No S2Node provided")]
    S2NodeNotProvided,
    #[error("No valid pairingToken on PairingServer")]
    InvalidPairingToken,
    #[error("Parsing error")]
    ParsingError,
    #[error("Other")]
    Other,
}

impl From<PairingResponseErrorMessage> for super::Error {
    fn from(value: PairingResponseErrorMessage) -> Self {
        use super::ErrorKind;
        use PairingResponseErrorMessage::*;

        let error_kind = match value {
            InvalidCombinationOfRoles => ErrorKind::RemoteOfSameType,
            IncompatibleS2MessageVersions | IncompatibleHMACHashingAlgorithms | IncompatibleCommunicationProtocols => {
                ErrorKind::NoSupportedVersion
            }
            S2NodeNotFound | S2NodeNotProvided => ErrorKind::UnknownNode,
            InvalidPairingToken => ErrorKind::InvalidToken,
            ParsingError | PairingResponseErrorMessage::Other => ErrorKind::ProtocolError,
        };

        super::Error::new(error_kind, value)
    }
}

impl IntoResponse for PairingResponseErrorMessage {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
}

#[derive(Error, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "errorMessage")]
pub(crate) enum WaitForPairingErrorMessage {
    #[error("No valid token available on remote.")]
    NoValidTokenOnPairingClient,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum HmacHashingAlgorithm {
    Sha256,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct HmacChallenge(
    #[serde(serialize_with = "base64_bytes::serialize", deserialize_with = "deserialize_hmac_challenge")] pub(crate) Vec<u8>,
);

pub(crate) fn deserialize_hmac_challenge<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let decoded = base64_bytes::deserialize(deserializer)?;

    // The spec demands that an hmac challenge is at least 32 bytes.
    if decoded.len() < 32 {
        return Err(de::Error::custom("hmac challenge shorter than 32 bytes"));
    }

    Ok(decoded)
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq)]
pub(crate) struct HmacChallengeResponse(
    #[serde(serialize_with = "base64_bytes::serialize", deserialize_with = "base64_bytes::deserialize")] pub(crate) Vec<u8>,
);

impl PartialEq for HmacChallengeResponse {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

/// An identifier of the S2 node which is unique for the context of the Endpoint.
///
/// It is used as a short identifier (since the user might have to type it in manually)
/// for the S2Node, which can be used to lookup the actual [`S2NodeId`].
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeIdAlias(pub String);

impl NodeIdAlias {
    /// Create a new id.
    pub fn new(rng: &mut impl rand::CryptoRng) -> Self {
        Self(Alphanumeric.sample_string(rng, 12))
    }
}

impl std::fmt::Display for NodeIdAlias {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct RequestPairing {
    #[serde(rename = "clientNodeDescription")]
    pub node_description: NodeDescription,
    #[serde(rename = "clientEndpointDescription")]
    pub endpoint_description: EndpointDescription,
    /// A server-assigned identifier of the S2Node that this server represents.
    #[serde(rename = "nodeIdAlias")]
    #[serde(default)]
    pub id: Option<NodeIdAlias>,
    #[serde(rename = "supportedCommunicationProtocols")]
    pub supported_protocols: Vec<CommunicationProtocol>,
    /// The versions of the S2 JSON message schemas this S2Node implementation currently supports.
    #[serde(rename = "supportedS2MessageVersions")]
    pub supported_versions: Vec<MessageVersion>,
    #[serde(rename = "supportedHmacHashingAlgorithms")]
    #[serde(default)]
    pub supported_hashing_algorithms: Vec<HmacHashingAlgorithm>,
    #[serde(rename = "clientHmacChallenge")]
    pub client_hmac_challenge: HmacChallenge,
    /// Forces the server to attempt pairing, even though the S2 message versions are not compatible. In this case the S2Nodes won't be able to communicate after pairing, but this could later be solved through a software update on one or both of the S2Nodes.
    #[serde(rename = "forcePairing")]
    #[serde(default)]
    pub force_pairing: bool,
}

/// An identifier that is generated by the server for each pairing attempt.
#[derive(Serialize, Deserialize, Debug, Clone, Eq)]
pub(super) struct PairingAttemptId(pub(super) String);

impl PartialEq for PairingAttemptId {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl std::hash::Hash for PairingAttemptId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PairingAttemptId {
    pub fn new(rng: &mut impl rand::CryptoRng) -> Self {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        let encoded = STANDARD.encode(bytes);
        Self(encoded)
    }
}

impl<S: Sync + Send> FromRequestParts<S> for PairingAttemptId {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut axum::http::request::Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Some(token) = Option::<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>::from_request_parts(parts, state)
            .await
            .ok()
            .flatten()
        else {
            info!(uri = ?parts.uri, "Missing or invalid authorization header.");
            return Err(StatusCode::UNAUTHORIZED);
        };

        Ok(PairingAttemptId(token.token().into()))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RequestPairingResponse {
    pub pairing_attempt_id: PairingAttemptId,
    pub server_node_description: NodeDescription,
    pub server_endpoint_description: EndpointDescription,
    pub selected_hmac_hashing_algorithm: HmacHashingAlgorithm,
    pub client_hmac_challenge_response: HmacChallengeResponse,
    pub server_hmac_challenge: HmacChallenge,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RequestConnectionDetailsRequest {
    pub server_hmac_challenge_response: HmacChallengeResponse,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PrePairingRequest {
    pub client_endpoint_description: EndpointDescription,
    pub client_node_description: NodeDescription,
    #[serde(rename = "serverNodeId")]
    pub server_id: Option<NodeId>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct CancelPrePairingRequest {
    #[serde(rename = "clientNodeId")]
    pub client_id: NodeId,
    #[serde(rename = "serverNodeId")]
    pub server_id: Option<NodeId>,
}

/// Details the Connection client needs to set up an S2 session.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConnectionDetails {
    pub initiate_connection_url: String,
    pub access_token: AccessToken,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_fingerprint",
        deserialize_with = "deserialize_fingerprint"
    )]
    pub certificate_fingerprint: Option<CertificateHash>,
}

pub(crate) fn serialize_fingerprint<S: Serializer>(value: &Option<CertificateHash>, serializer: S) -> Result<S::Ok, S::Error> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    // Unwrap is ok here as we serialize only when not none.
    let encoded = STANDARD.encode(value.as_deref().unwrap() as &[u8]);
    let mut map = serializer.serialize_map(Some(1))?;
    map.serialize_entry("SHA256", &encoded)?;
    map.end()
}

pub(crate) fn deserialize_fingerprint<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<CertificateHash>, D::Error> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{borrow::Cow, collections::HashMap};
    let data = HashMap::<Cow<'de, str>, Cow<'de, str>>::deserialize(deserializer)?;
    if let Some(hash) = data.get("SHA256") {
        let decoded = STANDARD.decode(hash.as_ref()).map_err(de::Error::custom)?;
        Ok(Some(CertificateHash(CertificateHashInner::Sha256(
            <[u8; 32]>::try_from(decoded)
                .map_err(|_| de::Error::custom("Hash is wrong length"))?
                .into(),
        ))))
    } else {
        Err(de::Error::custom("Missing SHA256 hash"))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PostConnectionDetailsRequest {
    pub server_hmac_challenge_response: HmacChallengeResponse,
    pub connection_details: ConnectionDetails,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WaitForPairingRequest {
    pub client_node_id: NodeId,
    pub clien_node_description: Option<NodeDescription>,
    pub client_endpoint_description: Option<EndpointDescription>,
    #[serde(flatten)]
    pub error_message: Option<WaitForPairingErrorMessage>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct FinalizePairingRequest {
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub(crate) enum WaitForPairingAction {
    SendNodeDescription,
    PreparePairing,
    CancelPreparePairing,
    RequestPairing,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WaitForPairingResponse {
    pub client_node_id: NodeId,
    pub action: WaitForPairingAction,
}

mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub(crate) fn serialize<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        let encoded = STANDARD.encode(value.as_ref());
        serializer.serialize_str(&encoded)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = STANDARD.decode(&s).map_err(de::Error::custom)?;

        Ok(decoded)
    }
}
