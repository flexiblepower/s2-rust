use axum::extract::FromRequestParts;
use axum_extra::{TypedHeader, headers};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PairingVersion {
    V1,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub(crate) enum WirePairingVersion {
    V1,
    #[serde(other)]
    Other,
}

impl TryFrom<WirePairingVersion> for PairingVersion {
    type Error = ();

    fn try_from(value: WirePairingVersion) -> Result<Self, Self::Error> {
        match value {
            WirePairingVersion::V1 => Ok(PairingVersion::V1),
            WirePairingVersion::Other => Err(()),
        }
    }
}

/// Message schema version.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageVersion(pub String);

/// Information about the pairing endpoint of a S2 node
#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct S2EndpointDescription {
    /// Name of the endpoint
    #[serde(default)]
    pub name: Option<String>,
    /// URI of a logo to be used for the endpoint in GUIs
    #[serde(default)]
    pub logo_uri: Option<String>,
    /// Type of deployment used by the endpoint (local or globally routable).
    #[serde(default)]
    pub deployment: Option<Deployment>,
}

/// One-time access token for secure access to the S2 message communication channel. It must be renewed every time a client wants to access
/// the S2 message communication channel by calling the requestToken endpoint. This token is valid for one time login, with a maximum 5
/// years, and should have a minimum length of 32 bytes.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct AccessToken(pub String);

impl AccessToken {
    pub fn new(rng: &mut impl rand::Rng) -> Self {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);

        let encoded = STANDARD.encode(bytes);
        Self(encoded)
    }
}

impl AsRef<AccessToken> for AccessToken {
    fn as_ref(&self) -> &AccessToken {
        self
    }
}

impl<S: Sync + Send> FromRequestParts<S> for AccessToken {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut axum::http::request::Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Some(token) = Option::<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>::from_request_parts(parts, state)
            .await
            .ok()
            .flatten()
        else {
            return Err(StatusCode::UNAUTHORIZED);
        };

        Ok(AccessToken(token.token().into()))
    }
}

/// Unique identifier of the S2 node
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct S2NodeId(pub String);

/// Information about the S2 node
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct S2NodeDescription {
    /// Unique identifier of the node
    pub id: S2NodeId,
    /// Brandname used for the node
    pub brand: String,
    /// URI of a logo to be used for the node in GUIs
    #[serde(default)]
    pub logo_uri: Option<String>,
    /// The type of this node.
    pub type_: String,
    /// Model name of the device this node belongs to.
    pub model_name: String,
    /// A name for the device configured by the end user/owner.
    #[serde(default)]
    pub user_defined_name: Option<String>,
    /// The S2 role this device has (e.g. CEM or RM).
    pub role: S2Role,
}

/// Identifier of a protocol that can be used for communication of S2 messages between nodes, for example `"WebSocket"`
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct CommunicationProtocol(pub String);

/// Role within the S2 standard.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum S2Role {
    /// Customer Energy Manager.
    Cem,
    /// Resource Manager.
    Rm,
}

/// Place of deployment for an S2 Node
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum Deployment {
    /// On a WAN, reachable over the internet
    Wan,
    /// On the local network, only reachable near the place the device is located.
    Lan,
}
