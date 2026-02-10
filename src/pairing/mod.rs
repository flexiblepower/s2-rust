#![allow(missing_docs)]
#![warn(clippy::clone_on_copy)]
mod client;
mod server;
mod transport;
mod wire;

use rand::Rng;

use wire::{AccessToken, HmacChallenge, HmacChallengeResponse};

pub use client::{Client, PairingRemote};
pub use server::{PairingToken, Server, ServerConfig};
pub use wire::{CommunicationProtocol, Deployment, MessageVersion, S2EndpointDescription, S2NodeDescription, S2NodeId, S2Role};

use crate::pairing::wire::PairingVersion;

const SUPPORTED_PAIRING_VERSIONS: &[PairingVersion] = &[PairingVersion::V1];

#[derive(Debug, Clone)]
pub struct EndpointConfig {
    node_description: S2NodeDescription,
    endpoint_description: S2EndpointDescription,
    supported_message_versions: Vec<MessageVersion>,
    supported_communication_protocols: Vec<CommunicationProtocol>,
    connection_initiate_url: Option<String>,
}

impl EndpointConfig {
    pub fn node_description(&self) -> &S2NodeDescription {
        &self.node_description
    }

    pub fn endpoint_description(&self) -> &S2EndpointDescription {
        &self.endpoint_description
    }

    pub fn supported_message_versions(&self) -> &[MessageVersion] {
        &self.supported_message_versions
    }

    pub fn builder(node_description: S2NodeDescription, supported_message_versions: Vec<MessageVersion>) -> ConfigBuilder {
        ConfigBuilder {
            node_description,
            endpoint_description: S2EndpointDescription::default(),
            supported_message_versions,
            supported_communication_protocols: vec![CommunicationProtocol("WebSocket".into())],
            connection_initiate_url: None,
        }
    }
}

pub struct ConfigBuilder {
    node_description: S2NodeDescription,
    endpoint_description: S2EndpointDescription,
    supported_message_versions: Vec<MessageVersion>,
    supported_communication_protocols: Vec<CommunicationProtocol>,
    connection_initiate_url: Option<String>,
}

impl ConfigBuilder {
    pub fn with_connection_initiate_url(mut self, connection_initiate_url: String) -> Self {
        self.connection_initiate_url = Some(connection_initiate_url);
        self
    }

    pub fn with_supported_communication_protocols(mut self, communication_protocols: Vec<CommunicationProtocol>) -> Self {
        self.supported_communication_protocols = communication_protocols;
        self
    }

    pub fn with_endpoint_description(mut self, endpoint_description: S2EndpointDescription) -> Self {
        self.endpoint_description = endpoint_description;
        self
    }

    pub fn build(self) -> Result<EndpointConfig, ConfigError> {
        if (self.node_description.role == S2Role::Cem || self.endpoint_description.deployment == Some(Deployment::Wan))
            && self.connection_initiate_url.is_none()
        {
            return Err(ConfigError::MissingInitiateUrl);
        }
        Ok(EndpointConfig {
            node_description: self.node_description,
            endpoint_description: self.endpoint_description,
            supported_message_versions: self.supported_message_versions,
            supported_communication_protocols: self.supported_communication_protocols,
            connection_initiate_url: self.connection_initiate_url,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConfigError {
    MissingInitiateUrl,
}

pub enum PairingRole {
    CommunicationClient { initiate_url: String },
    CommunicationServer,
}

pub struct Pairing {
    pub remote_node_description: S2NodeDescription,
    pub remote_endpoint_description: S2EndpointDescription,
    pub token: AccessToken,
    pub role: PairingRole,
}

impl HmacChallenge {
    pub fn new(rng: &mut impl Rng) -> Self {
        Self(rng.random())
    }

    pub fn sha256(&self, network: &Network, pairing_token: &[u8]) -> HmacChallengeResponse {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC can take a key of any size");

        match network {
            Network::Wan => {
                // R = HMAC(C, T)
                mac.update(pairing_token);
            }
            Network::Lan { fingerprint } => {
                // R = HMAC(C, T || F)
                mac.update(pairing_token);
                mac.update(fingerprint);
            }
        }

        HmacChallengeResponse(mac.finalize().into_bytes().into())
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    // Something went wrong in the transport layers
    TransportFailed,
    // The remote reacted outside our expectations
    ProtocolError,
    // No shared version with the remote.
    NoSupportedVersion,
    // Session timed out.
    Timeout,
    // Already a pending pairing session with that node id.
    AlreadyPending,
    // Provided token was invalid.
    InvalidToken,
    // The pairing session was cancelled.
    Cancelled,
    // The remote is of the same type
    RemoteOfSameType,
    // The configuration was invalid
    InvalidConfig(ConfigError),
}

impl From<ConfigError> for Error {
    fn from(value: ConfigError) -> Self {
        Self::InvalidConfig(value)
    }
}

pub type PairingResult<T> = Result<T, Error>;

#[derive(Debug)]
enum Network {
    Wan,
    Lan { fingerprint: [u8; 32] },
}

impl Network {
    fn as_deployment(&self) -> Deployment {
        match self {
            Network::Wan => Deployment::Wan,
            Network::Lan { .. } => Deployment::Lan,
        }
    }
}
