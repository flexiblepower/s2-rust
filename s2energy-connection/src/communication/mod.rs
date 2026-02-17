use crate::{MessageVersion, S2NodeDescription, common::BaseError};

mod client;
mod server;
mod wire;

pub use client::{Client, ClientConfig, ClientPairing, ConnectionInfo};
pub use server::{PairingLookup, PairingLookupResult, Server, ServerConfig, ServerPairing, ServerPairingStore};

/// Full description of an S2 endpoint
#[derive(Debug, Clone)]
pub struct NodeConfig {
    node_description: Option<S2NodeDescription>,
    supported_message_versions: Vec<MessageVersion>,
}

impl NodeConfig {
    /// Description of the S2 node.
    pub fn node_description(&self) -> Option<&S2NodeDescription> {
        self.node_description.as_ref()
    }

    /// Message versions supported by this endpoint.
    pub fn supported_message_versions(&self) -> &[MessageVersion] {
        &self.supported_message_versions
    }

    /// Create a builder for a new [`EndpointConfig`]
    ///
    /// All endpoint configurations must at least contain description of the node and supported message versions. Additional
    /// properties can be configured through the builder.
    pub fn builder(supported_message_versions: Vec<MessageVersion>) -> ConfigBuilder {
        ConfigBuilder {
            node_description: None,
            supported_message_versions,
        }
    }
}

/// Builder for an [`EndpointConfig`]
pub struct ConfigBuilder {
    node_description: Option<S2NodeDescription>,
    supported_message_versions: Vec<MessageVersion>,
}

impl ConfigBuilder {
    /// Set the node description.
    ///
    /// Note that this replaces any previous node decriptions passed
    pub fn with_node_description(mut self, node_description: S2NodeDescription) -> Self {
        self.node_description = Some(node_description);
        self
    }

    /// Create the actual [`EndpointConfig`], validating that it is reasonable.
    pub fn build(self) -> NodeConfig {
        NodeConfig {
            node_description: self.node_description,
            supported_message_versions: self.supported_message_versions,
        }
    }
}

/// Error that occured during the communication process.
#[derive(Debug, Clone)]
pub enum Error {
    /// Invalid URL for remote
    InvalidUrl,
    /// Something went wrong in the transport layers
    TransportFailed,
    /// The remote reacted outside our expectations
    ProtocolError,
    /// No shared version with the remote.
    NoSupportedVersion,
    /// The nodes are no longer paired
    Unpaired,
    /// The nodes were not paired
    NotPaired,
    /// Storage failed to persist token
    Storage,
}

impl From<BaseError> for Error {
    fn from(value: BaseError) -> Self {
        match value {
            BaseError::TransportFailed => Self::TransportFailed,
            BaseError::ProtocolError => Self::ProtocolError,
            BaseError::NoSupportedVersion => Self::NoSupportedVersion,
        }
    }
}

/// Convenience type for [`Result<T, Error>`]
pub type CommunicationResult<T> = Result<T, Error>;
