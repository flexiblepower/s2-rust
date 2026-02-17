//! Pairing logic for the S2 protocols.
//!
//! This module provides client and server implementations of the [S2 pairing protocol](https://docs.s2standard.org/docs/communication-layer/discovery-pairing-authentication/#the-pairing-process)
//!
//! # Endpoint configuration
//!
//! The main configuration struct [`EndpointConfig`] describes an S2 endpoint. It is constructed through
//! a builder pattern. For simple configuration, the builder can immediately be build:
//! ```rust
//! # use s2energy_connection::pairing::EndpointConfig;
//! # use s2energy_connection::{MessageVersion, S2NodeDescription, S2NodeId, S2Role};
//! let _config = EndpointConfig::builder(S2NodeDescription {
//!     id: S2NodeId::try_from("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
//!     brand: String::from("super-reliable-corp"),
//!     logo_uri: None,
//!     type_: String::from("fancy"),
//!     model_name: String::from("the best"),
//!     user_defined_name: None,
//!     role: S2Role::Rm,
//! }, vec![MessageVersion("v1".into())])
//! .build()
//! .unwrap();
//! ```
//!
//! Additional information can be added through methods on the builder. For example, we can add a connection initiate url through:
//! ```rust
//! # use s2energy_connection::pairing::EndpointConfig;
//! # use s2energy_connection::{MessageVersion, S2NodeDescription, S2NodeId, S2Role};
//! let _config = EndpointConfig::builder(S2NodeDescription {
//!     id: S2NodeId::try_from("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
//!     brand: String::from("super-reliable-corp"),
//!     logo_uri: None,
//!     type_: String::from("fancy"),
//!     model_name: String::from("the best"),
//!     user_defined_name: None,
//!     role: S2Role::Rm,
//! }, vec![MessageVersion("v1".into())])
//! .with_connection_initiate_url("https://example.com/".into())
//! .build()
//! .unwrap();
//! ```
//!
//! # Client usage
//!
//! Given an endpoint configuration, a [`Client`] can be constructed which can be used to pair with a remote S2 node running a pairing
//! server. For this, you will also need to know the id of the node, and the URL on which its pairing server is reachable.
//! ```rust
//! # use std::sync::Arc;
//! # use s2energy_connection::pairing::{Client, ClientConfig, EndpointConfig, PairingRemote};
//! # use s2energy_connection::{Deployment, MessageVersion, S2NodeDescription, S2NodeId, S2Role};
//! # let config = EndpointConfig::builder(S2NodeDescription {
//! #     id: S2NodeId::new(),
//! #     brand: String::from("super-reliable-corp"),
//! #     logo_uri: None,
//! #     type_: String::from("fancy"),
//! #     model_name: String::from("the best"),
//! #     user_defined_name: None,
//! #     role: S2Role::Rm,
//! # }, vec![MessageVersion("v1".into())])
//! # .with_connection_initiate_url("https://example.com/".into())
//! # .build()
//! # .unwrap();
//!
//! let client = Client::new(Arc::new(config), ClientConfig {
//!     pairing_deployment: Deployment::Lan,
//!     additional_certificates: vec![],
//! }).unwrap();
//!
//! let pairing_result = client.pair(PairingRemote {
//!     url: "https://remote.example.com".into(),
//!     id: S2NodeId::try_from("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
//! }, b"ABCDEF0123456");
//! ```
//!
//! # Server usage
//!
//! We can also setup a server to act as the HTTP server in a pairing exchange. The server then provides a router which we need to serve. Setting this up can look something like
//! ```rust
//! # use std::{path::PathBuf, net::SocketAddr};
//! # use axum_server::tls_rustls::RustlsConfig;
//! # use s2energy_connection::pairing::{Server, ServerConfig};
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() {
//! # let tls_config = RustlsConfig::from_pem_file(
//! #     PathBuf::from(env!("CARGO_MANIFEST_DIR"))
//! #         .join("testdata")
//! #         .join("test.local.chain.pem"),
//! #     PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("test.local.key"),
//! # )
//! # .await
//! # .unwrap();
//! # let addr = SocketAddr::from(([127, 0, 0, 1], 8005));
//! let server = Server::new(ServerConfig {
//!     root_certificate: None,
//! });
//! tokio::spawn(async move {
//!     axum_server::bind_rustls(addr, tls_config)
//!         .serve(server.get_router().into_make_service())
//!         .await
//!         .unwrap();
//! });
//! # }
//! ```
//! After this setup, the server can be used to either start a single pairing session:
//! ```no_run
//! # use std::{path::PathBuf, net::SocketAddr, sync::Arc};
//! # use axum_server::tls_rustls::RustlsConfig;
//! # use s2energy_connection::pairing::{EndpointConfig, PairingToken, Server, ServerConfig};
//! # use s2energy_connection::{MessageVersion, S2NodeDescription, S2NodeId, S2Role};
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() {
//! # let tls_config = RustlsConfig::from_pem_file(
//! #     PathBuf::from(env!("CARGO_MANIFEST_DIR"))
//! #         .join("testdata")
//! #         .join("test.local.chain.pem"),
//! #     PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("test.local.key"),
//! # )
//! # .await
//! # .unwrap();
//! # let addr = SocketAddr::from(([127, 0, 0, 1], 8005));
//! # let server = Server::new(ServerConfig {
//! #     root_certificate: None,
//! # });
//! # let config = Arc::new(EndpointConfig::builder(S2NodeDescription {
//! #     id: S2NodeId::new(),
//! #     brand: String::from("super-reliable-corp"),
//! #     logo_uri: None,
//! #     type_: String::from("fancy"),
//! #     model_name: String::from("the best"),
//! #     user_defined_name: None,
//! #     role: S2Role::Rm,
//! # }, vec![MessageVersion("v1".into())])
//! # .with_connection_initiate_url("https://example.com/".into())
//! # .build()
//! # .unwrap());
//! let pairing_result = server.pair_once(config, PairingToken(b"ABCDEF0123456".as_slice().into())).unwrap().result().await;
//! # }
//! ```
//!
//! Or to enable repeated pairing using the same fixed pairing token:
//! ```no_run
//! # use std::{path::PathBuf, net::SocketAddr, sync::Arc};
//! # use axum_server::tls_rustls::RustlsConfig;
//! # use s2energy_connection::pairing::{EndpointConfig, PairingToken, Server, ServerConfig};
//! # use s2energy_connection::{MessageVersion, S2NodeDescription, S2NodeId, S2Role};
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() {
//! # let tls_config = RustlsConfig::from_pem_file(
//! #     PathBuf::from(env!("CARGO_MANIFEST_DIR"))
//! #         .join("testdata")
//! #         .join("test.local.chain.pem"),
//! #     PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("test.local.key"),
//! # )
//! # .await
//! # .unwrap();
//! # let addr = SocketAddr::from(([127, 0, 0, 1], 8005));
//! # let server = Server::new(ServerConfig {
//! #     root_certificate: None,
//! # });
//! # let config = Arc::new(EndpointConfig::builder(S2NodeDescription {
//! #     id: S2NodeId::new(),
//! #     brand: String::from("super-reliable-corp"),
//! #     logo_uri: None,
//! #     type_: String::from("fancy"),
//! #     model_name: String::from("the best"),
//! #     user_defined_name: None,
//! #     role: S2Role::Rm,
//! # }, vec![MessageVersion("v1".into())])
//! # .with_connection_initiate_url("https://example.com/".into())
//! # .build()
//! # .unwrap());
//! let mut pairing_results = server.pair_repeated(config, PairingToken(b"ABCDEF0123456".as_slice().into())).unwrap();
//! while let Some(pairing_result) = pairing_results.next().await {
//!     /* do something with the pairing result */
//! }
//! # }
//! ```
//!
//! # Example applications
//!
//! A complete example of a pairing client and pairing server are present in the examples folder. These demonstrate also more completely
//! how a simple server setup can be done using the [`axum-server`](https://docs.rs/axum-server/0.8.0/axum_server/) crate.
#![warn(clippy::clone_on_copy)]
mod client;
mod server;
mod transport;
mod wire;

use rand::Rng;

use wire::{HmacChallenge, HmacChallengeResponse};

pub use client::{Client, ClientConfig, PairingRemote};
pub use server::{PairingToken, PendingPairing, RepeatedPairing, Server, ServerConfig};

use crate::{
    CommunicationProtocol, Deployment, MessageVersion, S2EndpointDescription, S2NodeDescription, S2Role,
    common::{BaseError, wire::AccessToken},
};

/// Full description of an S2 endpoint
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    node_description: S2NodeDescription,
    endpoint_description: S2EndpointDescription,
    supported_message_versions: Vec<MessageVersion>,
    supported_communication_protocols: Vec<CommunicationProtocol>,
    connection_initiate_url: Option<String>,
}

impl EndpointConfig {
    /// Description of the S2 node.
    pub fn node_description(&self) -> &S2NodeDescription {
        &self.node_description
    }

    /// Description of the actual endpoint of the node.
    pub fn endpoint_description(&self) -> &S2EndpointDescription {
        &self.endpoint_description
    }

    /// Message versions supported by this endpoint.
    pub fn supported_message_versions(&self) -> &[MessageVersion] {
        &self.supported_message_versions
    }

    /// Communication protocols supported by this endpoint
    pub fn supported_communication_protocols(&self) -> &[CommunicationProtocol] {
        &self.supported_communication_protocols
    }

    /// Connection initiate url used for this endpoint, if configured.
    pub fn connection_initiate_url(&self) -> Option<&str> {
        self.connection_initiate_url.as_deref()
    }

    /// Create a builder for a new [`EndpointConfig`]
    ///
    /// All endpoint configurations must at least contain description of the node and supported message versions. Additional
    /// properties can be configured through the builder.
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

/// Builder for an [`EndpointConfig`]
pub struct ConfigBuilder {
    node_description: S2NodeDescription,
    endpoint_description: S2EndpointDescription,
    supported_message_versions: Vec<MessageVersion>,
    supported_communication_protocols: Vec<CommunicationProtocol>,
    connection_initiate_url: Option<String>,
}

impl ConfigBuilder {
    /// Set a url for initiating new connections.
    ///
    /// By default, this URL is not present. It is however required for CEM endpoints, or RM endpoints with a WAN deployment.
    pub fn with_connection_initiate_url(mut self, connection_initiate_url: String) -> Self {
        self.connection_initiate_url = Some(connection_initiate_url);
        self
    }

    /// Set the communication protocols supported by
    pub fn with_supported_communication_protocols(mut self, communication_protocols: Vec<CommunicationProtocol>) -> Self {
        self.supported_communication_protocols = communication_protocols;
        self
    }

    /// Set the endpoint description explicitly.
    ///
    /// By default, all fields in the endpoint description are unset. Note that this replaces any previous endpoint descriptions passed.
    pub fn with_endpoint_description(mut self, endpoint_description: S2EndpointDescription) -> Self {
        self.endpoint_description = endpoint_description;
        self
    }

    /// Create the actual [`EndpointConfig`], validating that it is reasonable.
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

/// Error for problems with inconsistent [`EndpointConfig`]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The [`EndpointConfig`] doesn't have an `connection_initiate_url` even though it is needed for the configuration to make sense.
    MissingInitiateUrl,
}

/// Role for the communication protocol assigned to the node in the pairing process
pub enum PairingRole {
    /// This node must initiate the connection protocol.
    CommunicationClient {
        /// URL to be used for initiating the connection.
        initiate_url: String,
    },
    /// This node gets contacted by the other node to initiate a connection.
    CommunicationServer,
}

/// The result of a pairing operation
///
/// Describes the remote endpoint, and how communication between the nodes will happen.
pub struct Pairing {
    /// Description of the remote S2 Node.
    pub remote_node_description: S2NodeDescription,
    /// Description of the remote S2 Endpoint.
    pub remote_endpoint_description: S2EndpointDescription,
    /// Token used during communication setup.
    pub token: AccessToken,
    /// Role this node has for initiating communication.
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

/// Error that occured during the pairing process.
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
    /// Session timed out.
    Timeout,
    /// Already a pending pairing session with that node id.
    AlreadyPending,
    /// Provided token was invalid.
    InvalidToken,
    /// The pairing session was cancelled.
    Cancelled,
    /// The remote is of the same type
    RemoteOfSameType,
    /// The configuration was invalid
    InvalidConfig(ConfigError),
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

impl From<ConfigError> for Error {
    fn from(value: ConfigError) -> Self {
        Self::InvalidConfig(value)
    }
}

/// Convenience type for [`Result<T, Error>`]
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
