//! Pairing logic for the S2 protocols.
//!
//! This module provides client and server implementations of the [S2 pairing protocol](https://docs.s2standard.org/docs/communication-layer/discovery-pairing-authentication/#the-pairing-process)
//!
//! # Node configuration
//!
//! The main configuration struct [`NodeConfig`] describes an S2 node. It is constructed through
//! a builder pattern. For simple configuration, the builder can immediately be build:
//! ```rust
//! # use s2energy_connection::pairing::NodeConfig;
//! # use s2energy_connection::{MessageVersion, S2NodeDescription, S2NodeId, S2Role};
//! let _config = NodeConfig::builder(S2NodeDescription {
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
//! # use s2energy_connection::pairing::NodeConfig;
//! # use s2energy_connection::{MessageVersion, S2NodeDescription, S2NodeId, S2Role};
//! let _config = NodeConfig::builder(S2NodeDescription {
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
//! Given a node configuration, a [`Client`] can be constructed which can be used to pair with a remote S2 node running a pairing
//! server. For this, you will also need to know the id of the node, and the URL on which its pairing server is reachable.
//! ```rust
//! # use std::sync::Arc;
//! # use s2energy_connection::pairing::{Client, ClientConfig, NodeConfig, PairingRemote, PairingS2NodeId};
//! # use s2energy_connection::{Deployment, MessageVersion, S2NodeDescription, S2NodeId, S2Role};
//! # let config = NodeConfig::builder(S2NodeDescription {
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
//!     id: PairingS2NodeId("test_pairing_id".into()),
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
//! # use s2energy_connection::S2EndpointDescription;
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
//!     advertised_endpoint: S2EndpointDescription::default(),
//!     advertised_nodes: vec![],
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
//! # use s2energy_connection::pairing::{NodeConfig, PairingToken, Server, ServerConfig, PairingS2NodeId};
//! # use s2energy_connection::{MessageVersion, S2NodeDescription, S2EndpointDescription, S2NodeId, S2Role};
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
//! #     advertised_endpoint: S2EndpointDescription::default(),
//! #     advertised_nodes: vec![],
//! # });
//! # let config = Arc::new(NodeConfig::builder(S2NodeDescription {
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
//! let pairing_result = server.pair_once(config, PairingS2NodeId("XYZ".into()), PairingToken(b"ABCDEF0123456".as_slice().into())).unwrap().result().await;
//! # }
//! ```
//!
//! Or to enable repeated pairing using the same fixed pairing token:
//! ```no_run
//! # use std::{path::PathBuf, net::SocketAddr, sync::Arc};
//! # use axum_server::tls_rustls::RustlsConfig;
//! # use s2energy_connection::pairing::{NodeConfig, PairingToken, Server, ServerConfig, PairingS2NodeId};
//! # use s2energy_connection::{MessageVersion, S2NodeDescription, S2EndpointDescription, S2NodeId, S2Role};
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
//! #     advertised_endpoint: S2EndpointDescription::default(),
//! #     advertised_nodes: vec![],
//! # });
//! # let config = Arc::new(NodeConfig::builder(S2NodeDescription {
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
//! let mut pairing_results = server.pair_repeated(config, PairingS2NodeId("XYZ".into()), PairingToken(b"ABCDEF0123456".as_slice().into())).unwrap();
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
mod error;
mod server;
mod transport;
mod wire;

use rand::CryptoRng;

use wire::{HmacChallenge, HmacChallengeResponse};

pub use client::{Client, ClientConfig, PairingRemote};
pub use error::{ConfigError, Error, ErrorKind};
pub use server::{
    NoopPrePairingHandler, PairingToken, PairingTokenError, PendingPairing, PrePairingHandler, PrePairingResponse, RepeatedPairing, Server,
    ServerConfig,
};
pub use wire::PairingS2NodeId;

use crate::{
    CommunicationProtocol, Deployment, MessageVersion, S2EndpointDescription, S2NodeDescription, S2Role, common::wire::AccessToken,
};

/// Full description of an S2 node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    node_description: S2NodeDescription,
    endpoint_description: S2EndpointDescription,
    supported_message_versions: Vec<MessageVersion>,
    supported_communication_protocols: Vec<CommunicationProtocol>,
    connection_initiate_url: Option<String>,
}

impl NodeConfig {
    /// Description of the S2 node.
    pub fn node_description(&self) -> &S2NodeDescription {
        &self.node_description
    }

    /// Description of the endpoint hosting the node.
    pub fn endpoint_description(&self) -> &S2EndpointDescription {
        &self.endpoint_description
    }

    /// Message versions supported by this node.
    pub fn supported_message_versions(&self) -> &[MessageVersion] {
        &self.supported_message_versions
    }

    /// Communication protocols supported by this node.
    pub fn supported_communication_protocols(&self) -> &[CommunicationProtocol] {
        &self.supported_communication_protocols
    }

    /// Connection initiate url used for this node, if configured.
    pub fn connection_initiate_url(&self) -> Option<&str> {
        self.connection_initiate_url.as_deref()
    }

    /// Create a builder for a new [`NodeConfig`].
    ///
    /// All node configurations must at least contain description of the node and supported message versions. Additional
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

/// Builder for an [`NodeConfig`].
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
    /// By default, this URL is not present. It is however required for CEM nodes, or RM nodes with a WAN deployment.
    pub fn with_connection_initiate_url(mut self, connection_initiate_url: String) -> Self {
        self.connection_initiate_url = Some(connection_initiate_url);
        self
    }

    /// Set the communication protocols supported by this node.
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

    /// Create the actual [`NodeConfig`], validating that it is reasonable.
    pub fn build(self) -> Result<NodeConfig, ConfigError> {
        if (self.node_description.role == S2Role::Cem || self.endpoint_description.deployment == Some(Deployment::Wan))
            && self.connection_initiate_url.is_none()
        {
            return Err(ConfigError::MissingInitiateUrl);
        }
        Ok(NodeConfig {
            node_description: self.node_description,
            endpoint_description: self.endpoint_description,
            supported_message_versions: self.supported_message_versions,
            supported_communication_protocols: self.supported_communication_protocols,
            connection_initiate_url: self.connection_initiate_url,
        })
    }
}

/// Role for the communication protocol assigned to the node in the pairing process.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PairingRole {
    /// This node must initiate the connection protocol.
    CommunicationClient {
        /// URL to be used for initiating the connection.
        initiate_url: String,
    },
    /// This node gets contacted by the other node to initiate a connection.
    CommunicationServer,
}

/// The result of a pairing operation.
///
/// Describes the remote node, and how communication between the nodes will happen.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pairing {
    /// Description of the remote S2 Node.
    pub remote_node_description: S2NodeDescription,
    /// Description of the remote S2 Endpoint hosting the node.
    pub remote_endpoint_description: S2EndpointDescription,
    /// Token used during communication setup.
    pub token: AccessToken,
    /// Role this node has for initiating communication.
    pub role: PairingRole,
}

impl HmacChallenge {
    pub fn new(rng: &mut impl CryptoRng, len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
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

        HmacChallengeResponse(mac.finalize().into_bytes().to_vec())
    }
}

/// Convenience type for [`Result<T, Error>`].
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

    fn is_lan(&self) -> bool {
        matches!(self, Network::Lan { .. })
    }
}
