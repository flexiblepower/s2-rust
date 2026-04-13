//! Implementation of the communication subprotocol of S2 Pairing.
//!
//! This module provides client and server implementations of the [S2 Communication subprotocol](https://docs.s2standard.org/docs/communication-layer/discovery-pairing-authentication/#s2-connections)
//!
//! # Node configuration
//!
//! The main configuration struct [`NodeConfig`] describes an S2 node. It is constructed through
//! a builder pattern. For simple configuration, the builder can immediately be build:
//! ```rust
//! # use s2energy_connection::communication::NodeConfig;
//! # use s2energy_connection::MessageVersion;
//! let _config = NodeConfig::builder(vec![MessageVersion("v1".into())]).build();
//! ```
//!
//! Additional information, such as a new node description to provide during the setting
//! up of communication, can be added through methods on the builder:
//! ```rust
//! # use s2energy_connection::communication::NodeConfig;
//! # use s2energy_connection::{MessageVersion, NodeDescription, NodeId, Role};
//! let _config = NodeConfig::builder(vec![MessageVersion("v1".into())])
//! .with_node_description(NodeDescription {
//!     id: NodeId::try_from("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
//!     brand: String::from("super-reliable-corp"),
//!     logo_url: None,
//!     type_: String::from("fancy"),
//!     model_name: String::from("the best"),
//!     user_defined_name: None,
//!     role: Role::Rm,
//! }).build();
//! ```
//!
//! # Pairing descriptions
//!
//! The communication protocol needs to update the access tokens for a pairing during the
//! main interaction between client and server. To facilitate this without forcing a
//! specific implementation for the storage of access tokens, this crate uses traits to
//! describe the pairings used by client and server.
//!
//! # Client usage
//!
//! The [`Client`] can be used to establish a communication sessions for which the local
//! software is the communication initiator:
//! ```rust
//! # use std::sync::Arc;
//! # use std::convert::Infallible;
//! # use s2energy_connection::communication::{NodeConfig, Client, ClientConfig, ClientPairing};
//! # use s2energy_connection::{MessageVersion, AccessToken, NodeId, CertificateHash};
//! struct MemoryClientPairing {
//!     client_id: NodeId,
//!     server_id: NodeId,
//!     communication_url: String,
//!     access_tokens: Vec<AccessToken>,
//!     certificate_hash: Option<CertificateHash>,
//! }
//!
//! impl ClientPairing for MemoryClientPairing {
//!     type Error = Infallible;
//!     
//!     fn client_id(&self) -> NodeId {
//!         self.client_id
//!     }
//!
//!     fn server_id(&self) -> NodeId {
//!         self.server_id
//!     }
//!
//!     fn communication_url(&self) -> impl AsRef<str> {
//!         &self.communication_url
//!     }
//!
//!     fn access_tokens(&self) -> impl AsRef<[AccessToken]> {
//!         &self.access_tokens
//!     }
//!
//!     fn certificate_hash(&self) -> Option<CertificateHash> {
//!         self.certificate_hash.clone()
//!     }
//!
//!     async fn set_access_tokens(&mut self, tokens: Vec<AccessToken>) -> Result<(), Infallible> {
//!         self.access_tokens = tokens;
//!         Ok(())
//!     }
//! }
//!
//! let config = NodeConfig::builder(vec![MessageVersion("v1".into())]).build();
//! let client = Client::new(ClientConfig::default(), Arc::new(config));
//! let connection_result = client.connect(MemoryClientPairing {
//!     client_id: NodeId::try_from("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap(),
//!     server_id: NodeId::try_from("67e55044-10b1-426f-9247-bb680e5fe0c6").unwrap(),
//!     communication_url: "https://example.com".into(),
//!     access_tokens: vec![AccessToken("some-token-value".into())],
//!     certificate_hash: None,
//! });
//! ```
//!
//! The resulting [`ConnectionInfo`] provides the negotiated connection. It also contains the
//! negotiated protocol version, as well as any updates to node and endpoint descriptions
//! received during the session.
//!
//! # Server usage
//!
//! The [`Server`] provides the passive end of communication establishment. It provides an
//! axum router which needs to be served to allow paired clients to establish a connection.
//! Setting up a server and the serving of these endpoints can be done as follows:
//! ```rust
//! # use std::{path::PathBuf, net::SocketAddr, convert::Infallible};
//! # use axum_server::tls_rustls::RustlsConfig;
//! # use s2energy_connection::communication::{NodeConfig, Server, ServerConfig, ServerPairingStore, ServerPairing, PairingLookup, PairingLookupResult};
//! # use s2energy_connection::AccessToken;
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
//! # struct SomeStorageProvider;
//! # struct SomeServerPairing;
//! # impl ServerPairing for SomeServerPairing {
//! #     type Error = Infallible;
//! #     fn access_token(&self) -> impl AsRef<AccessToken> {
//! #         unimplemented!() as &AccessToken
//! #     }
//! #     fn config(&self) -> impl AsRef<NodeConfig> {
//! #         unimplemented!() as &NodeConfig
//! #     }
//! #     async fn set_access_token(&mut self, token: AccessToken) -> Result<(), Self::Error> {
//! #         unimplemented!()
//! #     }
//! #     async fn unpair(self) -> Result<(), Self::Error> {
//! #         unimplemented!()
//! #     }
//! # }
//! # impl ServerPairingStore for SomeStorageProvider {
//! #     type Error = Infallible;
//! #     type Pairing<'a> = SomeServerPairing;
//! #     async fn lookup(&self, request: PairingLookup) -> Result<PairingLookupResult<Self::Pairing<'_>>, Self::Error> {
//! #         unimplemented!()
//! #     }
//! # }
//! let server = Server::new(ServerConfig {
//!     base_url: "https://example.com/".into(),
//!     endpoint_description: None,
//! }, SomeStorageProvider);
//! tokio::spawn(async move {
//!     axum_server::bind_rustls(addr, tls_config)
//!         .serve(server.get_router().into_make_service())
//!         .await
//!         .unwrap();
//! });
//! # }
//! ```
//!
//! Once the server is setup, the connections it established can be accessed through calls to
//! [`Server::next_connection`]:
//! ```no_run
//! # use std::{path::PathBuf, net::SocketAddr, convert::Infallible};
//! # use axum_server::tls_rustls::RustlsConfig;
//! # use s2energy_connection::communication::{NodeConfig, Server, ServerConfig, ServerPairingStore, ServerPairing, PairingLookup, PairingLookupResult};
//! # use s2energy_connection::AccessToken;
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
//! # struct SomeStorageProvider;
//! # struct SomeServerPairing;
//! # impl ServerPairing for SomeServerPairing {
//! #     type Error = Infallible;
//! #     fn access_token(&self) -> impl AsRef<AccessToken> {
//! #         unimplemented!() as &AccessToken
//! #     }
//! #     fn config(&self) -> impl AsRef<NodeConfig> {
//! #         unimplemented!() as &NodeConfig
//! #     }
//! #     async fn set_access_token(&mut self, token: AccessToken) -> Result<(), Self::Error> {
//! #         unimplemented!()
//! #     }
//! #     async fn unpair(self) -> Result<(), Self::Error> {
//! #         unimplemented!()
//! #     }
//! # }
//! # impl ServerPairingStore for SomeStorageProvider {
//! #     type Error = Infallible;
//! #     type Pairing<'a> = SomeServerPairing;
//! #     async fn lookup(&self, request: PairingLookup) -> Result<PairingLookupResult<Self::Pairing<'_>>, Self::Error> {
//! #         unimplemented!()
//! #     }
//! # }
//! # let mut server = Server::new(ServerConfig {
//! #     base_url: "https://example.com/".into(),
//! #     endpoint_description: None,
//! # }, SomeStorageProvider);
//! let (pairing, connection) = server.next_connection().await;
//! # }
//! ```
//! The call to [`Server::next_connection`] returns the node identifiers of the pairing the connection is for, as well as the same connection
//! information as provided by the client.
//!
//! # Example applications
//!
//! A complete example of a communication client and communication server are present in the examples folder. These demonstrate also more completely
//! how a simple server setup can be done using the [`axum-server`](https://docs.rs/axum-server/0.8.0/axum_server/) crate.
use crate::{EndpointDescription, MessageVersion, NodeDescription};

mod client;
mod error;
mod server;
mod transport;
mod websocket;
pub(crate) mod wire;

pub use client::{Client, ClientConfig, ClientPairing};
pub(crate) use error::WrappedError;
pub use error::{Error, ErrorKind};
pub use server::{PairingLookup, PairingLookupResult, Server, ServerConfig, ServerPairing, ServerPairingStore};
pub use websocket::{WebSocketError, WebSocketTransport};

/// Full description of an S2 Node for communication.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    node_description: Option<NodeDescription>,
    supported_message_versions: Vec<MessageVersion>,
}

impl NodeConfig {
    /// Description of the S2 node.
    pub fn node_description(&self) -> Option<&NodeDescription> {
        self.node_description.as_ref()
    }

    /// Message versions supported by this node.
    pub fn supported_message_versions(&self) -> &[MessageVersion] {
        &self.supported_message_versions
    }

    /// Create a builder for a new [`NodeConfig`].
    ///
    /// All node configurations must at least contain description of the node and supported message versions. Additional
    /// properties can be configured through the builder.
    pub fn builder(supported_message_versions: Vec<MessageVersion>) -> ConfigBuilder {
        ConfigBuilder {
            node_description: None,
            supported_message_versions,
        }
    }
}

impl AsRef<NodeConfig> for NodeConfig {
    fn as_ref(&self) -> &NodeConfig {
        self
    }
}

/// Builder for a [`NodeConfig`].
pub struct ConfigBuilder {
    node_description: Option<NodeDescription>,
    supported_message_versions: Vec<MessageVersion>,
}

impl ConfigBuilder {
    /// Set the node description.
    ///
    /// Note that this replaces any previous node decriptions passed.
    pub fn with_node_description(mut self, node_description: NodeDescription) -> Self {
        self.node_description = Some(node_description);
        self
    }

    /// Create the actual [`NodeConfig`], validating that it is reasonable.
    pub fn build(self) -> NodeConfig {
        NodeConfig {
            node_description: self.node_description,
            supported_message_versions: self.supported_message_versions,
        }
    }
}

/// Convenience type for [`Result<T, Error>`].
pub type CommunicationResult<T> = Result<T, Error>;

/// Information on a newly established connection.
#[derive(Debug)]
pub struct ConnectionInfo {
    /// New description of the remote node received during establishing of this connection.
    pub remote_node_description: Option<NodeDescription>,
    /// New description of the remote endpoint received during establishing of this connection.
    pub remote_endpoint_description: Option<EndpointDescription>,
    /// The version of the S2 Messages negotiated for this connection.
    pub message_version: MessageVersion,

    /// The actual transport of the connection.
    pub transport: WebSocketTransport,
}
