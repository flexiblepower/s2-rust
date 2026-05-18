//! A combined communication and pairing server.
//!
//! This provides a convenient combined server for pairing and communication.
//! An complete example on how to use this can be found in the examples folder.

use std::sync::Arc;

use axum::{Router, routing::get};
use rustls::pki_types::CertificateDer;

use crate::{
    CommunicationProtocol, EndpointDescription, MessageVersion, NodeDescription, NodeId,
    common::root,
    communication::{self, ConnectionInfo, PairingLookup, ServerPairingStore},
    error::{Error, ErrorKind},
    pairing::{self, LongpollingHandle, NodeIdAlias, NoopPrePairingHandler, Pairing, PairingToken, PrePairingHandler},
};

/// Extensions to the pairing store for combined servers
pub trait CombinedServerPairingStore: ServerPairingStore {
    /// Store the result of a newly negotiated pairing, replacing an existing pairing if present.
    fn store(&self, local_node: NodeId, pairing: Pairing) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Certificate
pub struct ServerCertificates {
    /// Leaf certificate
    pub leaf_certificate: CertificateDer<'static>,
    /// Root certificate
    pub root_certificate: CertificateDer<'static>,
}

/// Configuration for a combined pairing and communication S2 server.
pub struct ServerConfig {
    /// URL at which the server is reachable.
    pub base_url: String,
    /// The leaf and root certificates of the server, if we are using a self-signed root.
    /// Must be present if this is a LAN-deployed endpoint.
    pub certificates: Option<ServerCertificates>,
    /// Endpoint description of the server
    pub endpoint_description: EndpointDescription,
    /// Initial set of nodes to advertise. This is only used if the server
    /// is deployed on LAN.
    pub advertised_nodes: Vec<NodeDescription>,
}

/// Combined pairing and communication server
pub struct Server<H, Store> {
    pairing: pairing::Server<H>,
    communication: communication::Server<Store>,
    base_url: String,
    root_certificate: Option<CertificateDer<'static>>,
}

impl<H, Store> Clone for Server<H, Store> {
    fn clone(&self) -> Self {
        Self {
            pairing: self.pairing.clone(),
            communication: self.communication.clone(),
            base_url: self.base_url.clone(),
            root_certificate: self.root_certificate.clone(),
        }
    }
}

impl<Store: CombinedServerPairingStore> Server<NoopPrePairingHandler, Store> {
    /// Create a new combined pairing/communication server.
    pub fn new(server_config: ServerConfig, store: Store) -> Result<Self, Error> {
        Self::new_with_prepairing(server_config, NoopPrePairingHandler, store)
    }
}

/// Either a longpolling session or a connection to the server.
pub enum Session {
    /// A longpolling connection
    Longpolling(LongpollingHandle),
    /// A new S2 transport connection
    Connection(PairingLookup, ConnectionInfo),
}

impl<H: PrePairingHandler, Store: CombinedServerPairingStore> Server<H, Store> {
    /// Create a new combined pairing/communication server with custom pre-pairing handling.
    pub fn new_with_prepairing(server_config: ServerConfig, handler: H, store: Store) -> Result<Self, Error> {
        if server_config.endpoint_description.deployment == Some(crate::Deployment::Lan) && server_config.certificates.is_none() {
            return Err(ErrorKind::InvalidServerConfig.into());
        }
        let (leaf_certificate, root_certificate) = match server_config.certificates {
            Some(certificates) => (Some(certificates.leaf_certificate), Some(certificates.root_certificate)),
            None => (None, None),
        };
        Ok(Self {
            pairing: pairing::Server::new_with_prepairing(
                pairing::ServerConfig {
                    leaf_certificate,
                    endpoint_description: server_config.endpoint_description.clone(),
                    advertised_nodes: server_config.advertised_nodes,
                },
                handler,
            ),
            communication: communication::Server::new(
                communication::ServerConfig {
                    base_url: server_config.base_url.clone(),
                    endpoint_description: Some(server_config.endpoint_description),
                },
                store,
            ),
            base_url: format!("https://{}", server_config.base_url),
            root_certificate,
        })
    }

    /// Get an [`axum::Router`] handling the endpoints for the s2 connect protocol.
    ///
    /// Incomming http requests can be handled by this router through the [axum-server](https://docs.rs/axum-server/0.8.0/axum_server/) crate.
    pub fn get_router(&self) -> axum::Router<()> {
        Router::new().route("/", get(root)).nest(
            "/v1",
            self.communication.get_internal_router().merge(self.pairing.get_internal_router()),
        )
    }

    /// Update the nodes advertised by this server.
    ///
    /// These are only used when the server is on a LAN.
    pub fn update_advertised_nodes(&self, advertised_nodes: Vec<NodeDescription>) {
        self.pairing.update_advertised_nodes(advertised_nodes);
    }

    /// Enable longpolling
    pub async fn enable_longpolling(&self) {
        self.pairing.enable_longpolling().await;
    }

    /// Disable longpolling
    pub async fn disable_longpolling(&self) {
        self.pairing.disable_longpolling().await;
    }

    /// Get a pending longpolling handle.
    pub async fn get_longpolling(&self) -> LongpollingHandle {
        self.pairing.get_longpolling().await
    }

    /// Start a one-time pairing session for the given node using the given token.
    ///
    /// The callback will receive the result of the pairing attempt. If the server
    /// S2 node also becomes server for the communication, it must ensure it is
    /// ready to handle the communication requests before returning Ok(()) from
    /// the callback.
    pub fn allow_pair_once<F: Future<Output = ()> + Send>(
        &self,
        node_description: NodeDescription,
        message_versions: Vec<MessageVersion>,
        pairing_node_id: Option<NodeIdAlias>,
        pairing_token: PairingToken,
        completion_handler: impl (FnOnce(Result<(), Error>) -> F) + Send + 'static,
    ) -> Result<(), Error> {
        let local_node = node_description.id;

        let config = pairing::NodeConfig {
            node_description,
            supported_message_versions: message_versions,
            supported_communication_protocols: vec![CommunicationProtocol("WebSocket".into())],
            connection_initiate_url: Some(self.base_url.clone()),
            root_certificate: self.root_certificate.clone(),
        };

        let store = self.communication.store();
        Ok(self.pairing.allow_pair_once(
            Arc::new(config),
            pairing_node_id,
            pairing_token,
            async move |pairing_result| match pairing_result {
                Ok(pairing) => match store.store(local_node, pairing).await {
                    Ok(_) => {
                        completion_handler(Ok(())).await;
                        Ok(())
                    }
                    Err(error) => {
                        completion_handler(Err(ErrorKind::Storage.into())).await;
                        Err(error)
                    }
                },
                Err(error) => {
                    completion_handler(Err(error.into())).await;
                    Ok(())
                }
            },
        )?)
    }

    /// Allow repeated pairing sessions for the given endpoing using the given token.
    ///
    /// The callback will receive the result of the pairing attempt. If the server
    /// S2 node also becomes server for the communication, it must ensure it is
    /// ready to handle the communication requests before returning Ok(()) from
    /// the callback.
    pub fn allow_pair_repeated(
        &self,
        node_description: NodeDescription,
        message_versions: Vec<MessageVersion>,
        pairing_node_id: Option<NodeIdAlias>,
        pairing_token: PairingToken,
    ) -> Result<(), Error> {
        let local_node = node_description.id;

        let config = pairing::NodeConfig {
            node_description,
            supported_message_versions: message_versions,
            supported_communication_protocols: vec![CommunicationProtocol("WebSocket".into())],
            connection_initiate_url: Some(self.base_url.clone()),
            root_certificate: self.root_certificate.clone(),
        };

        let store = self.communication.store();
        Ok(self
            .pairing
            .allow_pair_repeated(Arc::new(config), pairing_node_id, pairing_token, move |pairing_result| {
                let store = store.clone();
                async move {
                    if let Ok(pairing) = pairing_result {
                        store.store(local_node, pairing).await
                    } else {
                        Ok(())
                    }
                }
            })?)
    }

    /// Get the next connection which has been established with the server.
    pub async fn next_connection(&self) -> (PairingLookup, ConnectionInfo) {
        self.communication.next_connection().await
    }
}
