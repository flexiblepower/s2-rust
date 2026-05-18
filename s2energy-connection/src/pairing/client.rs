use std::sync::Arc;

use reqwest::{StatusCode, Url};
use rustls::pki_types::CertificateDer;
use tracing::{Instrument, Span, debug, span, trace};

use crate::common::negotiate_version;
use crate::common::wire::{AccessToken, Deployment, PairingVersion, Role};
use crate::pairing::transport::{HashProvider, hash_providing_https_client};
use crate::pairing::{ConfigError, Error, Pairing, PairingRole};
use crate::{CertificateHash, EndpointDescription, NodeDescription, NodeId};

use super::NodeConfig;
use super::wire::*;
use super::{ErrorKind, Network, PairingResult};

/// Optional node identifier of a remote node
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RemoteNodeIdentifier {
    /// A full UUID node identifier
    Id(NodeId),
    /// A human-entered alias for an S2 Node
    Alias(NodeIdAlias),
    /// No identifier
    None,
}

/// Remote node to pair with.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PairingRemote {
    /// URL at which the remote node can be reached
    pub url: String,
    /// S2 node id of the remote node.
    pub id: RemoteNodeIdentifier,
}

/// Remote node to pair with.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrePairingRemote {
    /// URL at which the remote node can be reached
    pub url: String,
    /// S2 node id of the remote node.
    pub id: NodeId,
}

/// Configuration for pairing clients.
pub struct ClientConfig {
    /// Additional roots of trust for TLS connections. Useful when testing during the development of WAN endpoints.
    ///
    /// When the remote is on the LAN, this is not used.
    pub additional_certificates: Vec<CertificateDer<'static>>,
    /// Description of our endpoint.
    pub endpoint_description: EndpointDescription,
    /// Where the pairing is deployed.
    pub pairing_deployment: Deployment,
}

/// Client for S2 pairing transactions.
///
/// Used as the client end of a pairing interaction.
pub struct Client {
    endpoint_description: EndpointDescription,
    additional_certificates: Vec<CertificateDer<'static>>,
    pairing_deployment: Deployment,
}

/// A currently active pre-pairing session with a remote.
pub struct PrePairing<'a> {
    span: tracing::Span,
    remote_id: NodeId,
    session: V1Session<'a>,
    local_deployment: Deployment,
    certhash: Option<HashProvider>,
}

impl PrePairing<'_> {
    /// Indicate to the remote that we will not move towards actually pairing.
    pub async fn cancel(self) -> PairingResult<()> {
        self.session
            .client
            .post(self.session.base_url.join("cancelPreparePairing").unwrap())
            .json(&CancelPrePairingRequest {
                client_id: self.session.config.node_description.id,
                server_id: Some(self.remote_id),
            })
            .send()
            .instrument(self.span)
            .await
            .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;
        Ok(())
    }

    /// Actually pair with the remote using the given information.
    ///
    /// The callback will receive the result of the pairing attempt. If the client
    /// S2 node becomes server for the communication, it must ensure it is ready to
    /// handle the communication requests before returning Ok(()) from the callback.
    ///
    /// When the callback returns an error, the client will be notified of the error.
    pub async fn pair<E: std::error::Error + Send + 'static>(
        self,
        pairing_token: &[u8],
        callback: impl AsyncFnOnce(Pairing) -> Result<(), E>,
    ) -> PairingResult<()> {
        async move {
            trace!("Start pairing after pre-pairing.");
            self.session
                .pair(
                    self.certhash,
                    self.local_deployment,
                    RemoteNodeIdentifier::Id(self.remote_id),
                    pairing_token,
                    callback,
                )
                .await
        }
        .instrument(self.span)
        .await
    }
}

/// A handler for longpolling to a specific remote endpoint, from our local endpoint.
#[derive(Clone)]
pub struct Longpoller(Arc<LongpollerInner>);

struct LongpollerInner {
    span: Span,
    nodes: std::sync::Mutex<Vec<NodeConfig>>,
    endpoint_description: EndpointDescription,
    // Client is held by the runner longterm, hence we use a tokio mutex.
    client: tokio::sync::Mutex<reqwest::Client>,
    base_url: Url,
}

/// Handler for requests received during longpolling.
pub trait LongpollHandler {
    /// Remote requests pairing
    ///
    /// Return value indicates whether we are able to start pairing with the remote.
    fn request_pairing(&mut self, node: NodeId) -> impl Future<Output = bool> + Send;
    /// Remote requests us to prepare for pairing.
    fn prepare_pairing(&mut self, node: NodeId) -> impl Future<Output = ()> + Send;
    /// Remote cancels a previous request to prepare for pairing.
    fn cancel_prepare_pairing(&mut self, node: NodeId) -> impl Future<Output = ()> + Send;
}

impl Longpoller {
    /// Do longpolling for the current set of nodes.
    ///
    /// Returns succesfully once there are no longer any nodes to longpoll for.
    ///
    /// The longpoller should not be reused when this returns an error.
    pub async fn run(&self, handler: &mut impl LongpollHandler) -> PairingResult<()> {
        async move {
            let client = self.0.client.lock().await;

            #[derive(Clone, Copy, PartialEq, Eq)]
            enum Action {
                None,
                ProvideDescription(NodeId),
                ReturnError(NodeId, WaitForPairingErrorMessage),
            }

            let mut action = Action::None;
            loop {
                let request: Vec<_> = self
                    .0
                    .nodes
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|node| match action {
                        Action::ProvideDescription(id) if id == node.node_description.id => WaitForPairingRequest {
                            client_node_id: node.node_description.id,
                            clien_node_description: Some(node.node_description.clone()),
                            client_endpoint_description: Some(self.0.endpoint_description.clone()),
                            error_message: None,
                        },
                        Action::ReturnError(id, error_message) if id == node.node_description.id => WaitForPairingRequest {
                            client_node_id: node.node_description.id,
                            clien_node_description: None,
                            client_endpoint_description: None,
                            error_message: Some(error_message),
                        },
                        _ => WaitForPairingRequest {
                            client_node_id: node.node_description.id,
                            clien_node_description: None,
                            client_endpoint_description: None,
                            error_message: None,
                        },
                    })
                    .collect();

                action = Action::None;

                if request.is_empty() {
                    return Ok(());
                }

                let response = client
                    .post(self.0.base_url.join("waitForPairing").unwrap())
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;
                if response.status() == StatusCode::BAD_REQUEST {
                    return Err(ErrorKind::Cancelled.into());
                }
                if response.status() == StatusCode::UNAUTHORIZED {
                    return Err(ErrorKind::Rejected.into());
                }
                if response.status() == StatusCode::NO_CONTENT {
                    continue;
                }

                let response: WaitForPairingResponse = response.json().await.map_err(|e| Error::new(ErrorKind::ProtocolError, e))?;
                match response.action {
                    WaitForPairingAction::SendNodeDescription => action = Action::ProvideDescription(response.client_node_id),
                    WaitForPairingAction::PreparePairing => handler.prepare_pairing(response.client_node_id).await,
                    WaitForPairingAction::CancelPreparePairing => handler.cancel_prepare_pairing(response.client_node_id).await,
                    WaitForPairingAction::RequestPairing => {
                        if !handler.request_pairing(response.client_node_id).await {
                            action = Action::ReturnError(response.client_node_id, WaitForPairingErrorMessage::NoValidTokenOnPairingClient)
                        }
                    }
                }
            }
        }
        .instrument(self.0.span.clone())
        .await
    }

    /// Start longpolling for the given local node.
    pub fn add_node(&self, new_node: NodeConfig) -> PairingResult<()> {
        let mut nodes = self.0.nodes.lock().unwrap();
        if nodes.iter().any(|node| node.node_description.id == new_node.node_description.id) {
            return Err(ErrorKind::AlreadyPending.into());
        }
        nodes.push(new_node);
        Ok(())
    }

    /// Stop longpolling for the local node with the given id.
    pub fn remove_node(&self, id: NodeId) {
        self.0.nodes.lock().unwrap().retain(|node| node.node_description.id != id);
    }
}

impl Client {
    /// Create a new client for pairing on an node with the given configuration.
    pub fn new(client_config: ClientConfig) -> PairingResult<Self> {
        Ok(Self {
            endpoint_description: client_config.endpoint_description,
            additional_certificates: client_config.additional_certificates,
            pairing_deployment: client_config.pairing_deployment,
        })
    }

    /// Get information about a specific endpoint and its nodes
    #[tracing::instrument(skip_all, fields(remote = ?remote), level = tracing::Level::ERROR)]
    pub async fn get_endpoint_descriptors(&self, remote: String) -> PairingResult<(EndpointDescription, Vec<NodeDescription>)> {
        trace!("Querying remote for descriptors");

        let url = Url::try_from(remote.as_str()).map_err(|e| Error::new(ErrorKind::InvalidUrl, e))?;

        let (client, _) = self.prepare_reqwest_client(&url)?;

        trace!("Prepared reqwest client.");

        let pairing_version = negotiate_version(&client, url.clone()).await?;

        match pairing_version {
            PairingVersion::V1 => {
                let base_url = url.join("v1/").unwrap();

                let endpoint_response = client
                    .get(base_url.join("endpoint").unwrap())
                    .send()
                    .await
                    .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;

                if endpoint_response.status() == StatusCode::UNAUTHORIZED {
                    return Err(ErrorKind::Rejected.into());
                }
                if endpoint_response.status() != StatusCode::OK {
                    return Err(ErrorKind::ProtocolError.into());
                }

                let endpoint: EndpointDescription = endpoint_response
                    .json()
                    .await
                    .map_err(|e| Error::new(ErrorKind::ProtocolError, e))?;

                let node_response = client
                    .get(base_url.join("nodes").unwrap())
                    .send()
                    .await
                    .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;

                if node_response.status() == StatusCode::UNAUTHORIZED {
                    return Err(ErrorKind::Rejected.into());
                }
                if node_response.status() != StatusCode::OK {
                    return Err(ErrorKind::ProtocolError.into());
                }

                let nodes: Vec<NodeDescription> = node_response.json().await.map_err(|e| Error::new(ErrorKind::ProtocolError, e))?;

                Ok((endpoint, nodes))
            }
        }
    }

    /// Create a longpoller for a given remote.
    pub async fn longpoller(&self, remote: String) -> PairingResult<Longpoller> {
        let span = span!(tracing::Level::ERROR, "longpolling", remote);
        let span_clone = span.clone();
        async move {
            trace!("Preparing long polling with remote");
            let url = Url::try_from(remote.as_str()).map_err(|e| Error::new(ErrorKind::InvalidUrl, e))?;

            let (client, _) = self.prepare_reqwest_client(&url)?;

            trace!("Prepared reqwest client.");

            let pairing_version = negotiate_version(&client, url.clone()).await?;

            match pairing_version {
                PairingVersion::V1 => Ok(Longpoller(Arc::new(LongpollerInner {
                    span,
                    endpoint_description: self.endpoint_description.clone(),
                    nodes: std::sync::Mutex::new(vec![]),
                    client: tokio::sync::Mutex::new(client),
                    base_url: url.join("v1/").unwrap(),
                }))),
            }
        }
        .instrument(span_clone)
        .await
    }

    /// Start a pre-pairing session with the remote. This can be used to trigger the remote to
    /// provide the user with a pairing code and such.
    pub async fn prepair<'a>(&self, local_node: &'a NodeConfig, remote: PrePairingRemote) -> PairingResult<PrePairing<'a>> {
        let span = span!(tracing::Level::ERROR, "prepair", local = %local_node.node_description.id, remote = ?remote);
        let span_clone = span.clone();
        async move {
            if self.endpoint_description.deployment == Some(Deployment::Wan) && local_node.connection_initiate_url.is_none() {
                return Err(ErrorKind::InvalidConfig(ConfigError::MissingInitiateUrl).into());
            }

            trace!("Start pre-pairing with new remote.");
            let url = Url::try_from(remote.url.as_str()).map_err(|e| Error::new(ErrorKind::InvalidUrl, e))?;

            let (client, certhash) = self.prepare_reqwest_client(&url)?;

            trace!("Prepared reqwest client.");

            let pairing_version = negotiate_version(&client, url.clone()).await?;

            match pairing_version {
                PairingVersion::V1 => {
                    V1Session::new(client, url, local_node, self.endpoint_description.clone())
                        .prepair(certhash, self.pairing_deployment, remote.id, span)
                        .await
                }
            }
        }
        .instrument(span_clone)
        .await
    }

    /// Pair with a given remote S2 node, using the provided token.
    ///
    /// The callback will receive the result of the pairing attempt. If the client
    /// S2 node becomes server for the communication, it must ensure it is ready to
    /// handle the communication requests before returning Ok(()) from the callback.
    ///
    /// When the callback returns an error, the client will be notified of the error.
    #[tracing::instrument(skip_all, fields(local = %local_node.node_description.id, remote = ?remote), level = tracing::Level::ERROR)]
    pub async fn pair<E: std::error::Error + Send + 'static>(
        &self,
        local_node: &NodeConfig,
        remote: PairingRemote,
        pairing_token: &[u8],
        callback: impl AsyncFnOnce(Pairing) -> Result<(), E>,
    ) -> PairingResult<()> {
        if self.endpoint_description.deployment == Some(Deployment::Wan) && local_node.connection_initiate_url.is_none() {
            return Err(ErrorKind::InvalidConfig(ConfigError::MissingInitiateUrl).into());
        }

        trace!("Start pairing with new remote.");
        let url = Url::try_from(remote.url.as_str()).map_err(|e| Error::new(ErrorKind::InvalidUrl, e))?;

        let (client, certhash) = self.prepare_reqwest_client(&url)?;

        trace!("Prepared reqwest client.");

        let pairing_version = negotiate_version(&client, url.clone()).await?;

        match pairing_version {
            PairingVersion::V1 => {
                V1Session::new(client, url, local_node, self.endpoint_description.clone())
                    .pair(certhash, self.pairing_deployment, remote.id, pairing_token, callback)
                    .await
            }
        }
    }

    fn prepare_reqwest_client(&self, url: &Url) -> Result<(reqwest::Client, Option<HashProvider>), Error> {
        let (client, certhash) = if url.domain().map(|v| v.ends_with(".local")).unwrap_or_default()
            || url.domain().map(|v| v.ends_with(".local.")).unwrap_or_default()
        {
            let (client, certhash) = hash_providing_https_client()?;
            (client, Some(certhash))
        } else {
            (
                reqwest::Client::builder()
                    .tls_certs_merge(
                        self.additional_certificates
                            .iter()
                            .filter_map(|v| reqwest::Certificate::from_der(v).ok()),
                    )
                    .build()
                    .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?,
                None,
            )
        };
        Ok((client, certhash))
    }
}

struct V1Session<'a> {
    client: reqwest::Client,
    endpoint_description: EndpointDescription,
    base_url: Url,
    config: &'a NodeConfig,
}

impl<'a> V1Session<'a> {
    fn new(client: reqwest::Client, url: Url, config: &'a NodeConfig, endpoint_description: EndpointDescription) -> Self {
        V1Session {
            client,
            endpoint_description,
            base_url: url.join("v1/").unwrap(),
            config,
        }
    }

    async fn prepair(
        self,
        certhash: Option<HashProvider>,
        local_deployment: Deployment,
        id: NodeId,
        span: Span,
    ) -> PairingResult<PrePairing<'a>> {
        let response = self
            .client
            .post(self.base_url.join("preparePairing").unwrap())
            .json(&PrePairingRequest {
                client_endpoint_description: self.endpoint_description.clone(),
                client_node_description: self.config.node_description.clone(),
                server_id: Some(id),
            })
            .send()
            .await
            .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;

        if response.status() == StatusCode::BAD_REQUEST {
            let response_error: PairingResponseErrorMessage = response.json().await.map_err(|e| Error::new(ErrorKind::ProtocolError, e))?;
            return Err(Error::from(response_error));
        }
        if response.status() != StatusCode::NO_CONTENT {
            return Err(ErrorKind::ProtocolError.into());
        }

        Ok(PrePairing {
            span,
            remote_id: id,
            session: self,
            local_deployment,
            certhash,
        })
    }

    async fn pair<E: std::error::Error + Send + 'static>(
        self,
        certhash: Option<HashProvider>,
        local_deployment: Deployment,
        id: RemoteNodeIdentifier,
        pairing_token: &[u8],
        callback: impl AsyncFnOnce(Pairing) -> Result<(), E>,
    ) -> PairingResult<()> {
        let our_deployment = self.endpoint_description.deployment.unwrap_or(local_deployment);
        let our_role = self.config.node_description.role;

        let network = if self.base_url.domain().map(|v| v.ends_with(".local")).unwrap_or_default()
            || self.base_url.domain().map(|v| v.ends_with(".local.")).unwrap_or_default()
        {
            if let Some(hash) = certhash.as_ref().and_then(HashProvider::leaf_hash) {
                Network::Lan { fingerprint: hash.clone() }
            } else {
                return Err(ErrorKind::ProtocolError.into());
            }
        } else {
            Network::Wan
        };

        trace!(?network, "Determined network type of remote.");

        const HMAC_CHALLENGE_BYTES: usize = 32;
        let client_hmac_challenge = HmacChallenge::new(&mut rand::rng(), HMAC_CHALLENGE_BYTES);

        let request_pairing_response = self.request_pairing(id, &client_hmac_challenge).await?;
        let attempt_id = request_pairing_response.pairing_attempt_id;
        let remote_deployment = request_pairing_response
            .server_endpoint_description
            .deployment
            .unwrap_or_else(|| network.as_deployment());
        let remote_role = request_pairing_response.server_node_description.role;

        trace!("Requested pairing from remote.");

        match request_pairing_response.selected_hmac_hashing_algorithm {
            HmacHashingAlgorithm::Sha256 => {
                let expected = client_hmac_challenge.sha256(&network, pairing_token);

                if expected != request_pairing_response.client_hmac_challenge_response {
                    let _ = self.finalize(&attempt_id, false).await;
                    return Err(ErrorKind::InvalidToken.into());
                }
            }
        }

        trace!("Validated remote has same pairing token.");

        debug_assert!(request_pairing_response.server_hmac_challenge.0.len() >= 32);
        let server_hmac_challenge_response = match request_pairing_response.selected_hmac_hashing_algorithm {
            HmacHashingAlgorithm::Sha256 => request_pairing_response.server_hmac_challenge.sha256(&network, pairing_token),
        };

        trace!("Computed pairing token challenge response.");

        enum CommunicationRole {
            CommunicationServer { initiate_connection_url: String },
            CommunicationClient,
        }

        let role = match (our_deployment, our_role, remote_deployment, remote_role) {
            (_, Role::Rm, _, Role::Rm) | (_, Role::Cem, _, Role::Cem) => {
                let _ = self.finalize(&attempt_id, false).await;
                return Err(ErrorKind::RemoteOfSameType.into());
            }
            (Deployment::Lan, _, Deployment::Wan, _) => CommunicationRole::CommunicationClient,
            // unwrap is okay here, as Deployment::Wan or S2Role::Cem locally means we will ALWAYS have a connection initiate url.
            (Deployment::Wan, _, Deployment::Lan, _) | (_, Role::Cem, _, Role::Rm) => CommunicationRole::CommunicationServer {
                initiate_connection_url: self.config.connection_initiate_url.as_ref().unwrap().into(),
            },
            (_, Role::Rm, _, Role::Cem) => CommunicationRole::CommunicationClient,
        };

        trace!("Determined communication role.");

        let pairing = match role {
            CommunicationRole::CommunicationServer { initiate_connection_url } => {
                let access_token = AccessToken::new(&mut rand::rng());
                if let Err(e) = self
                    .post_connection_details(
                        &attempt_id,
                        server_hmac_challenge_response,
                        initiate_connection_url.clone(),
                        access_token.clone(),
                        self.config.root_certificate.as_deref().map(CertificateHash::sha256),
                    )
                    .await
                {
                    let _ = self.finalize(&attempt_id, false).await;
                    return Err(e);
                }
                Pairing {
                    remote_endpoint_description: request_pairing_response.server_endpoint_description,
                    remote_node_description: request_pairing_response.server_node_description,
                    token: access_token,
                    role: PairingRole::CommunicationServer,
                }
            }
            CommunicationRole::CommunicationClient => {
                let connection_details = match self.get_connection_details(&attempt_id, server_hmac_challenge_response).await {
                    Ok(connection_details) => connection_details,
                    Err(e) => {
                        let _ = self.finalize(&attempt_id, false).await;
                        return Err(e);
                    }
                };

                let initiate_url =
                    Url::parse(&connection_details.initiate_connection_url).map_err(|e| Error::new(ErrorKind::ProtocolError, e))?;
                let root_hash = if initiate_url.domain().map(|v| v.ends_with(".local")).unwrap_or_default()
                    || initiate_url.domain().map(|v| v.ends_with(".local.")).unwrap_or_default()
                {
                    connection_details
                        .certificate_fingerprint
                        .or(certhash.as_ref().and_then(HashProvider::root_hash).cloned())
                } else {
                    None
                };

                Pairing {
                    remote_endpoint_description: request_pairing_response.server_endpoint_description,
                    remote_node_description: request_pairing_response.server_node_description,
                    token: connection_details.access_token,
                    role: PairingRole::CommunicationClient {
                        initiate_url: connection_details.initiate_connection_url,
                        root_hash,
                    },
                }
            }
        };

        trace!("Exchanged communication details.");

        if matches!(pairing.role, PairingRole::CommunicationServer) {
            if let Err(e) = callback(pairing).await {
                let _ = self.finalize(&attempt_id, false).await;
                return Err(Error::new(
                    ErrorKind::CallbackFailed,
                    Box::new(e) as Box<dyn std::error::Error + Send + 'static>,
                ));
            }
            self.finalize(&attempt_id, true).await?;
        } else {
            self.finalize(&attempt_id, true).await?;

            callback(pairing).await.map_err(|e| {
                Error::new(
                    ErrorKind::CallbackFailed,
                    Box::new(e) as Box<dyn std::error::Error + Send + 'static>,
                )
            })?;
        }

        trace!("Confirmed pairing with remote.");

        Ok(())
    }

    async fn get_connection_details(
        &self,
        attempt_id: &PairingAttemptId,
        server_hmac_challenge_response: HmacChallengeResponse,
    ) -> PairingResult<ConnectionDetails> {
        let request = RequestConnectionDetailsRequest {
            server_hmac_challenge_response,
        };
        let response = self
            .client
            .post(self.base_url.join("requestConnectionDetails").unwrap())
            .bearer_auth(&attempt_id.0)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;
        if response.status() != StatusCode::OK {
            debug!(status = ?response.status(), "Unexpected status code in response to requestConnectionDetails.");
            return Err(ErrorKind::ProtocolError.into());
        }
        let connection_details = response
            .json::<ConnectionDetails>()
            .await
            .map_err(|e| Error::new(ErrorKind::ProtocolError, e))?;
        Ok(connection_details)
    }

    async fn post_connection_details(
        &self,
        attempt_id: &PairingAttemptId,
        server_hmac_challenge_response: HmacChallengeResponse,
        initiate_connection_url: String,
        access_token: AccessToken,
        certificate_fingerprint: Option<CertificateHash>,
    ) -> PairingResult<()> {
        let request = PostConnectionDetailsRequest {
            server_hmac_challenge_response,
            connection_details: ConnectionDetails {
                initiate_connection_url,
                access_token,
                certificate_fingerprint,
            },
        };
        let response = self
            .client
            .post(self.base_url.join("postConnectionDetails").unwrap())
            .bearer_auth(&attempt_id.0)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;
        if response.status() != StatusCode::NO_CONTENT {
            debug!(status = ?response.status(), "Unexpected status code in response to postConnectionDetails.");
            return Err(ErrorKind::ProtocolError.into());
        }

        Ok(())
    }

    async fn request_pairing(
        &self,
        id: RemoteNodeIdentifier,
        client_hmac_challenge: &HmacChallenge,
    ) -> PairingResult<RequestPairingResponse> {
        let bare_request = RequestPairing {
            node_description: self.config.node_description.clone(),
            endpoint_description: self.endpoint_description.clone(),
            id: None,
            id_alias: None,
            supported_protocols: self.config.supported_communication_protocols.clone(),
            supported_versions: self.config.supported_message_versions.clone(),
            supported_hashing_algorithms: vec![HmacHashingAlgorithm::Sha256],
            client_hmac_challenge: client_hmac_challenge.clone(),
            force_pairing: false,
        };
        let request = match id {
            RemoteNodeIdentifier::Id(node_id) => RequestPairing {
                id: Some(node_id),
                ..bare_request
            },
            RemoteNodeIdentifier::Alias(node_id_alias) => RequestPairing {
                id_alias: Some(node_id_alias),
                ..bare_request
            },
            RemoteNodeIdentifier::None => bare_request,
        };
        let response = self
            .client
            .post(self.base_url.join("requestPairing").unwrap())
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;
        if response.status() == StatusCode::BAD_REQUEST {
            let error_response = response
                .json::<PairingResponseErrorMessage>()
                .await
                .map_err(|e| Error::new(ErrorKind::ProtocolError, e))?;
            return Err(Error::from(error_response));
        }
        if response.status() != StatusCode::OK {
            debug!(status = ?response.status(), "Unexpected status code in response to requestPairing.");
            return Err(ErrorKind::ProtocolError.into());
        }
        let request_pairing_response = response
            .json::<RequestPairingResponse>()
            .await
            .map_err(|e| Error::new(ErrorKind::ProtocolError, e))?;
        Ok(request_pairing_response)
    }

    async fn finalize(self, attempt_id: &PairingAttemptId, success: bool) -> PairingResult<()> {
        let response = self
            .client
            .post(self.base_url.join("finalizePairing").unwrap())
            .bearer_auth(&attempt_id.0)
            .json(&FinalizePairingRequest { success })
            .send()
            .await
            .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;
        if response.status() != StatusCode::NO_CONTENT {
            debug!(status = ?response.status(), "Unexpected status code in response to finalize.");
            return Err(ErrorKind::ProtocolError.into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::{Arc, Mutex},
    };

    use crate::{
        Deployment, EndpointDescription, MessageVersion, NodeDescription, NodeId, Role,
        common::wire::test::{UUID_A, UUID_B, basic_node_description, pairing_s2_node_id},
        pairing::{
            Client, ClientConfig, ErrorKind, LongpollHandler, Longpoller, Network, NodeConfig, NoopPrePairingHandler, Pairing,
            PairingRemote, PairingRole, PairingToken, PrePairingHandler, PrePairingResponse, RemoteNodeIdentifier, Server, ServerConfig,
            client::PrePairingRemote,
            wire::{
                FinalizePairingRequest, HmacChallenge, HmacChallengeResponse, PairingAttemptId, PairingResponseErrorMessage,
                RequestPairing, RequestPairingResponse,
            },
        },
    };

    use axum::{
        Json, Router,
        routing::{get, post},
    };
    use axum_server::{Handle, tls_rustls::RustlsConfig};
    use http::StatusCode;
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    use tokio::{join, task::JoinHandle};

    async fn setup_server_with_prepairing(
        config: NodeConfig,
        handler: impl PrePairingHandler,
        overrides: Router<()>,
    ) -> (Handle<SocketAddr>, JoinHandle<Pairing>, Server<impl PrePairingHandler>) {
        let mut server = Server::new_with_prepairing(
            ServerConfig {
                leaf_certificate: None,
                endpoint_description: EndpointDescription::default(),
                advertised_nodes: vec![],
            },
            handler,
        );
        server.enable_longpolling().await;
        let rustls_config = RustlsConfig::from_pem(
            include_bytes!("../../testdata/localhost.chain.pem").into(),
            include_bytes!("../../testdata/localhost.key").into(),
        )
        .await
        .unwrap();
        let app = server.get_router();
        let https_server_handle = Handle::new();
        let https_server_handle_clone = https_server_handle.clone();
        tokio::spawn(async move {
            axum_server::bind_rustls(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0), rustls_config)
                .handle(https_server_handle_clone)
                .serve(overrides.fallback_service(app).into_make_service())
                .await
                .unwrap();
        });
        let server_clone = server.clone();
        let server_pair_handle = tokio::spawn(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            server
                .allow_pair_once(
                    Arc::new(config),
                    Some(pairing_s2_node_id()),
                    PairingToken(b"testtoken".as_slice().into()),
                    async |result| {
                        tx.send(result).ok();
                        Ok::<_, std::io::Error>(())
                    },
                )
                .unwrap();
            rx.await.unwrap().unwrap()
        });

        (https_server_handle, server_pair_handle, server_clone)
    }

    async fn setup_server(
        config: NodeConfig,
        overrides: Router<()>,
    ) -> (Handle<SocketAddr>, JoinHandle<Pairing>, Server<impl PrePairingHandler>) {
        setup_server_with_prepairing(config, NoopPrePairingHandler, overrides).await
    }

    #[tokio::test]
    async fn descriptors() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let (server_handle, _server_pairing, _) = setup_server(
            server_config,
            Router::new()
                .route("/v1/endpoint", get(|| async { Json(EndpointDescription::default()) }))
                .route(
                    "/v1/nodes",
                    get(|| async {
                        Json(vec![
                            basic_node_description(UUID_A, Role::Cem),
                            basic_node_description(UUID_B, Role::Rm),
                        ])
                    }),
                ),
        )
        .await;

        let addr = server_handle.listening().await.unwrap();

        let client = Client::new(ClientConfig {
            additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
            endpoint_description: EndpointDescription::default(),
            pairing_deployment: Deployment::Wan,
        })
        .unwrap();

        let (endpoint, nodes) = client
            .get_endpoint_descriptors(format!("https://localhost:{}/", addr.port()))
            .await
            .unwrap();
        assert_eq!(endpoint.deployment, None);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes.first().unwrap().id, UUID_A.into());
    }

    #[tokio::test]
    async fn descriptors_forbidden() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let (server_handle, _server_pairing, _) = setup_server(
            server_config,
            Router::new()
                .route("/v1/endpoint", get(|| async { StatusCode::UNAUTHORIZED }))
                .route("/v1/nodes", get(|| async { StatusCode::UNAUTHORIZED })),
        )
        .await;

        let addr = server_handle.listening().await.unwrap();

        let client = Client::new(ClientConfig {
            additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
            endpoint_description: EndpointDescription::default(),
            pairing_deployment: Deployment::Wan,
        })
        .unwrap();

        let err = client
            .get_endpoint_descriptors(format!("https://localhost:{}/", addr.port()))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Rejected);
    }

    #[tokio::test]
    async fn pairing_ok_rm_initiates() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("https://test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("https://client.example.com".into())
            .build()
            .unwrap();

        let (server_handle, server_pairing, _) = setup_server(server_config, Router::new()).await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: RemoteNodeIdentifier::Alias(pairing_s2_node_id()),
        };

        let client = Client::new(ClientConfig {
            additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
            endpoint_description: EndpointDescription::default(),
            pairing_deployment: Deployment::Wan,
        })
        .unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();
        client
            .pair(&client_config, remote, b"testtoken", async |pairing| {
                tx.send(pairing).unwrap();
                Ok::<_, std::io::Error>(())
            })
            .await
            .unwrap();
        let client_pairing = rx.await.unwrap();
        let server_pairing = server_pairing.await.unwrap();
        assert_eq!(client_pairing.token, server_pairing.token);
        assert_ne!(client_pairing.role, server_pairing.role);
        assert!(matches!(client_pairing.role, PairingRole::CommunicationClient { .. }));

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn pairing_ok_cem_initiates() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let (server_handle, server_pairing, _) = setup_server(server_config, Router::new()).await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: RemoteNodeIdentifier::Id(UUID_A.into()),
        };

        let client = Client::new(ClientConfig {
            additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
            endpoint_description: EndpointDescription::default(),
            pairing_deployment: Deployment::Wan,
        })
        .unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();
        client
            .pair(&client_config, remote, b"testtoken", async |pairing| {
                tx.send(pairing).unwrap();
                Ok::<_, std::io::Error>(())
            })
            .await
            .unwrap();
        let client_pairing = rx.await.unwrap();
        let server_pairing = server_pairing.await.unwrap();
        assert_eq!(client_pairing.token, server_pairing.token);
        assert_ne!(client_pairing.role, server_pairing.role);
        assert!(matches!(client_pairing.role, PairingRole::CommunicationServer));

        server_handle.shutdown();
    }

    #[derive(Debug, Clone)]
    struct TestPrePairingHandler {
        endpoint: Arc<Mutex<Option<EndpointDescription>>>,
        node: Arc<Mutex<Option<NodeDescription>>>,
        client_id: Arc<Mutex<Option<NodeId>>>,
        target_node: Arc<Mutex<Option<Option<NodeId>>>>,
        response: PrePairingResponse,
    }

    impl TestPrePairingHandler {
        fn new(response: PrePairingResponse) -> Self {
            Self {
                endpoint: Arc::default(),
                node: Arc::default(),
                client_id: Arc::default(),
                target_node: Arc::default(),
                response,
            }
        }
    }

    impl PrePairingHandler for TestPrePairingHandler {
        fn prepairing_requested(
            &self,
            endpoint: EndpointDescription,
            node: NodeDescription,
            target_node: Option<NodeId>,
        ) -> PrePairingResponse {
            *self.endpoint.lock().unwrap() = Some(endpoint);
            *self.node.lock().unwrap() = Some(node);
            *self.target_node.lock().unwrap() = Some(target_node);
            self.response
        }

        fn prepairing_cancelled(&self, id: crate::NodeId, target_node: Option<NodeId>) {
            *self.client_id.lock().unwrap() = Some(id);
            *self.target_node.lock().unwrap() = Some(target_node);
        }
    }

    #[tokio::test]
    async fn prepairing_then_pair() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let test_handler = TestPrePairingHandler::new(PrePairingResponse::Accept);
        let (server_handle, server_pairing, _) = setup_server_with_prepairing(server_config, test_handler.clone(), Router::new()).await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PrePairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: UUID_A.into(),
        };

        let client = Client::new(ClientConfig {
            additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
            endpoint_description: EndpointDescription::default(),
            pairing_deployment: Deployment::Wan,
        })
        .unwrap();

        let client_prepair = client.prepair(&client_config, remote).await.unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        client_prepair
            .pair(b"testtoken", async |pairing| {
                tx.send(pairing).unwrap();
                Ok::<_, std::io::Error>(())
            })
            .await
            .unwrap();
        let client_pairing = rx.await.unwrap();
        let server_pairing = server_pairing.await.unwrap();
        assert_eq!(client_pairing.token, server_pairing.token);
        assert_ne!(client_pairing.role, server_pairing.role);
        assert!(matches!(client_pairing.role, PairingRole::CommunicationServer));

        let endpoint = test_handler.endpoint.lock().unwrap().take().unwrap();
        let node = test_handler.node.lock().unwrap().take().unwrap();
        let target_node = test_handler.target_node.lock().unwrap().take().unwrap();
        assert_eq!(endpoint.deployment, None);
        assert_eq!(node.id, UUID_B.into());
        assert_eq!(target_node, Some(UUID_A.into()));

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn prepairing_then_cancel() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let test_handler = TestPrePairingHandler::new(PrePairingResponse::Accept);
        let (server_handle, _, _) = setup_server_with_prepairing(server_config, test_handler.clone(), Router::new()).await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PrePairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: UUID_A.into(),
        };

        let client = Client::new(ClientConfig {
            additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
            endpoint_description: EndpointDescription::default(),
            pairing_deployment: Deployment::Wan,
        })
        .unwrap();

        let client_prepair = client.prepair(&client_config, remote).await.unwrap();

        let endpoint = test_handler.endpoint.lock().unwrap().take().unwrap();
        let node = test_handler.node.lock().unwrap().take().unwrap();
        let target_node = test_handler.target_node.lock().unwrap().take().unwrap();
        assert_eq!(endpoint.deployment, None);
        assert_eq!(node.id, UUID_B.into());
        assert_eq!(target_node, Some(UUID_A.into()));

        client_prepair.cancel().await.unwrap();

        let client_id = test_handler.client_id.lock().unwrap().take().unwrap();
        let target_node = test_handler.target_node.lock().unwrap().take().unwrap();
        assert_eq!(client_id, UUID_B.into());
        assert_eq!(target_node, Some(UUID_A.into()));

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn prepairing_rejected() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let test_handler = TestPrePairingHandler::new(PrePairingResponse::RejectUnwantedRole);
        let (server_handle, _, _) = setup_server_with_prepairing(server_config, test_handler.clone(), Router::new()).await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PrePairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: UUID_A.into(),
        };

        let client = Client::new(ClientConfig {
            additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
            endpoint_description: EndpointDescription::default(),
            pairing_deployment: Deployment::Wan,
        })
        .unwrap();

        let Err(client_prepair) = client.prepair(&client_config, remote).await else {
            panic!("Unexpected successfull prepairing");
        };

        assert_eq!(client_prepair.kind(), ErrorKind::RemoteOfSameType)
    }

    #[tokio::test]
    async fn pairing_rejects_invalid_hmac() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let finalize_result = Arc::new(Mutex::new(None));
        let finalize_result_clone = finalize_result.clone();
        let (server_handle, _, _) = setup_server(
            server_config,
            Router::new()
                .route(
                    "/v1/requestPairing",
                    post(|| async {
                        Json(RequestPairingResponse {
                            pairing_attempt_id: PairingAttemptId("testid".into()),
                            server_node_description: basic_node_description(UUID_A, Role::Cem),
                            server_endpoint_description: EndpointDescription::default(),
                            selected_hmac_hashing_algorithm: crate::pairing::wire::HmacHashingAlgorithm::Sha256,
                            client_hmac_challenge_response: HmacChallengeResponse(vec![0; 64]),
                            server_hmac_challenge: HmacChallenge::new(&mut rand::rng(), 32),
                        })
                    }),
                )
                .route(
                    "/v1/finalizePairing",
                    post(
                        |attempt_id: PairingAttemptId, Json(FinalizePairingRequest { success })| async move {
                            assert_eq!(attempt_id.0, "testid");
                            *finalize_result_clone.lock().unwrap() = Some(success);
                        },
                    ),
                ),
        )
        .await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: RemoteNodeIdentifier::Alias(pairing_s2_node_id()),
        };

        let client = Client::new(ClientConfig {
            additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
            endpoint_description: EndpointDescription::default(),
            pairing_deployment: Deployment::Wan,
        })
        .unwrap();

        let client_pairing = client
            .pair(&client_config, remote, b"testtoken", async |_| -> Result<(), std::io::Error> {
                panic!("Should not be called on failure");
            })
            .await
            .unwrap_err();
        assert_eq!(client_pairing.kind(), ErrorKind::InvalidToken);
        assert_eq!(*finalize_result.lock().unwrap(), Some(false));

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn pairing_rejects_same_role() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let finalize_result = Arc::new(Mutex::new(None));
        let finalize_result_clone = finalize_result.clone();
        let (server_handle, _, _) = setup_server(
            server_config,
            Router::new()
                .route(
                    "/v1/requestPairing",
                    post(|Json(request): Json<RequestPairing>| async move {
                        Json(RequestPairingResponse {
                            pairing_attempt_id: PairingAttemptId("testid".into()),
                            server_node_description: basic_node_description(UUID_A, Role::Rm),
                            server_endpoint_description: EndpointDescription::default(),
                            selected_hmac_hashing_algorithm: crate::pairing::wire::HmacHashingAlgorithm::Sha256,
                            client_hmac_challenge_response: request.client_hmac_challenge.sha256(&Network::Wan, b"testtoken"),
                            server_hmac_challenge: HmacChallenge::new(&mut rand::rng(), 32),
                        })
                    }),
                )
                .route(
                    "/v1/finalizePairing",
                    post(
                        |attempt_id: PairingAttemptId, Json(FinalizePairingRequest { success })| async move {
                            assert_eq!(attempt_id.0, "testid");
                            *finalize_result_clone.lock().unwrap() = Some(success);
                        },
                    ),
                ),
        )
        .await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: RemoteNodeIdentifier::Alias(pairing_s2_node_id()),
        };

        let client = Client::new(ClientConfig {
            additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
            endpoint_description: EndpointDescription::default(),
            pairing_deployment: Deployment::Wan,
        })
        .unwrap();

        let client_pairing = client
            .pair(&client_config, remote, b"testtoken", async |_| -> Result<(), std::io::Error> {
                panic!("Should not be called on failure");
            })
            .await
            .unwrap_err();
        assert_eq!(client_pairing.kind(), ErrorKind::RemoteOfSameType);
        assert_eq!(*finalize_result.lock().unwrap(), Some(false));

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn pairing_rejects_same_role_reported_by_server() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let finalize_result = Arc::new(Mutex::new(None));
        let finalize_result_clone = finalize_result.clone();
        let (server_handle, _, _) = setup_server(
            server_config,
            Router::new()
                .route(
                    "/v1/requestPairing",
                    post(|| async {
                        (
                            StatusCode::BAD_REQUEST,
                            Json(PairingResponseErrorMessage::InvalidCombinationOfRoles),
                        )
                    }),
                )
                .route(
                    "/v1/finalizePairing",
                    post(
                        |attempt_id: PairingAttemptId, Json(FinalizePairingRequest { success })| async move {
                            assert_eq!(attempt_id.0, "testid");
                            *finalize_result_clone.lock().unwrap() = Some(success);
                        },
                    ),
                ),
        )
        .await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: RemoteNodeIdentifier::Alias(pairing_s2_node_id()),
        };

        let client = Client::new(ClientConfig {
            additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
            endpoint_description: EndpointDescription::default(),
            pairing_deployment: Deployment::Wan,
        })
        .unwrap();

        let client_pairing = client
            .pair(&client_config, remote, b"testtoken", async |_| -> Result<(), std::io::Error> {
                panic!("Should not be called on failure");
            })
            .await
            .unwrap_err();
        assert_eq!(client_pairing.kind(), ErrorKind::RemoteOfSameType);
        assert_eq!(*finalize_result.lock().unwrap(), None);

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn pairing_invokes_finalize_on_bad_request_connection_details() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let finalize_result = Arc::new(Mutex::new(None));
        let finalize_result_clone = finalize_result.clone();
        let (server_handle, _, _) = setup_server(
            server_config,
            Router::new()
                .route("/v1/requestConnectionDetails", post(|| async { StatusCode::BAD_GATEWAY }))
                .route(
                    "/v1/finalizePairing",
                    post(|Json(FinalizePairingRequest { success })| async move {
                        *finalize_result_clone.lock().unwrap() = Some(success);
                    }),
                ),
        )
        .await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: RemoteNodeIdentifier::Alias(pairing_s2_node_id()),
        };

        let client = Client::new(ClientConfig {
            additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
            endpoint_description: EndpointDescription::default(),
            pairing_deployment: Deployment::Wan,
        })
        .unwrap();

        let client_pairing = client
            .pair(&client_config, remote, b"testtoken", async |_| -> Result<(), std::io::Error> {
                panic!("Should not be called on failure");
            })
            .await
            .unwrap_err();
        assert_eq!(client_pairing.kind(), ErrorKind::ProtocolError);
        assert_eq!(*finalize_result.lock().unwrap(), Some(false));

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn pairing_invokes_finalize_on_bad_post_connection_details() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let finalize_result = Arc::new(Mutex::new(None));
        let finalize_result_clone = finalize_result.clone();
        let (server_handle, _, _) = setup_server(
            server_config,
            Router::new()
                .route("/v1/postConnectionDetails", post(|| async { StatusCode::BAD_GATEWAY }))
                .route(
                    "/v1/finalizePairing",
                    post(|Json(FinalizePairingRequest { success })| async move {
                        *finalize_result_clone.lock().unwrap() = Some(success);
                    }),
                ),
        )
        .await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: RemoteNodeIdentifier::Alias(pairing_s2_node_id()),
        };

        let client = Client::new(ClientConfig {
            additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
            endpoint_description: EndpointDescription::default(),
            pairing_deployment: Deployment::Wan,
        })
        .unwrap();

        let client_pairing = client
            .pair(&client_config, remote, b"testtoken", async |_| -> Result<(), std::io::Error> {
                panic!("Should not be called on failure");
            })
            .await
            .unwrap_err();
        assert_eq!(client_pairing.kind(), ErrorKind::ProtocolError);
        assert_eq!(*finalize_result.lock().unwrap(), Some(false));

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn pairing_invokes_finalize_on_callback_failure() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let finalize_result = Arc::new(Mutex::new(None));
        let finalize_result_clone = finalize_result.clone();
        let (server_handle, _, _) = setup_server(
            server_config,
            Router::new().route(
                "/v1/finalizePairing",
                post(|Json(FinalizePairingRequest { success })| async move {
                    *finalize_result_clone.lock().unwrap() = Some(success);
                }),
            ),
        )
        .await;

        let addr = server_handle.listening().await.unwrap();
        let remote = PairingRemote {
            url: format!("https://localhost:{}/", addr.port()),
            id: RemoteNodeIdentifier::Alias(pairing_s2_node_id()),
        };

        let client = Client::new(ClientConfig {
            additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
            endpoint_description: EndpointDescription::default(),
            pairing_deployment: Deployment::Wan,
        })
        .unwrap();

        let client_pairing = client
            .pair(&client_config, remote, b"testtoken", async |_| -> Result<(), std::io::Error> {
                Err(std::io::ErrorKind::Other.into())
            })
            .await
            .unwrap_err();
        assert_eq!(client_pairing.kind(), ErrorKind::CallbackFailed);
        assert_eq!(*finalize_result.lock().unwrap(), Some(false));

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn longpolling() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("https://test.example.com".into())
            .build()
            .unwrap();

        let (server_handle, server_pairing, server) = setup_server(server_config, Router::new()).await;

        let addr = server_handle.listening().await.unwrap();

        let client_task = async move {
            let client_config = NodeConfig::builder(basic_node_description(UUID_B, Role::Rm), vec![MessageVersion("v1".into())])
                .with_connection_initiate_url("client.example.com".into())
                .build()
                .unwrap();

            let client = Client::new(ClientConfig {
                additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
                endpoint_description: EndpointDescription::default(),
                pairing_deployment: Deployment::Wan,
            })
            .unwrap();

            let longpoller = client.longpoller(format!("https://localhost:{}", addr.port())).await.unwrap();

            struct TestHandler<'a> {
                have_prepare: bool,
                have_cancel: bool,
                poller: &'a Longpoller,
            }

            impl LongpollHandler for TestHandler<'_> {
                async fn request_pairing(&mut self, node: NodeId) -> bool {
                    assert!(self.have_cancel);
                    assert_eq!(node, UUID_B.into());
                    self.poller.remove_node(node);
                    true
                }

                async fn prepare_pairing(&mut self, node: NodeId) {
                    assert_eq!(node, UUID_B.into());
                    self.have_prepare = true;
                }

                async fn cancel_prepare_pairing(&mut self, node: NodeId) {
                    assert_eq!(node, UUID_B.into());
                    assert!(self.have_prepare);
                    self.have_cancel = true;
                }
            }

            assert!(longpoller.add_node(client_config.clone()).is_ok());

            assert!(
                longpoller
                    .run(&mut TestHandler {
                        have_prepare: false,
                        have_cancel: false,
                        poller: &longpoller
                    })
                    .await
                    .is_ok()
            );

            let remote = PairingRemote {
                url: format!("https://localhost:{}/", addr.port()),
                id: RemoteNodeIdentifier::Alias(pairing_s2_node_id()),
            };

            let (tx, rx) = tokio::sync::oneshot::channel();
            client
                .pair(&client_config, remote, b"testtoken", async |pairing| {
                    tx.send(pairing).unwrap();
                    Ok::<_, std::io::Error>(())
                })
                .await
                .unwrap();
            rx.await.unwrap()
        };

        let server_task = async move {
            let mut longpoll_session = server.get_longpolling().await;
            assert_eq!(longpoll_session.client_id(), UUID_B.into());
            let node_description = longpoll_session.node_description().await.unwrap();
            assert_eq!(node_description.id, UUID_B.into());
            assert_eq!(node_description.role, Role::Rm);

            assert!(longpoll_session.prepare_pairing().await.is_ok());
            assert!(longpoll_session.cancel_prepare_pairing().await.is_ok());
            assert!(longpoll_session.request_pairing().await.is_ok());

            server_pairing.await.unwrap()
        };

        let (client_pairing, server_pairing) = join!(client_task, server_task);
        assert_eq!(client_pairing.token, server_pairing.token);
        assert_ne!(client_pairing.role, server_pairing.role);
        assert!(matches!(client_pairing.role, PairingRole::CommunicationClient { .. }));

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn longpolling_request_pairing_not_ready() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let (server_handle, _, server) = setup_server(server_config, Router::new()).await;

        let addr = server_handle.listening().await.unwrap();

        let client_task = tokio::spawn(async move {
            let client_config = NodeConfig::builder(basic_node_description(UUID_B, Role::Rm), vec![MessageVersion("v1".into())])
                .with_connection_initiate_url("client.example.com".into())
                .build()
                .unwrap();

            let client = Client::new(ClientConfig {
                additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
                endpoint_description: EndpointDescription::default(),
                pairing_deployment: Deployment::Wan,
            })
            .unwrap();

            let longpoller = client.longpoller(format!("https://localhost:{}", addr.port())).await.unwrap();

            struct TestHandler;

            impl LongpollHandler for TestHandler {
                async fn request_pairing(&mut self, node: NodeId) -> bool {
                    assert_eq!(node, UUID_B.into());
                    false
                }

                async fn prepare_pairing(&mut self, _node: NodeId) {
                    unimplemented!()
                }

                async fn cancel_prepare_pairing(&mut self, _node: NodeId) {
                    unimplemented!()
                }
            }

            assert!(longpoller.add_node(client_config.clone()).is_ok());

            longpoller.run(&mut TestHandler).await.ok();
        });

        let mut longpoll_session = server.get_longpolling().await;
        assert!(longpoll_session.request_pairing().await.is_err());

        client_task.abort();

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn longpolling_cancelled() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let (server_handle, _, _) = setup_server(
            server_config,
            Router::new().route("/v1/waitForPairing", post(|| async { StatusCode::BAD_REQUEST })),
        )
        .await;

        let client = Client::new(ClientConfig {
            additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
            endpoint_description: EndpointDescription::default(),
            pairing_deployment: Deployment::Wan,
        })
        .unwrap();

        let longpoller = client
            .longpoller(format!("https://localhost:{}", server_handle.listening().await.unwrap().port()))
            .await
            .unwrap();

        assert!(longpoller.add_node(client_config).is_ok());

        struct TestHandler;

        impl LongpollHandler for TestHandler {
            async fn request_pairing(&mut self, _node: NodeId) -> bool {
                unimplemented!()
            }

            async fn prepare_pairing(&mut self, _node: NodeId) {
                unimplemented!()
            }

            async fn cancel_prepare_pairing(&mut self, _node: NodeId) {
                unimplemented!()
            }
        }

        assert_eq!(longpoller.run(&mut TestHandler).await.unwrap_err().kind(), ErrorKind::Cancelled);

        server_handle.shutdown();
    }

    #[tokio::test]
    async fn longpolling_rejected() {
        let server_config = NodeConfig::builder(basic_node_description(UUID_A, Role::Cem), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("test.example.com".into())
            .build()
            .unwrap();

        let client_config = NodeConfig::builder(basic_node_description(UUID_B, Role::Rm), vec![MessageVersion("v1".into())])
            .with_connection_initiate_url("client.example.com".into())
            .build()
            .unwrap();

        let (server_handle, _, _) = setup_server(
            server_config,
            Router::new().route("/v1/waitForPairing", post(|| async { StatusCode::UNAUTHORIZED })),
        )
        .await;

        let client = Client::new(ClientConfig {
            additional_certificates: vec![CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()],
            endpoint_description: EndpointDescription::default(),
            pairing_deployment: Deployment::Wan,
        })
        .unwrap();

        let longpoller = client
            .longpoller(format!("https://localhost:{}", server_handle.listening().await.unwrap().port()))
            .await
            .unwrap();

        assert!(longpoller.add_node(client_config).is_ok());

        struct TestHandler;

        impl LongpollHandler for TestHandler {
            async fn request_pairing(&mut self, _node: NodeId) -> bool {
                unimplemented!()
            }

            async fn prepare_pairing(&mut self, _node: NodeId) {
                unimplemented!()
            }

            async fn cancel_prepare_pairing(&mut self, _node: NodeId) {
                unimplemented!()
            }
        }

        assert_eq!(longpoller.run(&mut TestHandler).await.unwrap_err().kind(), ErrorKind::Rejected);

        server_handle.shutdown();
    }
}
