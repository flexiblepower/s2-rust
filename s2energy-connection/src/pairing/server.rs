#![allow(unused)]
use std::{
    collections::{HashMap, VecDeque},
    future::poll_fn,
    str::FromStr,
    sync::{Arc, Mutex},
    task::Poll,
    time::Duration,
};

use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use base64::{DecodeError, Engine, display::Base64Display, prelude::BASE64_STANDARD};
use rand::RngCore;
use reqwest::StatusCode;
use rustls::pki_types::CertificateDer;
use sha2::Digest;
use tokio::{
    net::unix::pipe::Receiver,
    time::{Instant, timeout},
};
use tracing::{Instrument, info, trace};

use crate::{
    common::{
        root,
        wire::{AccessToken, PairingVersion, S2EndpointDescription, S2NodeDescription, S2NodeId},
    },
    pairing::{Error, PairingRole},
};

use super::{ErrorKind, Network, NodeConfig, Pairing, PairingResult, wire::*};

const PERMANENT_PAIRING_BUFFER_SIZE: usize = 1;
const LONGPOLLING_HANDLE_BUFFER_SIZE: usize = 16;
const LONGPOLLING_COMMAND_BUFFER_SIZE: usize = 1;

const LONGPOLLING_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Token known to both S2 nodes trying to pair.
///
/// This token is used to validate the identity of the nodes.
#[derive(Debug, Clone)]
pub struct PairingToken(pub Box<[u8]>);

impl std::fmt::Display for PairingToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Base64Display::new(&self.0, &BASE64_STANDARD).fmt(f)
    }
}

/// Error that occurred when parsing a pairing token.
#[derive(Debug, PartialEq, Eq)]
pub struct PairingTokenError(DecodeError);

impl std::fmt::Display for PairingTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid pairing token: {}", self.0)
    }
}

impl std::error::Error for PairingTokenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl From<DecodeError> for PairingTokenError {
    fn from(value: DecodeError) -> Self {
        Self(value)
    }
}

impl FromStr for PairingToken {
    type Err = PairingTokenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(PairingToken(BASE64_STANDARD.decode(s)?.into()))
    }
}

impl PairingToken {
    /// Generate a new pairing token suitable for short-lived use.
    #[expect(clippy::new_without_default, reason = "Uses non-trivial randomness")]
    pub fn new() -> Self {
        let mut result = Self(Box::new([0; 9]));
        rand::rng().fill_bytes(&mut result.0);
        result
    }

    /// Generate a new pairing token suitable for long-term use.
    pub fn new_static() -> Self {
        let mut result = Self(Box::new([0; 12]));
        rand::rng().fill_bytes(&mut result.0);
        result
    }
}

/// Server for handling S2 pairing transactions.
///
/// Responsible for providing the HTTP endpoints needed for handling
pub struct Server<H> {
    state: AppState<H>,
    longpolling_enabled: tokio::sync::watch::Sender<bool>,
    // used to allow waiting for the end of all longpolling request.
    //
    // each request will hold a read lock on this for its duration.
    // the enable/disable logic will keep a write lock.
    longpolling_sessions_active: Arc<tokio::sync::RwLock<()>>,
    pending_longpolling_handles: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<LongpollingHandle>>>,
}

impl<H> Clone for Server<H> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            longpolling_enabled: self.longpolling_enabled.clone(),
            longpolling_sessions_active: self.longpolling_sessions_active.clone(),
            pending_longpolling_handles: self.pending_longpolling_handles.clone(),
        }
    }
}

/// Configuration for the S2 pairing server.
pub struct ServerConfig {
    /// The root certificate of the server, if we are using a self-signed root.
    /// Presence of this field indicates we are deployed on LAN.
    pub leaf_certificate: Option<CertificateDer<'static>>,
    /// Endpoint description of the server
    pub endpoint_description: S2EndpointDescription,
    /// Initial set of nodes to advertise. This is only used if the server
    /// is deployed on LAN.
    pub advertised_nodes: Vec<S2NodeDescription>,
}

/// A pending one-time pairing transaction.
pub struct PendingPairing {
    receiver: tokio::sync::oneshot::Receiver<PairingResult<Pairing>>,
}

impl PendingPairing {
    /// Wait for the result of the pairing transaction.
    pub async fn result(self) -> PairingResult<Pairing> {
        self.receiver.await.unwrap_or(Err(ErrorKind::Timeout.into()))
    }
}

/// A repeated pairing with a fixed token, that can yield multiple pairings.
pub struct RepeatedPairing {
    receiver: tokio::sync::mpsc::Receiver<PairingResult<Pairing>>,
}

impl RepeatedPairing {
    /// Wait for and return the next pairing result using the token associated with this repeated pairing.
    pub async fn next(&mut self) -> Option<Pairing> {
        loop {
            if let Ok(pairing) = self.receiver.recv().await.transpose() {
                break pairing;
            }
        }
    }
}

/// Description of what response to
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrePairingResponse {
    /// Indicate willingness to pair
    Accept,
    /// Indicate unwillingness because we currently don't manage any nodes.
    RejectNoS2Node,
    /// Indicate unwillingness because we have the same role as the remote.
    RejectUnwantedRole,
}

/// Handler for pre-pairing requests.
///
/// This allows notification of other components when a pre-pairing request
/// comes in. The methods of this trait are called during request handling,
/// and should thus return rapidly.
// Note: Because these methods are called during request handling, we
// deliberately make them not async to encourage not doing long-lasting
// operations.
pub trait PrePairingHandler: Send + Sync + 'static {
    /// Handle a request for pre-pairing, and indicate our willingness.
    fn prepairing_requested(
        &self,
        endpoint: S2EndpointDescription,
        node: S2NodeDescription,
        target_node: Option<S2NodeId>,
    ) -> PrePairingResponse;
    /// Handle a cancel event for pre-pairing. Note that not every pre-pairing
    /// request will result in a cancel or a pairing interaction, so timeouts
    /// may be needed.
    fn prepairing_cancelled(&self, id: S2NodeId, target_node: Option<S2NodeId>);
}

/// A pre-pairing handler that does nothing on receiving a pre-pairing request.
///
/// The requests will always indicate willingness to pair to the client.
pub struct NoopPrePairingHandler;

impl PrePairingHandler for NoopPrePairingHandler {
    fn prepairing_requested(
        &self,
        _endpoint: S2EndpointDescription,
        _node: S2NodeDescription,
        _target_node: Option<S2NodeId>,
    ) -> PrePairingResponse {
        // no reason not to accept
        PrePairingResponse::Accept
    }

    fn prepairing_cancelled(&self, _id: S2NodeId, _target_node: Option<S2NodeId>) {
        // noop
    }
}

impl Server<NoopPrePairingHandler> {
    /// Create a new server using the given configuration.
    pub fn new(server_config: ServerConfig) -> Self {
        Self::new_with_prepairing(server_config, NoopPrePairingHandler)
    }
}

impl<H: PrePairingHandler> Server<H> {
    /// Create a new server using the given configuration, with a prepairing
    /// handler.
    pub fn new_with_prepairing(server_config: ServerConfig, handler: H) -> Self {
        let (longpolling_handle_sender, pending_longpolling_handles) = tokio::sync::mpsc::channel(LONGPOLLING_HANDLE_BUFFER_SIZE);
        let (longpolling_enabled_sender, longpolling_enabled_receiver) = tokio::sync::watch::channel(false);
        let longpolling_sessions_active = Arc::new(tokio::sync::RwLock::new(()));

        let state = AppStateInner {
            network: server_config
                .leaf_certificate
                .map(|v| Network::Lan {
                    fingerprint: sha2::Sha256::digest(v).into(),
                })
                .unwrap_or(Network::Wan),
            advertised_nodes: Mutex::new(server_config.advertised_nodes),
            endpoint_description: server_config.endpoint_description,
            permanent_pairings: Mutex::new(HashMap::new()),
            open_pairings: Mutex::new(HashMap::new()),
            attempts: Mutex::new(HashMap::default()),
            prepairing_handler: Arc::new(handler),
            longpolling_enabled: longpolling_enabled_receiver,
            longpolling_sessions_active: longpolling_sessions_active.clone(),
            longpolling_sessions: Mutex::new(HashMap::new()),
            longpolling_handle_sender,
        };

        Self {
            state: Arc::new(state),
            longpolling_enabled: longpolling_enabled_sender,
            longpolling_sessions_active,
            pending_longpolling_handles: Arc::new(tokio::sync::Mutex::new(pending_longpolling_handles)),
        }
    }
}

impl<H: PrePairingHandler> Server<H> {
    /// Get an [`axum::Router`] handling the endpoints for the pairing protocol.
    ///
    /// Incomming http requests can be handled by this router through the [axum-server](https://docs.rs/axum-server/0.8.0/axum_server/) crate.
    pub fn get_router(&self) -> axum::Router<()> {
        Router::new()
            .route("/", get(root))
            .nest("/v1", v1_router())
            .with_state(self.state.clone())
    }

    /// Update the nodes advertised by this server.
    ///
    /// These are only used when the server is on a LAN.
    pub fn update_advertised_nodes(&self, advertised_nodes: Vec<S2NodeDescription>) {
        *self.state.advertised_nodes.lock().unwrap() = advertised_nodes;
    }

    /// Enable longpolling
    pub async fn enable_longpolling(&mut self) {
        self.longpolling_enabled.send_replace(true);
    }

    /// Disable longpolling
    pub async fn disable_longpolling(&mut self) {
        self.longpolling_enabled.send_replace(false);
        let mut receiver = self.pending_longpolling_handles.lock().await;
        // Wait until all existing sessions are stopped. We need to drain any new
        // handles simultaneously to make sure the futures for these sessions can
        // make progress.
        let lock = tokio::select! {
            _ = async { loop { receiver.recv().await; } } => unreachable!(),
            lock = self.longpolling_sessions_active.write() => lock
        };
        // Drain the remaining new longpolling handles.
        while receiver.try_recv().is_ok() {}
        self.state.longpolling_sessions.lock().unwrap().clear();
    }

    /// Get a pending longpolling handle.
    pub async fn get_longpolling(&self) -> LongpollingHandle {
        // This unwrap can never fail, as self keeps the appstate, and therefore the sender, live.
        self.pending_longpolling_handles.lock().await.recv().await.unwrap()
    }

    /// Start a one-time pairing session for the given node using the given token.
    pub fn pair_once(
        &self,
        config: Arc<NodeConfig>,
        pairing_node_id: Option<PairingS2NodeId>,
        pairing_token: PairingToken,
    ) -> Result<PendingPairing, ErrorKind> {
        if config.connection_initiate_url.is_none() {
            return Err(ErrorKind::InvalidConfig(super::ConfigError::MissingInitiateUrl));
        }

        let pairing_node_id = pairing_node_id.unwrap_or(PairingS2NodeId(String::default()));

        // We hit issues here, because the node node_description only has S2NodeId with no
        // efficient way of mapping that back.
        let mut open_pairings = self.state.open_pairings.lock().unwrap();
        let mut permanent_pairings = self.state.permanent_pairings.lock().unwrap();
        if open_pairings.contains_key(&pairing_node_id) || permanent_pairings.contains_key(&pairing_node_id) {
            return Err(ErrorKind::AlreadyPending);
        }
        drop(permanent_pairings);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        open_pairings.insert(
            pairing_node_id,
            PairingRequest {
                config,
                sender: ResultSender::Oneshot(sender),
                token: pairing_token,
            },
        );
        Ok(PendingPairing { receiver })
    }

    /// Allow repeated pairing sessions for the given endpoing using the given token.
    pub fn pair_repeated(
        &self,
        config: Arc<NodeConfig>,
        pairing_node_id: Option<PairingS2NodeId>,
        pairing_token: PairingToken,
    ) -> Result<RepeatedPairing, ErrorKind> {
        if config.connection_initiate_url.is_none() {
            return Err(ErrorKind::InvalidConfig(super::ConfigError::MissingInitiateUrl));
        }

        let pairing_node_id = pairing_node_id.unwrap_or(PairingS2NodeId(String::default()));

        let mut open_pairings = self.state.open_pairings.lock().unwrap();
        let mut permanent_pairings = self.state.permanent_pairings.lock().unwrap();
        if open_pairings.contains_key(&pairing_node_id) || permanent_pairings.contains_key(&pairing_node_id) {
            return Err(ErrorKind::AlreadyPending);
        }
        drop(open_pairings);
        let (sender, receiver) = tokio::sync::mpsc::channel(PERMANENT_PAIRING_BUFFER_SIZE);
        permanent_pairings.insert(
            pairing_node_id,
            PermanentPairingRequest {
                config,
                sender,
                token: pairing_token,
            },
        );
        Ok(RepeatedPairing { receiver })
    }
}

/// Handle for a longpolling connection with a client S2 Node.
pub struct LongpollingHandle {
    commands: tokio::sync::mpsc::Sender<WaitForPairingAction>,
    endpoint: tokio::sync::watch::Receiver<Option<S2EndpointDescription>>,
    node: tokio::sync::watch::Receiver<Option<S2NodeDescription>>,
    last_pairing_response: tokio::sync::watch::Receiver<Option<Result<(), WaitForPairingErrorMessage>>>,
    client_id: S2NodeId,
}

impl LongpollingHandle {
    /// Client S2NodeId of the remote.
    pub fn client_id(&self) -> S2NodeId {
        self.client_id
    }

    /// Node description of the remote.
    ///
    /// This is fallible as it is not send by default, so we need to ask the remote.
    pub async fn node_description(&mut self) -> Result<S2NodeDescription, Error> {
        if self.node.borrow().is_none() {
            self.commands
                .send(WaitForPairingAction::SendS2NodeDescription)
                .await
                .map_err(|_| ErrorKind::Cancelled)?;
        }
        // The unwrap below doesn't ever fail because we wait for the option to have a value.
        Ok(timeout(LONGPOLLING_RESPONSE_TIMEOUT, self.node.wait_for(|v| v.is_some()))
            .await
            .map_err(|_| ErrorKind::Timeout)?
            .map_err(|_| ErrorKind::Cancelled)?
            .clone()
            .unwrap())
    }

    /// Endpoint description of the remote.
    ///
    /// This is fallible as it is not send by default, so we need to ask the remote.
    pub async fn endpoint_description(&mut self) -> Result<S2EndpointDescription, Error> {
        if self.endpoint.borrow().is_none() {
            self.commands
                .send(WaitForPairingAction::SendS2NodeDescription)
                .await
                .map_err(|_| ErrorKind::Cancelled)?;
        }
        // The unwrap below doesn't ever fail because we wait for the option to have a value.
        Ok(timeout(LONGPOLLING_RESPONSE_TIMEOUT, self.endpoint.wait_for(|v| v.is_some()))
            .await
            .map_err(|_| ErrorKind::Timeout)?
            .map_err(|_| ErrorKind::Cancelled)?
            .clone()
            .unwrap())
    }

    /// Request the remote to start pairing.
    pub async fn request_pairing(&mut self) -> Result<(), Error> {
        self.commands
            .send(WaitForPairingAction::RequestPairing)
            .await
            .map_err(|_| ErrorKind::Cancelled)?;
        // The unwrap below doesn't ever fail because we wait for the option to have a value.
        timeout(LONGPOLLING_RESPONSE_TIMEOUT, self.last_pairing_response.wait_for(|v| v.is_some()))
            .await
            .map_err(|_| ErrorKind::Timeout)?
            .map_err(|_| ErrorKind::Cancelled)?
            .unwrap()
            .map_err(|e| Error::new(ErrorKind::InvalidToken, e))
    }

    /// Request the remote to prepare for pairing.
    pub async fn prepare_pairing(&mut self) -> Result<(), Error> {
        self.commands
            .send(WaitForPairingAction::PreparePairing)
            .await
            .map_err(|_| ErrorKind::Cancelled.into())
    }

    /// Request the remote to cancel prepare for pairing.
    pub async fn cancel_prepare_pairing(&mut self) -> Result<(), Error> {
        self.commands
            .send(WaitForPairingAction::CancelPreparePairing)
            .await
            .map_err(|_| ErrorKind::Cancelled.into())
    }
}

enum LongpollingState {
    Disconnected {
        since: Instant,
        state: LongpollingStateInner,
    },
    Running {
        since: Instant,
        last_pairing_response: tokio::sync::watch::Sender<Option<Result<(), WaitForPairingErrorMessage>>>,
    },
}

impl LongpollingState {
    fn take(&mut self) -> Option<LongpollingStateInner> {
        match self {
            LongpollingState::Disconnected { state, .. } => {
                let mut swap_target = LongpollingState::Running {
                    since: Instant::now(),
                    last_pairing_response: state.last_pairing_response.clone(),
                };
                std::mem::swap(&mut swap_target, self);
                let LongpollingState::Disconnected { state, .. } = swap_target else {
                    unreachable!()
                };
                Some(state)
            }
            LongpollingState::Running { .. } => None,
        }
    }

    fn signal_pairing_request(&self) {
        match self {
            LongpollingState::Disconnected { state, .. } => state.last_pairing_response.send_replace(Some(Ok(()))),
            LongpollingState::Running {
                since,
                last_pairing_response,
            } => last_pairing_response.send_replace(Some(Ok(()))),
        };
    }
}

struct LongpollingStateInner {
    commands: tokio::sync::mpsc::Receiver<WaitForPairingAction>,
    endpoint: tokio::sync::watch::Sender<Option<S2EndpointDescription>>,
    node: tokio::sync::watch::Sender<Option<S2NodeDescription>>,
    last_pairing_response: tokio::sync::watch::Sender<Option<Result<(), WaitForPairingErrorMessage>>>,
}

enum ResultSender {
    Oneshot(tokio::sync::oneshot::Sender<PairingResult<Pairing>>),
    Multi(tokio::sync::mpsc::Sender<PairingResult<Pairing>>),
}

impl ResultSender {
    async fn send(self, result: PairingResult<Pairing>) {
        match self {
            Self::Oneshot(sender) => {
                let _ = sender.send(result);
            }
            Self::Multi(sender) => {
                let _ = sender.send(result).await;
            }
        };
    }
}

struct PermanentPairingRequest {
    config: Arc<NodeConfig>,
    sender: tokio::sync::mpsc::Sender<PairingResult<Pairing>>,
    token: PairingToken,
}

struct PairingRequest {
    config: Arc<NodeConfig>,
    sender: ResultSender,
    token: PairingToken,
}

struct InitialPairingState {
    session_span: tracing::Span,
    config: Arc<NodeConfig>,
    sender: ResultSender,
    challenge: HmacChallenge,
    token: PairingToken,
    remote_node_description: S2NodeDescription,
    remote_endpoint_description: S2EndpointDescription,
}
struct CompletePairingState {
    session_span: tracing::Span,
    sender: ResultSender,
    remote_node_description: S2NodeDescription,
    remote_endpoint_description: S2EndpointDescription,
    access_token: AccessToken,
    role: PairingRole,
}

enum PairingState {
    Empty,
    Initial(InitialPairingState),
    Complete(CompletePairingState),
}

impl PairingState {
    fn get_session_span(&self) -> Option<&tracing::Span> {
        match self {
            PairingState::Empty => None,
            PairingState::Initial(initial_pairing_state) => Some(&initial_pairing_state.session_span),
            PairingState::Complete(complete_pairing_state) => Some(&complete_pairing_state.session_span),
        }
    }
}

struct ExpiringPairingState {
    start_time: Instant,
    state: PairingState,
}

impl ExpiringPairingState {
    fn get_state(&mut self) -> Option<&mut PairingState> {
        if self.start_time.elapsed() > Duration::from_secs(15) {
            None
        } else {
            Some(&mut self.state)
        }
    }

    fn into_state(self) -> Option<PairingState> {
        if self.start_time.elapsed() > Duration::from_secs(15) {
            None
        } else {
            Some(self.state)
        }
    }
}

type AppState<H> = Arc<AppStateInner<H>>;

struct AppStateInner<H> {
    network: Network,
    endpoint_description: S2EndpointDescription,
    advertised_nodes: Mutex<Vec<S2NodeDescription>>,
    permanent_pairings: Mutex<HashMap<PairingS2NodeId, PermanentPairingRequest>>,
    open_pairings: Mutex<HashMap<PairingS2NodeId, PairingRequest>>,
    attempts: Mutex<HashMap<PairingAttemptId, ExpiringPairingState>>,
    prepairing_handler: Arc<H>,
    longpolling_enabled: tokio::sync::watch::Receiver<bool>,
    // used to allow waiting for the end of all longpolling request.
    //
    // each request will hold a read lock on this for its duration.
    // the enable/disable logic will keep a write lock.
    longpolling_sessions_active: Arc<tokio::sync::RwLock<()>>,
    longpolling_sessions: Mutex<HashMap<S2NodeId, LongpollingState>>,
    longpolling_handle_sender: tokio::sync::mpsc::Sender<LongpollingHandle>,
}

// Holder for longpolling sessions during a session. Returns
// them to the appstate on drop.
struct LocalLongpollingCache<H> {
    sessions: HashMap<S2NodeId, LongpollingStateInner>,
    state: AppState<H>,
}

impl<H> LocalLongpollingCache<H> {
    fn new(state: AppState<H>) -> Self {
        Self {
            sessions: HashMap::new(),
            state,
        }
    }
}

impl<H> std::ops::Deref for LocalLongpollingCache<H> {
    type Target = HashMap<S2NodeId, LongpollingStateInner>;

    fn deref(&self) -> &Self::Target {
        &self.sessions
    }
}

impl<H> std::ops::DerefMut for LocalLongpollingCache<H> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sessions
    }
}

impl<H> Drop for LocalLongpollingCache<H> {
    fn drop(&mut self) {
        let mut longpolling_sessions = self.state.longpolling_sessions.lock().unwrap();
        for (id, state) in self.sessions.drain() {
            longpolling_sessions.insert(
                id,
                LongpollingState::Disconnected {
                    since: Instant::now(),
                    state,
                },
            );
        }
    }
}

fn v1_router<H: PrePairingHandler>() -> Router<AppState<H>> {
    Router::new()
        .route("/s2endpoint", get(v1_s2endpoint))
        .route("/s2nodes", get(v1_s2nodes))
        .route("/preparePairing", post(v1_prepare_pairing))
        .route("/cancelPreparePairing", post(v1_cancel_prepare_pairing))
        .route("/waitForPairing", post(v1_wait_for_pairing))
        .route("/requestPairing", post(v1_request_pairing))
        .route("/requestConnectionDetails", post(v1_request_connection_details))
        .route("/postConnectionDetails", post(v1_post_connection_details))
        .route("/finalizePairing", post(v1_finalize_pairing))
}

#[tracing::instrument(skip_all, level = tracing::Level::INFO)]
async fn v1_wait_for_pairing<H>(
    State(state): State<AppState<H>>,
    Json(requests): Json<Vec<WaitForPairingRequest>>,
) -> Result<Json<WaitForPairingResponse>, StatusCode> {
    let _request_active = state.longpolling_sessions_active.read().await;

    let mut enabled = state.longpolling_enabled.clone();
    if !*enabled.borrow_and_update() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Collect all involved longpolling sessions
    let mut states = LocalLongpollingCache::new(state.clone());
    let mut pending_handles = vec![];
    {
        let mut longpolling_sessions = state.longpolling_sessions.lock().unwrap();
        for request in &requests {
            let state = match longpolling_sessions.entry(request.client_s2_node_id) {
                std::collections::hash_map::Entry::Occupied(mut occupied_entry) => match occupied_entry.get_mut().take() {
                    Some(state) => state,
                    None => {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                },
                std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                    let (commands_sender, commands_receiver) = tokio::sync::mpsc::channel(LONGPOLLING_COMMAND_BUFFER_SIZE);
                    let (endpoint_sender, endpoint_receiver) = tokio::sync::watch::channel(None);
                    let (node_sender, node_receiver) = tokio::sync::watch::channel(None);
                    let (last_pairing_sender, last_pairing_receiver) = tokio::sync::watch::channel(None);
                    pending_handles.push(LongpollingHandle {
                        commands: commands_sender,
                        endpoint: endpoint_receiver,
                        node: node_receiver,
                        last_pairing_response: last_pairing_receiver,
                        client_id: request.client_s2_node_id,
                    });
                    vacant_entry.insert(LongpollingState::Running {
                        since: Instant::now(),
                        last_pairing_response: last_pairing_sender.clone(),
                    });
                    LongpollingStateInner {
                        commands: commands_receiver,
                        endpoint: endpoint_sender,
                        node: node_sender,
                        last_pairing_response: last_pairing_sender,
                    }
                }
            };
            states.insert(request.client_s2_node_id, state);
        }
    }

    // Update sessions based on request data
    for request in requests {
        // Guaranteed to be present because of previous loop
        let state = states.get_mut(&request.client_s2_node_id).unwrap();
        if let Some(endpoint) = request.client_s2_endpoint_description {
            state.endpoint.send_replace(Some(endpoint));
        }
        if let Some(node) = request.client_s2_node_description {
            state.node.send_replace(Some(node));
        }
        if let Some(error_message) = request.error_message {
            state.last_pairing_response.send_replace(Some(Err(error_message)));
        }
    }

    // Send out any pending handles now we no longer hold the lock
    for handle in pending_handles {
        state.longpolling_handle_sender.send(handle).await.ok();
    }

    // Wait for something to communicate back to client
    tokio::select! {
        outcome = timeout(
            Duration::from_secs(25),
            poll_fn(|cx| {
                for (k, v) in states.iter_mut() {
                    if let Poll::Ready(message) = v.commands.poll_recv(cx) {
                        return match message {
                            Some(action) => Poll::Ready(Some((*k, action))),
                            None => Poll::Ready(None),
                        };
                    }
                }
                std::task::Poll::Pending
            }),
        ) => return match outcome {
            Ok(Some((client_s2_node_id, action))) => Ok(Json(WaitForPairingResponse { client_s2_node_id, action })),
            Ok(None) | Err(_) => Err(StatusCode::NO_CONTENT),
        },
        _ = enabled.wait_for(|v| !*v) => return Err(StatusCode::BAD_REQUEST),
    }
}

#[tracing::instrument(skip_all, level = tracing::Level::INFO)]
async fn v1_s2endpoint<H>(State(state): State<AppState<H>>) -> Result<Json<S2EndpointDescription>, StatusCode> {
    if state.network.is_lan() {
        Ok(Json(state.endpoint_description.clone()))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

#[tracing::instrument(skip_all, level = tracing::Level::INFO)]
async fn v1_s2nodes<H>(State(state): State<AppState<H>>) -> Result<Json<Vec<S2NodeDescription>>, StatusCode> {
    if state.network.is_lan() {
        Ok(Json(state.advertised_nodes.lock().unwrap().clone()))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

#[tracing::instrument(skip_all, level = tracing::Level::INFO)]
async fn v1_prepare_pairing<H: PrePairingHandler>(
    State(state): State<AppState<H>>,
    Json(request): Json<PrePairingRequest>,
) -> Result<StatusCode, PairingResponseErrorMessage> {
    match state.prepairing_handler.prepairing_requested(
        request.client_s2_endpoint_description,
        request.client_s2_node_description,
        request.server_id,
    ) {
        PrePairingResponse::Accept => Ok(StatusCode::NO_CONTENT),
        PrePairingResponse::RejectNoS2Node => Err(PairingResponseErrorMessage::S2NodeNotFound),
        PrePairingResponse::RejectUnwantedRole => Err(PairingResponseErrorMessage::InvalidCombinationOfRoles),
    }
}

#[tracing::instrument(skip_all, level = tracing::Level::INFO)]
async fn v1_cancel_prepare_pairing<H: PrePairingHandler>(
    State(state): State<AppState<H>>,
    Json(request): Json<CancelPrePairingRequest>,
) -> StatusCode {
    state.prepairing_handler.prepairing_cancelled(request.client_id, request.server_id);
    StatusCode::NO_CONTENT
}

#[tracing::instrument(skip_all, level = tracing::Level::INFO)]
async fn v1_request_pairing<H>(
    State(state): State<AppState<H>>,
    Json(request_pairing): Json<RequestPairing>,
) -> Result<Json<RequestPairingResponse>, PairingResponseErrorMessage> {
    trace!("Received pairing request.");
    if let Some(session) = state.longpolling_sessions.lock().unwrap().get(&request_pairing.node_description.id) {
        session.signal_pairing_request();
    }

    if !request_pairing.supported_hashing_algorithms.contains(&HmacHashingAlgorithm::Sha256) {
        info!(remote_hashing_algorithms = ?request_pairing.supported_hashing_algorithms, "No shared hashing algorithm with remote");
        return Err(PairingResponseErrorMessage::IncompatibleHMACHashingAlgorithms);
    }

    // 32 bytes is the minimum, this tests that the client can handle more.
    const HMAC_CHALLENGE_BYTES: usize = 64;

    let server_hmac_challenge = HmacChallenge::new(&mut rand::rng(), HMAC_CHALLENGE_BYTES);

    let pairing_s2_node_id = request_pairing.id.unwrap_or(PairingS2NodeId(String::default()));
    let open_pairing = {
        let mut open_pairings = state.open_pairings.lock().unwrap();
        if let Some((_, request)) = open_pairings.remove_entry(&pairing_s2_node_id) {
            request
        } else {
            drop(open_pairings);
            let permanent_pairings = state.permanent_pairings.lock().unwrap();
            let entry = permanent_pairings
                .get(&pairing_s2_node_id)
                .ok_or(PairingResponseErrorMessage::S2NodeNotFound)?;
            PairingRequest {
                config: entry.config.clone(),
                sender: ResultSender::Multi(entry.sender.clone()),
                token: PairingToken(entry.token.0.clone()),
            }
        }
    };

    let session_span = tracing::span!(parent: None, tracing::Level::ERROR, "Pairing session", local = %open_pairing.config.node_description.id, remote = %request_pairing.node_description.id);
    let session_span_clone = session_span.clone();

    async move {
        trace!("Found open pairing session.");

        if open_pairing.config.node_description.role == request_pairing.node_description.role {
            return Err(PairingResponseErrorMessage::InvalidCombinationOfRoles);
        }

        if !request_pairing.force_pairing {
            let mut communication_overlap = false;
            for communication_protocol in &open_pairing.config.supported_communication_protocols {
                if request_pairing.supported_protocols.contains(communication_protocol) {
                    communication_overlap = true;
                    break;
                }
            }
            if !communication_overlap {
                return Err(PairingResponseErrorMessage::IncompatibleCommunicationProtocols);
            }
            let mut connection_overlap = false;
            for connection_protocol in &open_pairing.config.supported_message_versions {
                if request_pairing.supported_versions.contains(connection_protocol) {
                    connection_overlap = true;
                    break;
                }
            }
            if !connection_overlap {
                return Err(PairingResponseErrorMessage::IncompatibleS2MessageVersions);
            }
        }

        trace!("Checked communication protocol and s2 message version compatibility.");

        debug_assert!(request_pairing.client_hmac_challenge.0.len() >= 32);
        let client_hmac_challenge_response = request_pairing.client_hmac_challenge.sha256(&state.network, &open_pairing.token.0);

        trace!("Calculated response to remote challenge.");

        let pairing_attempt_id = {
            let mut attempts = state.attempts.lock().unwrap();
            loop {
                let id = PairingAttemptId::new(&mut rand::rng());
                if !attempts.contains_key(&id) {
                    attempts.insert(
                        id.clone(),
                        ExpiringPairingState {
                            start_time: Instant::now(),
                            state: PairingState::Initial(InitialPairingState {
                                session_span,
                                config: open_pairing.config.clone(),
                                sender: open_pairing.sender,
                                challenge: server_hmac_challenge.clone(),
                                token: open_pairing.token,
                                remote_node_description: request_pairing.node_description,
                                remote_endpoint_description: request_pairing.endpoint_description,
                            }),
                        },
                    );
                    break id;
                }
            }
        };

        trace!("Created session for pairing attempt.");

        let resp = RequestPairingResponse {
            pairing_attempt_id,
            server_s2_node_description: open_pairing.config.node_description.clone(),
            server_s2_endpoint_description: state.endpoint_description.clone(),
            selected_hmac_hashing_algorithm: HmacHashingAlgorithm::Sha256,
            client_hmac_challenge_response,
            server_hmac_challenge,
        };

        Ok(Json(resp))
    }
    .instrument(session_span_clone)
    .await
}

#[tracing::instrument(skip_all, level = tracing::Level::INFO)]
async fn v1_request_connection_details<H>(
    State(app_state): State<AppState<H>>,
    pairing_attempt_id: PairingAttemptId,
    Json(req): Json<RequestConnectionDetailsRequest>,
) -> Result<Json<ConnectionDetails>, StatusCode> {
    trace!("Received request for connection details.");

    // We do this with a closure to drop attempts before we run the future for sending results to the caller, if it is present.
    let (result, future) = (|| {
        let mut attempts = app_state.attempts.lock().unwrap();
        let Some(state) = attempts.get_mut(&pairing_attempt_id) else {
            info!("No active pairing session found for requesting connection details.");
            return (Err(StatusCode::UNAUTHORIZED), None);
        };

        if let Some(state_entry) = state.get_state()
            && let PairingState::Initial(state) = std::mem::replace(state_entry, PairingState::Empty)
        {
            // It is ok to manually enter the span here as this closure is not async.
            let session_span_clone = state.session_span.clone();
            let _entered_span = session_span_clone.enter();

            trace!("Found pairing session.");

            let expected = state.challenge.sha256(&app_state.network, &state.token.0);
            if expected != req.server_hmac_challenge_response {
                attempts.remove(&pairing_attempt_id);
                return (
                    Err(StatusCode::FORBIDDEN),
                    Some(state.sender.send(Err(ErrorKind::InvalidToken.into()))),
                );
            }

            trace!("Validated remote's response to pairing token challenge.");

            let mut rng = rand::rng();
            let connection_details = ConnectionDetails {
                initiate_connection_url: match &state.config.connection_initiate_url {
                    Some(url) => url.clone(),
                    None => return (Err(StatusCode::BAD_REQUEST), None),
                },
                access_token: AccessToken::new(&mut rng),
            };

            trace!("Generated connection details");

            *state_entry = PairingState::Complete(CompletePairingState {
                session_span: state.session_span,
                sender: state.sender,
                remote_node_description: state.remote_node_description,
                remote_endpoint_description: state.remote_endpoint_description,
                access_token: connection_details.access_token.clone(),
                role: PairingRole::CommunicationServer,
            });

            (Ok(Json(connection_details)), None)
        } else {
            info!("Pairing session was expired, or in unexpected state for requesting connection details.");
            attempts.remove(&pairing_attempt_id);
            (Err(StatusCode::UNAUTHORIZED), None)
        }
    })();

    if let Some(future) = future {
        future.await;
    }

    result
}

#[tracing::instrument(skip_all, level = tracing::Level::INFO)]
async fn v1_post_connection_details<H>(
    State(app_state): State<AppState<H>>,
    pairing_attempt_id: PairingAttemptId,
    Json(req): Json<PostConnectionDetailsRequest>,
) -> StatusCode {
    trace!("Received post of connection details");

    // We do this with a closure to drop attempts before we run the future for sending results to the caller, if it is present.
    let (result, future) = (|| {
        let mut attempts: std::sync::MutexGuard<'_, HashMap<PairingAttemptId, ExpiringPairingState>> = app_state.attempts.lock().unwrap();
        let Some(state) = attempts.get_mut(&pairing_attempt_id) else {
            info!("No active pairing session found for posting connection details.");
            return (StatusCode::UNAUTHORIZED, None);
        };

        if let Some(state_entry) = state.get_state()
            && let PairingState::Initial(state) = std::mem::replace(state_entry, PairingState::Empty)
        {
            // It is ok to manually enter the span here as this closure is not async.
            let session_span_clone = state.session_span.clone();
            let _entered_span = session_span_clone.enter();

            trace!("Found pairing session.");

            let expected = state.challenge.sha256(&app_state.network, &state.token.0);
            if expected != req.server_hmac_challenge_response {
                attempts.remove(&pairing_attempt_id);
                return (StatusCode::FORBIDDEN, Some(state.sender.send(Err(ErrorKind::InvalidToken.into()))));
            }

            trace!("Validated remote's response to pairing token challenge.");

            // Do better error handling here than unwrap
            *state_entry = PairingState::Complete(CompletePairingState {
                session_span: state.session_span,
                sender: state.sender,
                remote_node_description: state.remote_node_description,
                remote_endpoint_description: state.remote_endpoint_description,
                access_token: req.connection_details.access_token,
                role: PairingRole::CommunicationClient {
                    initiate_url: req.connection_details.initiate_connection_url,
                },
            });

            trace!("Stored received connection details in session state.");

            (StatusCode::NO_CONTENT, None)
        } else {
            info!("Pairing session was expired, or in unexpected state for posting connection details.");
            attempts.remove(&pairing_attempt_id);
            (StatusCode::UNAUTHORIZED, None)
        }
    })();

    if let Some(future) = future {
        future.await;
    }

    result
}

#[tracing::instrument(skip_all, level = tracing::Level::INFO)]
async fn v1_finalize_pairing<H>(
    State(state): State<AppState<H>>,
    pairing_attempt_id: PairingAttemptId,
    Json(success): Json<bool>,
) -> StatusCode {
    trace!("Received request to finalize pairing session.");

    let Some(state) = ({
        let mut attempts = state.attempts.lock().unwrap();
        attempts.remove(&pairing_attempt_id)
    }) else {
        info!("No active pairing session found for finalizing pairing.");
        return StatusCode::UNAUTHORIZED;
    };

    if let Some(state) = state.into_state() {
        let session_span_clone = state.get_session_span().cloned();
        let completion = async move {
            if success {
                if let PairingState::Complete(state) = state {
                    state
                        .sender
                        .send(Ok(Pairing {
                            remote_endpoint_description: state.remote_endpoint_description,
                            remote_node_description: state.remote_node_description,
                            token: state.access_token,
                            role: state.role,
                        }))
                        .await;

                    trace!("Finalized pairing session.");

                    StatusCode::NO_CONTENT
                } else {
                    info!("Remote tried to finalize pairing session that did not yet have all the data exchanged.");
                    StatusCode::BAD_REQUEST
                }
            } else {
                match state {
                    PairingState::Empty => { /* should never happen, but fine to ignore */ }
                    PairingState::Initial(InitialPairingState { sender, .. })
                    | PairingState::Complete(CompletePairingState { sender, .. }) => {
                        sender.send(Err(ErrorKind::Cancelled.into())).await;
                    }
                }

                info!("Pairing session was cancelled by remote.");

                StatusCode::NO_CONTENT
            }
        };
        if let Some(session_span) = session_span_clone {
            completion.instrument(session_span).await
        } else {
            completion.await
        }
    } else {
        info!("Pairing session was expired during finalization.");
        StatusCode::UNAUTHORIZED
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex, OnceLock},
        time::Duration,
    };

    use axum::body::Body;
    use http::StatusCode;
    use http_body_util::BodyExt;
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    use tokio::{
        join,
        time::{Instant, sleep, timeout},
    };
    use tower::ServiceExt;
    use tracing::{Level, span};

    use crate::{
        AccessToken, CommunicationProtocol, MessageVersion, S2EndpointDescription, S2NodeDescription, S2NodeId, S2Role,
        common::wire::test::{UUID_A, UUID_B, basic_node_description, pairing_s2_node_id},
        pairing::{
            ErrorKind, Network, NodeConfig, PairingRole, PairingS2NodeId, PairingToken, PrePairingHandler, PrePairingResponse, Server,
            ServerConfig,
            server::{CompletePairingState, ExpiringPairingState, InitialPairingState, PairingRequest, PairingState, ResultSender},
            wire::{
                CancelPrePairingRequest, ConnectionDetails, HmacChallenge, HmacHashingAlgorithm, PairingAttemptId,
                PairingResponseErrorMessage, PostConnectionDetailsRequest, PrePairingRequest, RequestConnectionDetailsRequest,
                RequestPairing, RequestPairingResponse, WaitForPairingAction, WaitForPairingErrorMessage, WaitForPairingRequest,
                WaitForPairingResponse,
            },
        },
    };

    #[test]
    fn token_encode_decode() {
        let token = PairingToken(Box::new([0, 1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(token.to_string(), "AAECAwQFBgcI");
        assert_eq!(token.0, "AAECAwQFBgcI".parse::<PairingToken>().unwrap().0);
    }

    #[tokio::test]
    async fn version_negotiation() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });

        let response = server
            .get_router()
            .oneshot(http::Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, b"[\"v1\"]".as_slice());
    }

    #[tokio::test]
    async fn advertised_endpoint() {
        let server = Server::new(ServerConfig {
            leaf_certificate: Some(CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()),
            endpoint_description: S2EndpointDescription {
                name: Some("Testendpoint".into()),
                logo_uri: None,
                deployment: None,
            },
            advertised_nodes: vec![basic_node_description(UUID_A, S2Role::Cem)],
        });

        let response = server
            .get_router()
            .oneshot(http::Request::get("/v1/s2endpoint").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_data: S2EndpointDescription = serde_json::from_slice(&body).unwrap();
        assert_eq!(body_data.name.as_deref(), Some("Testendpoint"));
    }

    #[tokio::test]
    async fn advertised_endpoint_wan() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription {
                name: Some("Testendpoint".into()),
                logo_uri: None,
                deployment: None,
            },
            advertised_nodes: vec![basic_node_description(UUID_A, S2Role::Cem)],
        });

        let response = server
            .get_router()
            .oneshot(http::Request::get("/v1/s2endpoint").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn advertised_nodes() {
        let server = Server::new(ServerConfig {
            leaf_certificate: Some(CertificateDer::from_pem_slice(include_bytes!("../../testdata/root.pem")).unwrap()),
            endpoint_description: S2EndpointDescription {
                name: Some("Testendpoint".into()),
                logo_uri: None,
                deployment: None,
            },
            advertised_nodes: vec![basic_node_description(UUID_A, S2Role::Cem)],
        });

        let response = server
            .get_router()
            .oneshot(http::Request::get("/v1/s2nodes").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_data: Vec<S2NodeDescription> = serde_json::from_slice(&body).unwrap();
        assert_eq!(body_data, vec![basic_node_description(UUID_A, S2Role::Cem)]);
    }

    #[tokio::test]
    async fn advertised_nodes_wan() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription {
                name: Some("Testendpoint".into()),
                logo_uri: None,
                deployment: None,
            },
            advertised_nodes: vec![basic_node_description(UUID_A, S2Role::Cem)],
        });

        let response = server
            .get_router()
            .oneshot(http::Request::get("/v1/s2nodes").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[derive(Debug, Clone)]
    struct TestPrePairingHandler {
        endpoint: Arc<Mutex<Option<S2EndpointDescription>>>,
        node: Arc<Mutex<Option<S2NodeDescription>>>,
        client_id: Arc<Mutex<Option<S2NodeId>>>,
        target_node: Arc<Mutex<Option<Option<S2NodeId>>>>,
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
            endpoint: S2EndpointDescription,
            node: S2NodeDescription,
            target_node: Option<S2NodeId>,
        ) -> super::PrePairingResponse {
            *self.endpoint.lock().unwrap() = Some(endpoint);
            *self.node.lock().unwrap() = Some(node);
            *self.target_node.lock().unwrap() = Some(target_node);
            self.response
        }

        fn prepairing_cancelled(&self, id: crate::S2NodeId, target_node: Option<S2NodeId>) {
            *self.client_id.lock().unwrap() = Some(id);
            *self.target_node.lock().unwrap() = Some(target_node);
        }
    }

    #[tokio::test]
    async fn prepairing_accept() {
        let test_handler = TestPrePairingHandler::new(PrePairingResponse::Accept);
        let server = Server::new_with_prepairing(
            ServerConfig {
                leaf_certificate: None,
                endpoint_description: S2EndpointDescription::default(),
                advertised_nodes: vec![],
            },
            test_handler.clone(),
        );
        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/preparePairing")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&PrePairingRequest {
                            client_s2_endpoint_description: S2EndpointDescription::default(),
                            client_s2_node_description: basic_node_description(UUID_A, S2Role::Cem),
                            server_id: None,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let endpoint = test_handler.endpoint.lock().unwrap().take().unwrap();
        let node = test_handler.node.lock().unwrap().take().unwrap();
        let target_node = test_handler.target_node.lock().unwrap().take().unwrap();
        assert_eq!(endpoint.deployment, None);
        assert_eq!(node.role, S2Role::Cem);
        assert_eq!(node.id, UUID_A.into());
        assert_eq!(target_node, None);
    }

    #[tokio::test]
    async fn prepairing_reject_no_node() {
        let test_handler = TestPrePairingHandler::new(PrePairingResponse::RejectNoS2Node);
        let server = Server::new_with_prepairing(
            ServerConfig {
                leaf_certificate: None,
                endpoint_description: S2EndpointDescription::default(),
                advertised_nodes: vec![],
            },
            test_handler.clone(),
        );
        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/preparePairing")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&PrePairingRequest {
                            client_s2_endpoint_description: S2EndpointDescription::default(),
                            client_s2_node_description: basic_node_description(UUID_A, S2Role::Cem),
                            server_id: None,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let response_data: PairingResponseErrorMessage = serde_json::from_slice(&body).unwrap();
        assert_eq!(response_data, PairingResponseErrorMessage::S2NodeNotFound);

        let endpoint = test_handler.endpoint.lock().unwrap().take().unwrap();
        let node = test_handler.node.lock().unwrap().take().unwrap();
        let target_node = test_handler.target_node.lock().unwrap().take().unwrap();
        assert_eq!(endpoint.deployment, None);
        assert_eq!(node.role, S2Role::Cem);
        assert_eq!(node.id, UUID_A.into());
        assert_eq!(target_node, None);
    }

    #[tokio::test]
    async fn prepairing_reject_role() {
        let test_handler = TestPrePairingHandler::new(PrePairingResponse::RejectUnwantedRole);
        let server = Server::new_with_prepairing(
            ServerConfig {
                leaf_certificate: None,
                endpoint_description: S2EndpointDescription::default(),
                advertised_nodes: vec![],
            },
            test_handler.clone(),
        );
        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/preparePairing")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&PrePairingRequest {
                            client_s2_endpoint_description: S2EndpointDescription::default(),
                            client_s2_node_description: basic_node_description(UUID_A, S2Role::Cem),
                            server_id: None,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let response_data: PairingResponseErrorMessage = serde_json::from_slice(&body).unwrap();
        assert_eq!(response_data, PairingResponseErrorMessage::InvalidCombinationOfRoles);

        let endpoint = test_handler.endpoint.lock().unwrap().take().unwrap();
        let node = test_handler.node.lock().unwrap().take().unwrap();
        let target_node = test_handler.target_node.lock().unwrap().take().unwrap();
        assert_eq!(endpoint.deployment, None);
        assert_eq!(node.role, S2Role::Cem);
        assert_eq!(node.id, UUID_A.into());
        assert_eq!(target_node, None);
    }

    #[tokio::test]
    async fn cancel_prepairing() {
        let test_handler = TestPrePairingHandler::new(PrePairingResponse::Accept);
        let server = Server::new_with_prepairing(
            ServerConfig {
                leaf_certificate: None,
                endpoint_description: S2EndpointDescription::default(),
                advertised_nodes: vec![],
            },
            test_handler.clone(),
        );
        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/cancelPreparePairing")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&CancelPrePairingRequest {
                            client_id: UUID_B.into(),
                            server_id: None,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let client_id = test_handler.client_id.lock().unwrap().take().unwrap();
        let target_node = test_handler.target_node.lock().unwrap().take().unwrap();
        assert_eq!(client_id, UUID_B.into());
        assert_eq!(target_node, None);
    }

    #[tokio::test]
    async fn pair_attempt() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });
        let pairing_waiter = server
            .pair_once(
                Arc::new(
                    NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                        .with_connection_initiate_url("https://example.com/".into())
                        .build()
                        .unwrap(),
                ),
                Some(pairing_s2_node_id()),
                PairingToken(b"testtoken".as_slice().into()),
            )
            .unwrap();

        let challenge = HmacChallenge::new(&mut rand::rng(), 64);
        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/requestPairing")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&RequestPairing {
                            node_description: basic_node_description(UUID_B, S2Role::Cem),
                            endpoint_description: S2EndpointDescription::default(),
                            id: Some(pairing_s2_node_id()),
                            supported_protocols: vec![CommunicationProtocol("WebSocket".into())],
                            supported_versions: vec![MessageVersion("v1".into())],
                            supported_hashing_algorithms: vec![HmacHashingAlgorithm::Sha256],
                            client_hmac_challenge: challenge.clone(),
                            force_pairing: false,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let response_data: RequestPairingResponse = serde_json::from_slice(&body).unwrap();
        let expected_response = challenge.sha256(&Network::Wan, b"testtoken");
        assert_eq!(expected_response, response_data.client_hmac_challenge_response);
    }

    #[tokio::test]
    async fn pair_attempt_no_common_communication() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });
        let pairing_waiter = server
            .pair_once(
                Arc::new(
                    NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                        .with_connection_initiate_url("https://example.com/".into())
                        .build()
                        .unwrap(),
                ),
                Some(pairing_s2_node_id()),
                PairingToken(b"testtoken".as_slice().into()),
            )
            .unwrap();

        let challenge = HmacChallenge::new(&mut rand::rng(), 64);
        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/requestPairing")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&RequestPairing {
                            node_description: basic_node_description(UUID_B, S2Role::Cem),
                            endpoint_description: S2EndpointDescription::default(),
                            id: Some(pairing_s2_node_id()),
                            supported_protocols: vec![CommunicationProtocol("HTTP/3".into())],
                            supported_versions: vec![MessageVersion("v1".into())],
                            supported_hashing_algorithms: vec![HmacHashingAlgorithm::Sha256],
                            client_hmac_challenge: challenge.clone(),
                            force_pairing: false,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let error: PairingResponseErrorMessage = serde_json::from_slice(&body).unwrap();
        assert_eq!(error, PairingResponseErrorMessage::IncompatibleCommunicationProtocols);
    }

    #[tokio::test]
    async fn pair_attempt_no_common_messages() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });
        let pairing_waiter = server
            .pair_once(
                Arc::new(
                    NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                        .with_connection_initiate_url("https://example.com/".into())
                        .build()
                        .unwrap(),
                ),
                Some(pairing_s2_node_id()),
                PairingToken(b"testtoken".as_slice().into()),
            )
            .unwrap();

        let challenge = HmacChallenge::new(&mut rand::rng(), 64);
        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/requestPairing")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&RequestPairing {
                            node_description: basic_node_description(UUID_B, S2Role::Cem),
                            endpoint_description: S2EndpointDescription::default(),
                            id: Some(pairing_s2_node_id()),
                            supported_protocols: vec![CommunicationProtocol("WebSocket".into())],
                            supported_versions: vec![MessageVersion("v0".into())],
                            supported_hashing_algorithms: vec![HmacHashingAlgorithm::Sha256],
                            client_hmac_challenge: challenge.clone(),
                            force_pairing: false,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let error: PairingResponseErrorMessage = serde_json::from_slice(&body).unwrap();
        assert_eq!(error, PairingResponseErrorMessage::IncompatibleS2MessageVersions);
    }

    #[tokio::test]
    async fn pair_attempt_forced() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });
        let pairing_waiter = server
            .pair_once(
                Arc::new(
                    NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                        .with_connection_initiate_url("https://example.com/".into())
                        .build()
                        .unwrap(),
                ),
                Some(pairing_s2_node_id()),
                PairingToken(b"testtoken".as_slice().into()),
            )
            .unwrap();

        let challenge = HmacChallenge::new(&mut rand::rng(), 64);
        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/requestPairing")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&RequestPairing {
                            node_description: basic_node_description(UUID_B, S2Role::Cem),
                            endpoint_description: S2EndpointDescription::default(),
                            id: Some(pairing_s2_node_id()),
                            supported_protocols: vec![CommunicationProtocol("HTTP/3".into())],
                            supported_versions: vec![MessageVersion("v0".into())],
                            supported_hashing_algorithms: vec![HmacHashingAlgorithm::Sha256],
                            client_hmac_challenge: challenge.clone(),
                            force_pairing: true,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let response_data: RequestPairingResponse = serde_json::from_slice(&body).unwrap();
        let expected_response = challenge.sha256(&Network::Wan, b"testtoken");
        assert_eq!(expected_response, response_data.client_hmac_challenge_response);
    }

    #[tokio::test]
    async fn pair_attempt_with_unknown_node() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });

        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/requestPairing")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&RequestPairing {
                            node_description: basic_node_description(UUID_A, S2Role::Cem),
                            endpoint_description: S2EndpointDescription::default(),
                            id: Some(pairing_s2_node_id()),
                            supported_protocols: vec![CommunicationProtocol("WebSocket".into())],
                            supported_versions: vec![MessageVersion("v1".into())],
                            supported_hashing_algorithms: vec![HmacHashingAlgorithm::Sha256],
                            client_hmac_challenge: HmacChallenge::new(&mut rand::rng(), 64),
                            force_pairing: false,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let error: PairingResponseErrorMessage = serde_json::from_slice(&body).unwrap();
        assert_eq!(error, PairingResponseErrorMessage::S2NodeNotFound);
    }

    #[tokio::test]
    async fn pair_attempt_same_role() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });
        let pairing_waiter = server
            .pair_once(
                Arc::new(
                    NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                        .with_connection_initiate_url("https://example.com/".into())
                        .build()
                        .unwrap(),
                ),
                Some(pairing_s2_node_id()),
                PairingToken(b"testtoken".as_slice().into()),
            )
            .unwrap();

        let challenge = HmacChallenge::new(&mut rand::rng(), 64);
        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/requestPairing")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&RequestPairing {
                            node_description: basic_node_description(UUID_B, S2Role::Rm),
                            endpoint_description: S2EndpointDescription::default(),
                            id: Some(pairing_s2_node_id()),
                            supported_protocols: vec![CommunicationProtocol("WebSocket".into())],
                            supported_versions: vec![MessageVersion("v1".into())],
                            supported_hashing_algorithms: vec![HmacHashingAlgorithm::Sha256],
                            client_hmac_challenge: challenge.clone(),
                            force_pairing: false,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = dbg!(response.into_body().collect().await.unwrap().to_bytes());
        let error: PairingResponseErrorMessage = serde_json::from_slice(&body).unwrap();
        assert_eq!(error, PairingResponseErrorMessage::InvalidCombinationOfRoles);
    }

    #[tokio::test]
    async fn request_connection_details() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });
        let mut attempts = server.state.attempts.lock().unwrap();
        let (sender, _receiver) = tokio::sync::oneshot::channel();
        let challenge = HmacChallenge::new(&mut rand::rng(), 64);
        attempts.insert(
            PairingAttemptId("testid".into()),
            ExpiringPairingState {
                start_time: Instant::now(),
                state: PairingState::Initial(InitialPairingState {
                    session_span: span!(Level::TRACE, "testspan"),
                    config: Arc::new(
                        NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                            .with_connection_initiate_url("https://example.com/".into())
                            .build()
                            .unwrap(),
                    ),
                    sender: ResultSender::Oneshot(sender),
                    challenge: challenge.clone(),
                    token: PairingToken(b"testtoken".as_slice().into()),
                    remote_node_description: basic_node_description(UUID_B, S2Role::Cem),
                    remote_endpoint_description: S2EndpointDescription::default(),
                }),
            },
        );
        drop(attempts);

        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/requestConnectionDetails")
                    .header(http::header::AUTHORIZATION, "Bearer testid")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&RequestConnectionDetailsRequest {
                            server_hmac_challenge_response: challenge.sha256(&Network::Wan, b"testtoken"),
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let response_data: ConnectionDetails = serde_json::from_slice(&body).unwrap();
        assert_eq!(response_data.initiate_connection_url, "https://example.com/")
    }

    #[tokio::test]
    async fn request_connection_details_invalid_response() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });
        let mut attempts = server.state.attempts.lock().unwrap();
        let (sender, _receiver) = tokio::sync::oneshot::channel();
        let challenge = HmacChallenge::new(&mut rand::rng(), 64);
        attempts.insert(
            PairingAttemptId("testid".into()),
            ExpiringPairingState {
                start_time: Instant::now(),
                state: PairingState::Initial(InitialPairingState {
                    session_span: span!(Level::TRACE, "testspan"),
                    config: Arc::new(
                        NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                            .with_connection_initiate_url("https://example.com/".into())
                            .build()
                            .unwrap(),
                    ),
                    sender: ResultSender::Oneshot(sender),
                    challenge: challenge.clone(),
                    token: PairingToken(b"testtoken".as_slice().into()),
                    remote_node_description: basic_node_description(UUID_B, S2Role::Cem),
                    remote_endpoint_description: S2EndpointDescription::default(),
                }),
            },
        );
        drop(attempts);

        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/requestConnectionDetails")
                    .header(http::header::AUTHORIZATION, "Bearer testid")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&RequestConnectionDetailsRequest {
                            server_hmac_challenge_response: challenge.sha256(&Network::Wan, b"testtoken2"),
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test(start_paused = true)]
    async fn request_connection_details_too_late() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });
        let mut attempts = server.state.attempts.lock().unwrap();
        let (sender, _receiver) = tokio::sync::oneshot::channel();
        let challenge = HmacChallenge::new(&mut rand::rng(), 64);
        attempts.insert(
            PairingAttemptId("testid".into()),
            ExpiringPairingState {
                start_time: Instant::now(),
                state: PairingState::Initial(InitialPairingState {
                    session_span: span!(Level::TRACE, "testspan"),
                    config: Arc::new(
                        NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                            .with_connection_initiate_url("https://example.com/".into())
                            .build()
                            .unwrap(),
                    ),
                    sender: ResultSender::Oneshot(sender),
                    challenge: challenge.clone(),
                    token: PairingToken(b"testtoken".as_slice().into()),
                    remote_node_description: basic_node_description(UUID_B, S2Role::Cem),
                    remote_endpoint_description: S2EndpointDescription::default(),
                }),
            },
        );
        drop(attempts);

        tokio::time::sleep(std::time::Duration::from_secs(16)).await;

        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/requestConnectionDetails")
                    .header(http::header::AUTHORIZATION, "Bearer testid")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&RequestConnectionDetailsRequest {
                            server_hmac_challenge_response: challenge.sha256(&Network::Wan, b"testtoken"),
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn post_connection_details() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });
        let mut attempts = server.state.attempts.lock().unwrap();
        let (sender, _receiver) = tokio::sync::oneshot::channel();
        let challenge = HmacChallenge::new(&mut rand::rng(), 64);
        attempts.insert(
            PairingAttemptId("testid".into()),
            ExpiringPairingState {
                start_time: Instant::now(),
                state: PairingState::Initial(InitialPairingState {
                    session_span: span!(Level::TRACE, "testspan"),
                    config: Arc::new(
                        NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                            .with_connection_initiate_url("https://example.com/".into())
                            .build()
                            .unwrap(),
                    ),
                    sender: ResultSender::Oneshot(sender),
                    challenge: challenge.clone(),
                    token: PairingToken(b"testtoken".as_slice().into()),
                    remote_node_description: basic_node_description(UUID_B, S2Role::Cem),
                    remote_endpoint_description: S2EndpointDescription::default(),
                }),
            },
        );
        drop(attempts);

        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/postConnectionDetails")
                    .header(http::header::AUTHORIZATION, "Bearer testid")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&PostConnectionDetailsRequest {
                            server_hmac_challenge_response: challenge.sha256(&Network::Wan, b"testtoken"),
                            connection_details: ConnectionDetails {
                                initiate_connection_url: "https://example.com/".into(),
                                access_token: AccessToken::new(&mut rand::rng()),
                            },
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn post_connection_details_invalid_response() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });
        let mut attempts = server.state.attempts.lock().unwrap();
        let (sender, _receiver) = tokio::sync::oneshot::channel();
        let challenge = HmacChallenge::new(&mut rand::rng(), 64);
        attempts.insert(
            PairingAttemptId("testid".into()),
            ExpiringPairingState {
                start_time: Instant::now(),
                state: PairingState::Initial(InitialPairingState {
                    session_span: span!(Level::TRACE, "testspan"),
                    config: Arc::new(
                        NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                            .with_connection_initiate_url("https://example.com/".into())
                            .build()
                            .unwrap(),
                    ),
                    sender: ResultSender::Oneshot(sender),
                    challenge: challenge.clone(),
                    token: PairingToken(b"testtoken".as_slice().into()),
                    remote_node_description: basic_node_description(UUID_B, S2Role::Cem),
                    remote_endpoint_description: S2EndpointDescription::default(),
                }),
            },
        );
        drop(attempts);

        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/postConnectionDetails")
                    .header(http::header::AUTHORIZATION, "Bearer testid")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&PostConnectionDetailsRequest {
                            server_hmac_challenge_response: challenge.sha256(&Network::Wan, b"testtoken2"),
                            connection_details: ConnectionDetails {
                                initiate_connection_url: "https://example.com/".into(),
                                access_token: AccessToken::new(&mut rand::rng()),
                            },
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test(start_paused = true)]
    async fn post_connection_details_too_late() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });
        let mut attempts = server.state.attempts.lock().unwrap();
        let (sender, _receiver) = tokio::sync::oneshot::channel();
        let challenge = HmacChallenge::new(&mut rand::rng(), 64);
        attempts.insert(
            PairingAttemptId("testid".into()),
            ExpiringPairingState {
                start_time: Instant::now(),
                state: PairingState::Initial(InitialPairingState {
                    session_span: span!(Level::TRACE, "testspan"),
                    config: Arc::new(
                        NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                            .with_connection_initiate_url("https://example.com/".into())
                            .build()
                            .unwrap(),
                    ),
                    sender: ResultSender::Oneshot(sender),
                    challenge: challenge.clone(),
                    token: PairingToken(b"testtoken".as_slice().into()),
                    remote_node_description: basic_node_description(UUID_B, S2Role::Cem),
                    remote_endpoint_description: S2EndpointDescription::default(),
                }),
            },
        );
        drop(attempts);

        tokio::time::sleep(std::time::Duration::from_secs(16)).await;

        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/postConnectionDetails")
                    .header(http::header::AUTHORIZATION, "Bearer testid")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&PostConnectionDetailsRequest {
                            server_hmac_challenge_response: challenge.sha256(&Network::Wan, b"testtoken"),
                            connection_details: ConnectionDetails {
                                initiate_connection_url: "https://example.com/".into(),
                                access_token: AccessToken::new(&mut rand::rng()),
                            },
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn finalize() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });
        let mut attempts = server.state.attempts.lock().unwrap();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let challenge = HmacChallenge::new(&mut rand::rng(), 64);
        attempts.insert(
            PairingAttemptId("testid".into()),
            ExpiringPairingState {
                start_time: Instant::now(),
                state: PairingState::Complete(CompletePairingState {
                    session_span: span!(Level::TRACE, "testspan"),
                    sender: ResultSender::Oneshot(sender),
                    remote_node_description: basic_node_description(UUID_B, S2Role::Cem),
                    remote_endpoint_description: S2EndpointDescription::default(),
                    access_token: AccessToken::new(&mut rand::rng()),
                    role: PairingRole::CommunicationServer,
                }),
            },
        );
        drop(attempts);

        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/finalizePairing")
                    .header(http::header::AUTHORIZATION, "Bearer testid")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&true).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let outcome = receiver.await.unwrap().unwrap();
        assert_eq!(outcome.role, PairingRole::CommunicationServer);
    }

    #[tokio::test]
    async fn finalize_cancel() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });
        let mut attempts = server.state.attempts.lock().unwrap();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let challenge = HmacChallenge::new(&mut rand::rng(), 64);
        attempts.insert(
            PairingAttemptId("testid".into()),
            ExpiringPairingState {
                start_time: Instant::now(),
                state: PairingState::Complete(CompletePairingState {
                    session_span: span!(Level::TRACE, "testspan"),
                    sender: ResultSender::Oneshot(sender),
                    remote_node_description: basic_node_description(UUID_B, S2Role::Cem),
                    remote_endpoint_description: S2EndpointDescription::default(),
                    access_token: AccessToken::new(&mut rand::rng()),
                    role: PairingRole::CommunicationServer,
                }),
            },
        );
        drop(attempts);

        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/finalizePairing")
                    .header(http::header::AUTHORIZATION, "Bearer testid")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&false).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let outcome = receiver.await.unwrap().unwrap_err();
        assert_eq!(outcome.kind(), ErrorKind::Cancelled);
    }

    #[tokio::test]
    async fn finalize_cancel_at_intermediate() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });
        let mut attempts = server.state.attempts.lock().unwrap();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let challenge = HmacChallenge::new(&mut rand::rng(), 64);
        attempts.insert(
            PairingAttemptId("testid".into()),
            ExpiringPairingState {
                start_time: Instant::now(),
                state: PairingState::Initial(InitialPairingState {
                    session_span: span!(Level::TRACE, "testspan"),
                    config: Arc::new(
                        NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                            .with_connection_initiate_url("https://example.com/".into())
                            .build()
                            .unwrap(),
                    ),
                    sender: ResultSender::Oneshot(sender),
                    challenge: challenge.clone(),
                    token: PairingToken(b"testtoken".as_slice().into()),
                    remote_node_description: basic_node_description(UUID_B, S2Role::Cem),
                    remote_endpoint_description: S2EndpointDescription::default(),
                }),
            },
        );
        drop(attempts);

        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/finalizePairing")
                    .header(http::header::AUTHORIZATION, "Bearer testid")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&false).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let outcome = receiver.await.unwrap().unwrap_err();
        assert_eq!(outcome.kind(), ErrorKind::Cancelled);
    }

    #[tokio::test]
    async fn finalize_unknown_session() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });

        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/finalizePairing")
                    .header(http::header::AUTHORIZATION, "Bearer testid")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&true).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn finalize_cancel_unknown_session() {
        let server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });

        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/finalizePairing")
                    .header(http::header::AUTHORIZATION, "Bearer testid")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&false).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test(start_paused = true)]
    async fn longpolling_timeout() {
        let mut server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });

        server.enable_longpolling().await;

        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/waitForPairing")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&vec![WaitForPairingRequest {
                            client_s2_node_id: UUID_A.into(),
                            client_s2_node_description: None,
                            client_s2_endpoint_description: None,
                            error_message: None,
                        }])
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn longpolling_descriptions() {
        let mut server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });

        server.enable_longpolling().await;

        let server_clone = server.clone();

        let client_task = async move {
            let response = server_clone
                .get_router()
                .oneshot(
                    http::Request::post("/v1/waitForPairing")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&vec![WaitForPairingRequest {
                                client_s2_node_id: UUID_A.into(),
                                client_s2_node_description: None,
                                client_s2_endpoint_description: None,
                                error_message: None,
                            }])
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let response_data: WaitForPairingResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(response_data.client_s2_node_id, UUID_A.into());
            assert_eq!(response_data.action, WaitForPairingAction::SendS2NodeDescription);

            server_clone
                .get_router()
                .oneshot(
                    http::Request::post("/v1/waitForPairing")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&vec![WaitForPairingRequest {
                                client_s2_node_id: UUID_A.into(),
                                client_s2_node_description: Some(basic_node_description(UUID_A, S2Role::Cem)),
                                client_s2_endpoint_description: Some(S2EndpointDescription::default()),
                                error_message: None,
                            }])
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
        };

        let server_task = async move {
            let mut longpolling_handle = server.get_longpolling().await;
            assert_eq!(
                longpolling_handle.node_description().await.unwrap(),
                basic_node_description(UUID_A, S2Role::Cem)
            );
            assert_eq!(
                longpolling_handle.endpoint_description().await.unwrap(),
                S2EndpointDescription::default()
            );
        };

        join!(client_task, server_task);
    }

    #[tokio::test]
    async fn longpolling_prepare_pairing() {
        let mut server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });

        server.enable_longpolling().await;

        let server_clone = server.clone();

        let client_task = async move {
            let response = server_clone
                .get_router()
                .oneshot(
                    http::Request::post("/v1/waitForPairing")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&vec![WaitForPairingRequest {
                                client_s2_node_id: UUID_A.into(),
                                client_s2_node_description: None,
                                client_s2_endpoint_description: None,
                                error_message: None,
                            }])
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let response_data: WaitForPairingResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(response_data.client_s2_node_id, UUID_A.into());
            assert_eq!(response_data.action, WaitForPairingAction::PreparePairing);

            server_clone
                .get_router()
                .oneshot(
                    http::Request::post("/v1/waitForPairing")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&vec![WaitForPairingRequest {
                                client_s2_node_id: UUID_A.into(),
                                client_s2_node_description: None,
                                client_s2_endpoint_description: None,
                                error_message: None,
                            }])
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
        };

        let server_task = async move {
            let mut longpolling_handle = server.get_longpolling().await;
            assert!(longpolling_handle.prepare_pairing().await.is_ok());
        };

        join!(client_task, server_task);
    }

    #[tokio::test]
    async fn longpolling_cancel_prepare_pairing() {
        let mut server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });

        server.enable_longpolling().await;

        let server_clone = server.clone();

        let client_task = async move {
            let response = server_clone
                .get_router()
                .oneshot(
                    http::Request::post("/v1/waitForPairing")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&vec![WaitForPairingRequest {
                                client_s2_node_id: UUID_A.into(),
                                client_s2_node_description: None,
                                client_s2_endpoint_description: None,
                                error_message: None,
                            }])
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let response_data: WaitForPairingResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(response_data.client_s2_node_id, UUID_A.into());
            assert_eq!(response_data.action, WaitForPairingAction::CancelPreparePairing);

            server_clone
                .get_router()
                .oneshot(
                    http::Request::post("/v1/waitForPairing")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&vec![WaitForPairingRequest {
                                client_s2_node_id: UUID_A.into(),
                                client_s2_node_description: None,
                                client_s2_endpoint_description: None,
                                error_message: None,
                            }])
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
        };

        let server_task = async move {
            let mut longpolling_handle = server.get_longpolling().await;
            assert!(longpolling_handle.cancel_prepare_pairing().await.is_ok());
        };

        join!(client_task, server_task);
    }

    #[tokio::test]
    async fn longpolling_request_pairing_success() {
        let mut server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });

        server.enable_longpolling().await;

        let server_clone = server.clone();

        let client_task = async move {
            let response = server_clone
                .get_router()
                .oneshot(
                    http::Request::post("/v1/waitForPairing")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&vec![WaitForPairingRequest {
                                client_s2_node_id: UUID_A.into(),
                                client_s2_node_description: None,
                                client_s2_endpoint_description: None,
                                error_message: None,
                            }])
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let response_data: WaitForPairingResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(response_data.client_s2_node_id, UUID_A.into());
            assert_eq!(response_data.action, WaitForPairingAction::RequestPairing);

            let poll_req = server_clone.get_router().oneshot(
                http::Request::post("/v1/waitForPairing")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&vec![WaitForPairingRequest {
                            client_s2_node_id: UUID_A.into(),
                            client_s2_node_description: None,
                            client_s2_endpoint_description: None,
                            error_message: None,
                        }])
                        .unwrap(),
                    ))
                    .unwrap(),
            );
            let pair_req = server_clone.get_router().oneshot(
                http::Request::post("/v1/requestPairing")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&RequestPairing {
                            node_description: basic_node_description(UUID_A, S2Role::Cem),
                            endpoint_description: S2EndpointDescription::default(),
                            id: Some(pairing_s2_node_id()),
                            supported_protocols: vec![CommunicationProtocol("WebSocket".into())],
                            supported_versions: vec![MessageVersion("v1".into())],
                            supported_hashing_algorithms: vec![HmacHashingAlgorithm::Sha256],
                            client_hmac_challenge: HmacChallenge::new(&mut rand::rng(), 64),
                            force_pairing: false,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            );

            join!(poll_req, pair_req);
        };

        let server_task = async move {
            let mut longpolling_handle = server.get_longpolling().await;
            assert!(longpolling_handle.request_pairing().await.is_ok());
        };

        join!(client_task, server_task);
    }

    #[tokio::test]
    async fn longpolling_request_pairing_failure() {
        let mut server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });

        server.enable_longpolling().await;

        let server_clone = server.clone();

        let client_task = async move {
            let response = server_clone
                .get_router()
                .oneshot(
                    http::Request::post("/v1/waitForPairing")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&vec![WaitForPairingRequest {
                                client_s2_node_id: UUID_A.into(),
                                client_s2_node_description: None,
                                client_s2_endpoint_description: None,
                                error_message: None,
                            }])
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let response_data: WaitForPairingResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(response_data.client_s2_node_id, UUID_A.into());
            assert_eq!(response_data.action, WaitForPairingAction::RequestPairing);

            server_clone
                .get_router()
                .oneshot(
                    http::Request::post("/v1/waitForPairing")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&vec![WaitForPairingRequest {
                                client_s2_node_id: UUID_A.into(),
                                client_s2_node_description: None,
                                client_s2_endpoint_description: None,
                                error_message: Some(WaitForPairingErrorMessage::NoValidTokenOnPairingClient),
                            }])
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
        };

        let server_task = async move {
            let mut longpolling_handle = server.get_longpolling().await;
            assert_eq!(
                longpolling_handle.request_pairing().await.unwrap_err().kind(),
                ErrorKind::InvalidToken
            );
        };

        join!(client_task, server_task);
    }

    #[tokio::test(start_paused = true)]
    async fn longpolling_aborted_request_keeps_session_alive() {
        let mut server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });

        server.enable_longpolling().await;

        let server_clone = server.clone();

        let client_task = async move {
            assert!(
                timeout(
                    Duration::from_secs(5),
                    server_clone.get_router().oneshot(
                        http::Request::post("/v1/waitForPairing")
                            .header(http::header::CONTENT_TYPE, "application/json")
                            .body(Body::from(
                                serde_json::to_vec(&vec![WaitForPairingRequest {
                                    client_s2_node_id: UUID_A.into(),
                                    client_s2_node_description: None,
                                    client_s2_endpoint_description: None,
                                    error_message: None,
                                }])
                                .unwrap(),
                            ))
                            .unwrap(),
                    )
                )
                .await
                .is_err()
            );
            let response = server_clone
                .get_router()
                .oneshot(
                    http::Request::post("/v1/waitForPairing")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&vec![WaitForPairingRequest {
                                client_s2_node_id: UUID_A.into(),
                                client_s2_node_description: None,
                                client_s2_endpoint_description: None,
                                error_message: None,
                            }])
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let response_data: WaitForPairingResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(response_data.client_s2_node_id, UUID_A.into());
            assert_eq!(response_data.action, WaitForPairingAction::SendS2NodeDescription);

            server_clone
                .get_router()
                .oneshot(
                    http::Request::post("/v1/waitForPairing")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&vec![WaitForPairingRequest {
                                client_s2_node_id: UUID_A.into(),
                                client_s2_node_description: Some(basic_node_description(UUID_A, S2Role::Cem)),
                                client_s2_endpoint_description: Some(S2EndpointDescription::default()),
                                error_message: None,
                            }])
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
        };

        let server_task = async move {
            let mut longpolling_handle = server.get_longpolling().await;
            sleep(Duration::from_secs(10)).await;
            assert_eq!(
                longpolling_handle.node_description().await.unwrap(),
                basic_node_description(UUID_A, S2Role::Cem)
            );
            assert_eq!(
                longpolling_handle.endpoint_description().await.unwrap(),
                S2EndpointDescription::default()
            );
        };

        join!(client_task, server_task);
    }

    async fn longpolling_disable_during_request() {
        let mut server = Server::new(ServerConfig {
            leaf_certificate: None,
            endpoint_description: S2EndpointDescription::default(),
            advertised_nodes: vec![],
        });

        server.enable_longpolling().await;

        let server_clone = server.clone();

        let client_task = async move {
            let response = server_clone
                .get_router()
                .oneshot(
                    http::Request::post("/v1/waitForPairing")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&vec![WaitForPairingRequest {
                                client_s2_node_id: UUID_A.into(),
                                client_s2_node_description: None,
                                client_s2_endpoint_description: None,
                                error_message: None,
                            }])
                            .unwrap(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        };

        let server_task = async move {
            let mut longpolling_handle = server.get_longpolling().await;
            sleep(Duration::from_secs(5)).await;
            server.disable_longpolling().await;
        };

        join!(client_task, server_task);
    }
}
