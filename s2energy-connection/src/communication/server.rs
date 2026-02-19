use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use reqwest::StatusCode;

use crate::{
    CommunicationProtocol, MessageVersion, S2EndpointDescription, S2NodeDescription, S2NodeId,
    common::{root, wire::AccessToken},
    communication::{
        NodeConfig,
        wire::{
            CommunicationDetails, CommunicationDetailsErrorMessage, CommunicationToken, InitiateConnectionRequest,
            InitiateConnectionResponse, WebSocketCommunicationDetails,
        },
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// A pairing to be looked up.
pub struct PairingLookup {
    /// Identifier of the remote end of the pairing
    pub client: S2NodeId,
    /// Identifier of the local end of the pairing
    pub server: S2NodeId,
}

/// Result of looking up a pairing
pub enum PairingLookupResult<Pairing> {
    /// Pairing exists
    Pairing(Pairing),
    /// Pairing existed in the past, but has recently unpaired
    Unpaired,
    /// Pairing never existed, or existed so long ago that that is no longer known.
    NeverPaired,
}

pub trait ServerPairingStore: Sync + Send + 'static {
    type Error: std::error::Error;
    type Pairing<'a>: ServerPairing<Error = Self::Error> + 'a
    where
        Self: 'a;

    fn lookup(&self, request: PairingLookup) -> impl Future<Output = Result<PairingLookupResult<Self::Pairing<'_>>, Self::Error>> + Send;
}

pub trait ServerPairing: Send {
    type Error: std::error::Error;

    fn access_token(&self) -> impl AsRef<AccessToken>;
    fn config(&self) -> impl AsRef<NodeConfig>;

    fn set_access_token(&mut self, token: AccessToken) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn update_remote_node_description(&mut self, node_description: S2NodeDescription) -> impl Future<Output = ()> + Send;
    fn update_remote_endpoint_description(&mut self, endpoint_description: S2EndpointDescription) -> impl Future<Output = ()> + Send;
}

/// Configuration for the S2 connection server.
pub struct ServerConfig {
    /// URL at which the communication server is reachable.
    pub base_url: String,
    pub endpoint_description: Option<S2EndpointDescription>,
}

pub struct Server<Store> {
    app_state: AppState<Store>,
}

type AppState<Store> = Arc<AppStateInner<Store>>;

struct AppStateInner<Store> {
    store: Store,
    pending_tokens: Mutex<HashMap<AccessToken, ExpiringSession>>,
    base_url: String,
    endpoint_description: Option<S2EndpointDescription>,
}

struct ExpiringSession {
    start_time: tokio::time::Instant,
    session: Session,
}

impl ExpiringSession {
    fn into_state(self) -> Option<Session> {
        if self.start_time.elapsed() > Duration::from_secs(15) {
            None
        } else {
            Some(self.session)
        }
    }
}

#[expect(unused)]
struct Session {
    lookup: PairingLookup,
    token: AccessToken,
    node_description: Option<S2NodeDescription>,
    endpoint_description: Option<S2EndpointDescription>,
    message_version: MessageVersion,
    communication_protocol: CommunicationProtocol,
}

impl<Store: ServerPairingStore> Server<Store> {
    pub fn new(config: ServerConfig, store: Store) -> Self {
        Server {
            app_state: Arc::new(AppStateInner {
                store,
                pending_tokens: Mutex::new(HashMap::new()),
                base_url: config.base_url,
                endpoint_description: config.endpoint_description,
            }),
        }
    }

    /// Get an [`axum::Router`] handling the endpoints for the communication protocol.
    ///
    /// Incomming http requests can be handled by this router through the [axum-server](https://docs.rs/axum-server/0.8.0/axum_server/) crate.
    pub fn get_router(&self) -> axum::Router<()> {
        Router::new()
            .route("/", get(root))
            .nest("/v1", v1_router())
            .with_state(self.app_state.clone())
    }
}

impl IntoResponse for CommunicationDetailsErrorMessage {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
}

impl IntoResponse for InitiateConnectionResponse {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

fn select_overlap<T: Eq + Clone>(primary: &[T], secondary: &[T]) -> Option<T> {
    for el in primary {
        if secondary.contains(el) {
            return Some(el.clone());
        }
    }

    None
}

fn v1_router<Store: ServerPairingStore>() -> Router<AppState<Store>> {
    Router::new()
        .route("/initiateConnection", post(v1_initiate_connection))
        .route("/confirmAccessToken", post(v1_confirm_access_token))
}

async fn v1_initiate_connection<Store: ServerPairingStore>(
    State(state): State<AppState<Store>>,
    token: AccessToken,
    Json(request): Json<InitiateConnectionRequest>,
) -> axum::response::Response {
    let lookup = PairingLookup {
        client: request.client_node_id,
        server: request.server_node_id,
    };

    let pairing = match state.store.lookup(lookup.clone()).await {
        Ok(PairingLookupResult::Pairing(pairing)) => pairing,
        Ok(PairingLookupResult::Unpaired) => return CommunicationDetailsErrorMessage::NoLongerPaired.into_response(),
        Ok(PairingLookupResult::NeverPaired) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if pairing.access_token().as_ref() != &token {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let config = pairing.config();

    let Some(communication_protocol) = select_overlap(
        &request.supported_communication_protocols,
        &[CommunicationProtocol("WebSocket".into())],
    ) else {
        return CommunicationDetailsErrorMessage::IncompatibleCommunicationProtocols.into_response();
    };
    let Some(message_version) = select_overlap(&request.supported_message_versions, config.as_ref().supported_message_versions()) else {
        return CommunicationDetailsErrorMessage::IncompatibleS2MessageVersions.into_response();
    };

    let mut pending_tokens = state.pending_tokens.lock().unwrap();

    // Collisions are unlikely but technically possible.
    let new_access_token = loop {
        let candidate = AccessToken::new(&mut rand::rng());
        if !pending_tokens.contains_key(&candidate) {
            break candidate;
        }
    };

    pending_tokens.insert(
        new_access_token.clone(),
        ExpiringSession {
            start_time: tokio::time::Instant::now(),
            session: Session {
                lookup,
                token,
                node_description: request.node_description,
                endpoint_description: request.endpoint_description,
                message_version: message_version.clone(),
                communication_protocol: communication_protocol.clone(),
            },
        },
    );

    InitiateConnectionResponse {
        communication_protocol,
        message_version,
        access_token: new_access_token,
        node_description: config.as_ref().node_description().cloned(),
        endpoint_description: state.endpoint_description.clone(),
    }
    .into_response()
}

impl IntoResponse for CommunicationDetails {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

async fn v1_confirm_access_token<Store: ServerPairingStore>(
    State(state): State<AppState<Store>>,
    token: AccessToken,
) -> Result<CommunicationDetails, StatusCode> {
    let session = {
        let mut pending_tokens = state.pending_tokens.lock().unwrap();
        pending_tokens
            .remove(&token)
            .and_then(|v| v.into_state())
            .ok_or(StatusCode::UNAUTHORIZED)?
    };

    let mut pairing = match state.store.lookup(session.lookup.clone()).await {
        Ok(PairingLookupResult::Pairing(pairing)) => pairing,
        Ok(PairingLookupResult::Unpaired | PairingLookupResult::NeverPaired) => return Err(StatusCode::UNAUTHORIZED),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    pairing
        .set_access_token(token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // TODO: Implement websocket communication
    Ok(CommunicationDetails::WebSocket(WebSocketCommunicationDetails {
        websocket_token: CommunicationToken::new(&mut rand::rng()),
        websocket_url: format!("wss://{}/v1/websocket", state.base_url),
    }))
}
