#![allow(unused)]
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use reqwest::StatusCode;
use rustls::pki_types::CertificateDer;
use sha2::Digest;
use tokio::time::Instant;
use tracing::{Instrument, info, trace};

use crate::{
    common::{
        root,
        wire::{AccessToken, PairingVersion, S2EndpointDescription, S2NodeDescription, S2NodeId},
    },
    pairing::PairingRole,
};

use super::{ErrorKind, Network, NodeConfig, Pairing, PairingResult, wire::*};

const PERMANENT_PAIRING_BUFFER_SIZE: usize = 1;

/// Token known to both S2 nodes trying to pair.
///
/// This token is used to validate the identity of the nodes.
pub struct PairingToken(pub Box<[u8]>);

/// Server for handling S2 pairing transactions.
///
/// Responsible for providing the HTTP endpoints needed for handling
pub struct Server {
    state: AppState,
}

/// Configuration for the S2 pairing server.
pub struct ServerConfig {
    /// The root certificate of the server, if we are using a self-signed root.
    /// Presence of this field indicates we are deployed on LAN.
    pub root_certificate: Option<CertificateDer<'static>>,
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

impl Server {
    /// Create a new server using the given configuration.
    pub fn new(server_config: ServerConfig) -> Self {
        let state = AppStateInner {
            network: server_config
                .root_certificate
                .map(|v| Network::Lan {
                    fingerprint: sha2::Sha256::digest(v).into(),
                })
                .unwrap_or(Network::Wan),
            permanent_pairings: Mutex::new(HashMap::new()),
            open_pairings: Mutex::new(HashMap::new()),
            attempts: Mutex::new(HashMap::default()),
        };

        Self { state: Arc::new(state) }
    }

    /// Get an [`axum::Router`] handling the endpoints for the pairing protocol.
    ///
    /// Incomming http requests can be handled by this router through the [axum-server](https://docs.rs/axum-server/0.8.0/axum_server/) crate.
    pub fn get_router(&self) -> axum::Router<()> {
        Router::new()
            .route("/", get(root))
            .nest("/v1", v1_router())
            .with_state(self.state.clone())
    }

    /// Start a one-time pairing session for the given node using the given token.
    pub fn pair_once(&self, config: Arc<NodeConfig>, pairing_token: PairingToken) -> Result<PendingPairing, ErrorKind> {
        if config.connection_initiate_url.is_none() {
            return Err(ErrorKind::InvalidConfig(super::ConfigError::MissingInitiateUrl));
        }

        let mut open_pairings = self.state.open_pairings.lock().unwrap();
        let mut permanent_pairings = self.state.permanent_pairings.lock().unwrap();
        if open_pairings.contains_key(&config.node_description.id) || permanent_pairings.contains_key(&config.node_description.id) {
            return Err(ErrorKind::AlreadyPending);
        }
        drop(permanent_pairings);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        open_pairings.insert(
            config.node_description.id,
            PairingRequest {
                config,
                sender: ResultSender::Oneshot(sender),
                token: pairing_token,
            },
        );
        Ok(PendingPairing { receiver })
    }

    /// Allow repeated pairing sessions for the given endpoing using the given token.
    pub fn pair_repeated(&self, config: Arc<NodeConfig>, pairing_token: PairingToken) -> Result<RepeatedPairing, ErrorKind> {
        if config.connection_initiate_url.is_none() {
            return Err(ErrorKind::InvalidConfig(super::ConfigError::MissingInitiateUrl));
        }

        let mut open_pairings = self.state.open_pairings.lock().unwrap();
        let mut permanent_pairings = self.state.permanent_pairings.lock().unwrap();
        if open_pairings.contains_key(&config.node_description.id) || permanent_pairings.contains_key(&config.node_description.id) {
            return Err(ErrorKind::AlreadyPending);
        }
        drop(open_pairings);
        let (sender, receiver) = tokio::sync::mpsc::channel(PERMANENT_PAIRING_BUFFER_SIZE);
        permanent_pairings.insert(
            config.node_description.id,
            PermanentPairingRequest {
                config,
                sender,
                token: pairing_token,
            },
        );
        Ok(RepeatedPairing { receiver })
    }
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

type AppState = Arc<AppStateInner>;

struct AppStateInner {
    // rng: ThreadRng,
    network: Network,
    permanent_pairings: Mutex<HashMap<S2NodeId, PermanentPairingRequest>>,
    open_pairings: Mutex<HashMap<S2NodeId, PairingRequest>>,
    attempts: Mutex<HashMap<PairingAttemptId, ExpiringPairingState>>,
}

fn v1_router() -> Router<AppState> {
    Router::new()
        .route("/requestPairing", post(v1_request_pairing))
        .route("/requestConnectionDetails", post(v1_request_connection_details))
        .route("/postConnectionDetails", post(v1_post_connection_details))
        .route("/finalizePairing", post(v1_finalize_pairing))
}

#[tracing::instrument(skip_all, level = tracing::Level::INFO)]
async fn v1_request_pairing(
    State(state): State<AppState>,
    Json(request_pairing): Json<RequestPairing>,
) -> Result<Json<RequestPairingResponse>, PairingResponseErrorMessage> {
    trace!("Received pairing request.");
    if !request_pairing.supported_hashing_algorithms.contains(&HmacHashingAlgorithm::Sha256) {
        info!(remote_hashing_algorithms = ?request_pairing.supported_hashing_algorithms, "No shared hashing algorithm with remote");
        return Err(PairingResponseErrorMessage::IncompatibleHMACHashingAlgorithms);
    }

    // 32 bytes is the minimum, this tests that the client can handle more.
    const HMAC_CHALLENGE_BYTES: usize = 64;

    let server_hmac_challenge = HmacChallenge::new(&mut rand::rng(), HMAC_CHALLENGE_BYTES);

    let open_pairing = {
        let mut open_pairings = state.open_pairings.lock().unwrap();
        if let Some((_, request)) = open_pairings.remove_entry(&request_pairing.id) {
            request
        } else {
            drop(open_pairings);
            let permanent_pairings = state.permanent_pairings.lock().unwrap();
            let entry = permanent_pairings
                .get(&request_pairing.id)
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
            server_s2_endpoint_description: open_pairing.config.endpoint_description.clone(),
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
async fn v1_request_connection_details(
    State(app_state): State<AppState>,
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
async fn v1_post_connection_details(
    State(app_state): State<AppState>,
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
async fn v1_finalize_pairing(State(state): State<AppState>, pairing_attempt_id: PairingAttemptId, Json(success): Json<bool>) -> StatusCode {
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
    use std::sync::Arc;

    use axum::body::Body;
    use http::StatusCode;
    use http_body_util::BodyExt;
    use tokio::time::Instant;
    use tower::ServiceExt;
    use tracing::{Level, span};

    use crate::{
        AccessToken, CommunicationProtocol, MessageVersion, S2EndpointDescription, S2NodeDescription, S2Role,
        common::wire::test::{UUID_A, UUID_B, basic_node_description},
        pairing::{
            ErrorKind, Network, NodeConfig, PairingRole, PairingToken, Server, ServerConfig,
            server::{CompletePairingState, ExpiringPairingState, InitialPairingState, PairingRequest, PairingState, ResultSender},
            wire::{
                ConnectionDetails, HmacChallenge, HmacHashingAlgorithm, PairingAttemptId, PairingResponseErrorMessage,
                PostConnectionDetailsRequest, RequestConnectionDetailsRequest, RequestPairing, RequestPairingResponse,
            },
        },
    };

    #[tokio::test]
    async fn version_negotiation() {
        let server = Server::new(ServerConfig { root_certificate: None });

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
    async fn pair_attempt() {
        let server = Server::new(ServerConfig { root_certificate: None });
        let pairing_waiter = server
            .pair_once(
                Arc::new(
                    NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                        .with_connection_initiate_url("https://example.com/".into())
                        .build()
                        .unwrap(),
                ),
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
                            id: UUID_A.into(),
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
        let server = Server::new(ServerConfig { root_certificate: None });
        let pairing_waiter = server
            .pair_once(
                Arc::new(
                    NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                        .with_connection_initiate_url("https://example.com/".into())
                        .build()
                        .unwrap(),
                ),
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
                            id: UUID_A.into(),
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
        let server = Server::new(ServerConfig { root_certificate: None });
        let pairing_waiter = server
            .pair_once(
                Arc::new(
                    NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                        .with_connection_initiate_url("https://example.com/".into())
                        .build()
                        .unwrap(),
                ),
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
                            id: UUID_A.into(),
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
        let server = Server::new(ServerConfig { root_certificate: None });
        let pairing_waiter = server
            .pair_once(
                Arc::new(
                    NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                        .with_connection_initiate_url("https://example.com/".into())
                        .build()
                        .unwrap(),
                ),
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
                            id: UUID_A.into(),
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
        let server = Server::new(ServerConfig { root_certificate: None });

        let response = server
            .get_router()
            .oneshot(
                http::Request::post("/v1/requestPairing")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&RequestPairing {
                            node_description: basic_node_description(UUID_A, S2Role::Cem),
                            endpoint_description: S2EndpointDescription::default(),
                            id: UUID_A.into(),
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
        let server = Server::new(ServerConfig { root_certificate: None });
        let pairing_waiter = server
            .pair_once(
                Arc::new(
                    NodeConfig::builder(basic_node_description(UUID_A, S2Role::Rm), vec![MessageVersion("v1".into())])
                        .with_connection_initiate_url("https://example.com/".into())
                        .build()
                        .unwrap(),
                ),
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
                            id: UUID_A.into(),
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
        let server = Server::new(ServerConfig { root_certificate: None });
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
        let server = Server::new(ServerConfig { root_certificate: None });
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
        let server = Server::new(ServerConfig { root_certificate: None });
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
        let server = Server::new(ServerConfig { root_certificate: None });
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
        let server = Server::new(ServerConfig { root_certificate: None });
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
        let server = Server::new(ServerConfig { root_certificate: None });
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
        let server = Server::new(ServerConfig { root_certificate: None });
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
        let server = Server::new(ServerConfig { root_certificate: None });
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
        let server = Server::new(ServerConfig { root_certificate: None });
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
        let server = Server::new(ServerConfig { root_certificate: None });

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
        let server = Server::new(ServerConfig { root_certificate: None });

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
}
