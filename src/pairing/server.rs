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

use crate::pairing::{PairingRole, SUPPORTED_PAIRING_VERSIONS};

use super::{EndpointConfig, Error, Network, Pairing, PairingResult, S2EndpointDescription, S2NodeDescription, wire::*};

const PERMANENT_PAIRING_BUFFER_SIZE: usize = 1;

pub struct PairingToken(pub Box<[u8]>);

pub struct Server {
    state: AppState,
}

pub struct ServerConfig {
    /// The root certificate of the server, if we are using a self-signed root.
    /// Presence of this field indicates we are deployed on LAN.
    pub root_certificate: Option<CertificateDer<'static>>,
}

pub struct PendingPairing {
    receiver: tokio::sync::oneshot::Receiver<PairingResult<Pairing>>,
}

impl PendingPairing {
    pub async fn result(self) -> PairingResult<Pairing> {
        self.receiver.await.unwrap_or(Err(Error::Timeout))
    }
}

pub struct RepeatedPairing {
    receiver: tokio::sync::mpsc::Receiver<PairingResult<Pairing>>,
}

impl RepeatedPairing {
    pub async fn next(&mut self) -> Option<Pairing> {
        loop {
            if let Ok(pairing) = self.receiver.recv().await.transpose() {
                break pairing;
            }
        }
    }
}

impl Server {
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

    pub fn get_router(&self) -> axum::Router<()> {
        Router::new()
            .route("/", get(root))
            .nest("/v1", v1_router())
            .with_state(self.state.clone())
    }

    pub fn pair_once(&self, config: Arc<EndpointConfig>, pairing_token: PairingToken) -> Result<PendingPairing, Error> {
        if config.connection_initiate_url.is_none() {
            return Err(Error::InvalidConfig(super::ConfigError::MissingInitiateUrl));
        }

        let mut open_pairings = self.state.open_pairings.lock().unwrap();
        let mut permanent_pairings = self.state.permanent_pairings.lock().unwrap();
        if open_pairings.contains_key(&config.node_description.id) || permanent_pairings.contains_key(&config.node_description.id) {
            return Err(Error::AlreadyPending);
        }
        drop(permanent_pairings);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        open_pairings.insert(
            config.node_description.id.clone(),
            PairingRequest {
                config,
                sender: ResultSender::Oneshot(sender),
                token: pairing_token,
            },
        );
        Ok(PendingPairing { receiver })
    }

    pub fn pair_repeated(&self, config: Arc<EndpointConfig>, pairing_token: PairingToken) -> Result<RepeatedPairing, Error> {
        if config.connection_initiate_url.is_none() {
            return Err(Error::InvalidConfig(super::ConfigError::MissingInitiateUrl));
        }

        let mut open_pairings = self.state.open_pairings.lock().unwrap();
        let mut permanent_pairings = self.state.permanent_pairings.lock().unwrap();
        if open_pairings.contains_key(&config.node_description.id) || permanent_pairings.contains_key(&config.node_description.id) {
            return Err(Error::AlreadyPending);
        }
        drop(open_pairings);
        let (sender, receiver) = tokio::sync::mpsc::channel(PERMANENT_PAIRING_BUFFER_SIZE);
        permanent_pairings.insert(
            config.node_description.id.clone(),
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
    config: Arc<EndpointConfig>,
    sender: tokio::sync::mpsc::Sender<PairingResult<Pairing>>,
    token: PairingToken,
}

struct PairingRequest {
    config: Arc<EndpointConfig>,
    sender: ResultSender,
    token: PairingToken,
}

struct InitialPairingState {
    config: Arc<EndpointConfig>,
    sender: ResultSender,
    challenge: HmacChallenge,
    token: PairingToken,
    remote_node_description: S2NodeDescription,
    remote_endpoint_description: S2EndpointDescription,
}
struct CompletePairingState {
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

async fn root() -> Json<&'static [PairingVersion]> {
    Json(SUPPORTED_PAIRING_VERSIONS)
}

fn v1_router() -> Router<AppState> {
    Router::new()
        .route("/requestPairing", post(v1_request_pairing))
        .route("/requestConnectionDetails", post(v1_request_connection_details))
        .route("/postConnectionDetails", post(v1_post_connection_details))
        .route("/finalizePairing", post(v1_finalize_pairing))
}

async fn v1_request_pairing(
    State(state): State<AppState>,
    Json(request_pairing): Json<RequestPairing>,
) -> Result<Json<RequestPairingResponse>, Json<PairingResponseErrorMessage>> {
    if !request_pairing.supported_hashing_algorithms.contains(&HmacHashingAlgorithm::Sha256) {
        return Err(PairingResponseErrorMessage::IncompatibleHMACHashingAlgorithms.into());
    }

    let mut rng = rand::rng();
    let server_hmac_challenge = HmacChallenge::new(&mut rng);

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

    if !request_pairing.force_pairing {
        let mut communication_overlap = false;
        for communication_protocol in &open_pairing.config.supported_communication_protocols {
            if request_pairing.supported_protocols.contains(communication_protocol) {
                communication_overlap = true;
                break;
            }
        }
        if !communication_overlap {
            return Err(PairingResponseErrorMessage::IncompatibleCommunicationProtocols.into());
        }
        let mut connection_overlap = false;
        for connection_protocol in &open_pairing.config.supported_message_versions {
            if request_pairing.supported_versions.contains(connection_protocol) {
                connection_overlap = true;
                break;
            }
        }
        if !connection_overlap {
            return Err(PairingResponseErrorMessage::IncompatibleS2MessageVersions.into());
        }
    }

    let client_hmac_challenge_response = request_pairing.client_hmac_challenge.sha256(&state.network, &open_pairing.token.0);

    let pairing_attempt_id = {
        let mut attempts = state.attempts.lock().unwrap();
        loop {
            let id = PairingAttemptId::new(&mut rng);
            if !attempts.contains_key(&id) {
                attempts.insert(
                    id.clone(),
                    ExpiringPairingState {
                        start_time: Instant::now(),
                        state: PairingState::Initial(InitialPairingState {
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

async fn v1_request_connection_details(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RequestConnectionDetailsRequest>,
) -> Result<Json<ConnectionDetails>, StatusCode> {
    let Some(pairing_attempt_id) = PairingAttemptId::from_headers(&headers) else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    // We do this with a closure to drop attempts before we run the future for sending results to the caller, if it is present.
    let (result, future) = (|| {
        let mut attempts = app_state.attempts.lock().unwrap();
        let Some(state) = attempts.get_mut(&pairing_attempt_id) else {
            return (Err(StatusCode::UNAUTHORIZED), None);
        };

        if let Some(state_entry) = state.get_state()
            && let PairingState::Initial(state) = std::mem::replace(state_entry, PairingState::Empty)
        {
            let expected = state.challenge.sha256(&app_state.network, &state.token.0);
            if expected != req.server_hmac_challenge_response {
                attempts.remove(&pairing_attempt_id);
                return (Err(StatusCode::FORBIDDEN), Some(state.sender.send(Err(Error::InvalidToken))));
            }

            let mut rng = rand::rng();
            let connection_details = ConnectionDetails {
                initiate_connection_url: match &state.config.connection_initiate_url {
                    Some(url) => url.clone(),
                    None => return (Err(StatusCode::BAD_REQUEST), None),
                },
                access_token: AccessToken::new(&mut rng),
            };

            *state_entry = PairingState::Complete(CompletePairingState {
                sender: state.sender,
                remote_node_description: state.remote_node_description,
                remote_endpoint_description: state.remote_endpoint_description,
                access_token: connection_details.access_token.clone(),
                role: PairingRole::CommunicationServer,
            });

            (Ok(Json(connection_details)), None)
        } else {
            attempts.remove(&pairing_attempt_id);
            (Err(StatusCode::UNAUTHORIZED), None)
        }
    })();

    if let Some(future) = future {
        future.await;
    }

    result
}

async fn v1_post_connection_details(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PostConnectionDetailsRequest>,
) -> StatusCode {
    let Some(pairing_attempt_id) = PairingAttemptId::from_headers(&headers) else {
        return StatusCode::UNAUTHORIZED;
    };

    // We do this with a closure to drop attempts before we run the future for sending results to the caller, if it is present.
    let (result, future) = (|| {
        let mut attempts: std::sync::MutexGuard<'_, HashMap<PairingAttemptId, ExpiringPairingState>> = app_state.attempts.lock().unwrap();
        let Some(state) = attempts.get_mut(&pairing_attempt_id) else {
            return (StatusCode::UNAUTHORIZED, None);
        };

        if let Some(state_entry) = state.get_state()
            && let PairingState::Initial(state) = std::mem::replace(state_entry, PairingState::Empty)
        {
            let expected = state.challenge.sha256(&app_state.network, &state.token.0);
            if expected != req.server_hmac_challenge_response {
                attempts.remove(&pairing_attempt_id);
                return (StatusCode::FORBIDDEN, Some(state.sender.send(Err(Error::InvalidToken))));
            }

            // Do better error handling here than unwrap
            *state_entry = PairingState::Complete(CompletePairingState {
                sender: state.sender,
                remote_node_description: state.remote_node_description,
                remote_endpoint_description: state.remote_endpoint_description,
                access_token: req.connection_details.access_token,
                role: PairingRole::CommunicationClient {
                    initiate_url: req.connection_details.initiate_connection_url,
                },
            });

            (StatusCode::NO_CONTENT, None)
        } else {
            attempts.remove(&pairing_attempt_id);
            (StatusCode::UNAUTHORIZED, None)
        }
    })();

    if let Some(future) = future {
        future.await;
    }

    result
}

async fn v1_finalize_pairing(State(state): State<AppState>, headers: HeaderMap, Json(success): Json<bool>) -> StatusCode {
    let Some(pairing_attempt_id) = PairingAttemptId::from_headers(&headers) else {
        return StatusCode::UNAUTHORIZED;
    };

    let Some(state) = ({
        let mut attempts = state.attempts.lock().unwrap();
        attempts.remove(&pairing_attempt_id)
    }) else {
        return StatusCode::UNAUTHORIZED;
    };

    if let Some(state) = state.into_state() {
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

                StatusCode::NO_CONTENT
            } else {
                StatusCode::BAD_REQUEST
            }
        } else {
            match state {
                PairingState::Empty => { /* should never happen, but fine to ignore */ }
                PairingState::Initial(InitialPairingState { sender, .. }) | PairingState::Complete(CompletePairingState { sender, .. }) => {
                    sender.send(Err(Error::Cancelled)).await;
                }
            }

            StatusCode::NO_CONTENT
        }
    } else {
        StatusCode::UNAUTHORIZED
    }
}
