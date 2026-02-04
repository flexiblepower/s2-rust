#![allow(unused)]
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use reqwest::StatusCode;
use tokio::time::Instant;

use super::{Config, Network, S2EndpointDescription, S2NodeDescription, transport::*};

pub struct Server {}

pub struct ServerConfig {}

pub struct PendingPairing {}

pub struct RepeatedPairing {}

impl Server {
    pub fn new(server_config: ServerConfig) -> Self {
        Self {}
    }

    pub fn get_router(&self) -> axum::Router<()> {
        let server_s2_node_description = S2NodeDescription {
            id: S2NodeId(String::from("12121212")),
            brand: String::from("super-reliable-corp"),
            logo_uri: None,
            type_: String::from("fancy"),
            model_name: String::from("the best"),
            user_defined_name: None,
            role: S2Role::Rm,
        };

        let state = AppStateInner {
            description: server_s2_node_description,
            attempts: RwLock::new(HashMap::default()),
        };

        Router::new()
            .route("/", get(root))
            .nest("/v1", v1_router())
            .with_state(Arc::new(state))
    }

    pub fn pair_once(&self, config: Arc<Config>, pairing_token: Vec<u8>) -> PendingPairing {
        todo!()
    }

    pub fn pair_repeated(&self, config: Arc<Config>, pairing_token: Vec<u8>) -> RepeatedPairing {
        todo!()
    }
}

const PAIRING_TOKEN: &[u8] = &[1, 2, 3];

struct ClientState {
    start_time: Instant,
    hmac_challenge: HmacChallenge,
}
impl ClientState {
    fn has_expired(&self) -> bool {
        self.start_time.elapsed() > Duration::from_secs(15)
    }
}

type AppState = Arc<AppStateInner>;

struct AppStateInner {
    // rng: ThreadRng,
    description: S2NodeDescription,
    attempts: RwLock<HashMap<PairingAttemptId, ClientState>>,
}

async fn root() -> Json<Vec<&'static str>> {
    Json(vec!["v1"])
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
    let mut rng = rand::rng();
    let server_hmac_challenge = HmacChallenge::new(&mut rng);

    let pairing_attempt_id = {
        let mut attempts = state.attempts.write().unwrap();
        loop {
            let id = PairingAttemptId::new(&mut rng);
            if !attempts.contains_key(&id) {
                attempts.insert(
                    id.clone(),
                    ClientState {
                        start_time: Instant::now(),
                        hmac_challenge: server_hmac_challenge.clone(),
                    },
                );
                break id;
            }
        }
    };

    // let network = Wan;
    let network = Network::Lan { fingerprint: [0; 32] };
    let client_hmac_challenge_response = request_pairing.client_hmac_challenge.sha256(&network, PAIRING_TOKEN);

    let resp = RequestPairingResponse {
        pairing_attempt_id,
        server_s2_node_description: state.description.clone(),
        server_s2_endpoint_description: S2EndpointDescription {
            name: None,
            logo_uri: None,
            deployment: None,
        },
        selected_hmac_hashing_algorithm: HmacHashingAlgorithm::Sha256,
        client_hmac_challenge_response,
        server_hmac_challenge,
    };

    Ok(Json(resp))
}

async fn v1_request_connection_details(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RequestConnectionDetailsRequest>,
) -> Result<Json<ConnectionDetails>, StatusCode> {
    let Some(pairing_attempt_id) = PairingAttemptId::from_headers(&headers) else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let attempts = state.attempts.read().unwrap();
    let Some(client_state) = attempts.get(&pairing_attempt_id) else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    if client_state.has_expired() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // let network = Network::Wan;
    let network = Network::Lan { fingerprint: [0; 32] };

    let expected = client_state.hmac_challenge.sha256(&network, PAIRING_TOKEN);
    if expected != req.server_hmac_challenge_response {
        todo!();
    }

    let mut rng = rand::rng();
    let connection_details = ConnectionDetails {
        initiate_connection_url: Some(String::from("example.com")),
        access_token: Some(AccessToken::new(&mut rng)),
    };

    Ok(Json(connection_details))
}

async fn v1_post_connection_details(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PostConnectionDetailsRequest>,
) -> StatusCode {
    let Some(pairing_attempt_id) = PairingAttemptId::from_headers(&headers) else {
        return StatusCode::UNAUTHORIZED;
    };

    let attempts = state.attempts.read().unwrap();
    let Some(client_state) = attempts.get(&pairing_attempt_id) else {
        return StatusCode::UNAUTHORIZED;
    };

    if client_state.has_expired() {
        return StatusCode::UNAUTHORIZED;
    }

    // let network = Network::Wan;
    let network = Network::Lan { fingerprint: [0; 32] };

    let expected = client_state.hmac_challenge.sha256(&network, PAIRING_TOKEN);
    if expected != req.server_hmac_challenge_response {
        todo!();
    }

    StatusCode::NO_CONTENT
}

async fn v1_finalize_pairing(State(state): State<AppState>, headers: HeaderMap, Json(_req): Json<bool>) -> StatusCode {
    let Some(pairing_attempt_id) = PairingAttemptId::from_headers(&headers) else {
        return StatusCode::UNAUTHORIZED;
    };

    let mut attempts = state.attempts.write().unwrap();
    let Some(client_state) = attempts.remove(&pairing_attempt_id) else {
        return StatusCode::UNAUTHORIZED;
    };

    if client_state.has_expired() {
        return StatusCode::UNAUTHORIZED;
    }

    StatusCode::NO_CONTENT
}
