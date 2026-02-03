use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use reqwest::StatusCode;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock, RwLockReadGuard},
};
use tokio::net::TcpListener;

use s2energy::pairing::Network;
use s2energy::pairing::transport::*;

const PAIRING_TOKEN: &[u8] = &[1, 2, 3];

struct ClientState {
    // The pairing attempt must complete within 15 seconds.
    // start_time:
    hmac_challenge: HmacChallenge,
}
impl ClientState {
    fn has_expired(&self) -> bool {
        false
    }
}

type AppState = Arc<RwLock<AppStateInner>>;

struct AppStateInner {
    // rng: ThreadRng,
    attempts: HashMap<PairingAttemptId, ClientState>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let state = AppStateInner {
        // rng: rand::rng(),
        attempts: HashMap::default(),
    };

    let app = Router::new()
        .route("/", get(root))
        .nest("/v1", v1_router())
        .with_state(Arc::new(RwLock::new(state)));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8005));
    let listener = TcpListener::bind(addr).await.unwrap();

    println!("listening on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> Json<Vec<&'static str>> {
    Json(vec!["v1"])
}

fn v1_router() -> Router<AppState> {
    Router::new()
        .route("/requestPairing", post(v1_request_pairing))
        .route("/postConnectionDetails", post(v1_post_connection_details))
        .route("/finalizePairing", post(v1_finalize_pairing))
}

async fn v1_request_pairing(State(state): State<AppState>, Json(request_pairing): Json<RequestPairing>) -> Json<RequestPairingResponse> {
    let server_s2_node_description = S2NodeDescription {
        id: S2NodeId(String::from("12121212")),
        brand: String::from("super-reliable-corp"),
        logo_uri: None,
        type_: String::from("fancy"),
        model_name: String::from("the best"),
        user_defined_name: None,
        role: S2Role::Rm,
    };

    let mut rng = rand::rng();
    let server_hmac_challenge = HmacChallenge::new(&mut rng);

    // let network = Wan;
    let network = Network::Lan { fingerprint: [0; 32] };

    let client_hmac_challenge_response = request_pairing.client_hmac_challenge.sha256(&network, PAIRING_TOKEN);

    let pairing_attempt_id = {
        let mut writer = state.write().unwrap();
        loop {
            let id = PairingAttemptId::new(&mut rng);
            if !writer.attempts.contains_key(&id) {
                writer.attempts.insert(
                    id.clone(),
                    ClientState {
                        hmac_challenge: server_hmac_challenge.clone(),
                    },
                );
                break id;
            }
        }
    };

    let resp = RequestPairingResponse {
        pairing_attempt_id,
        server_s2_node_description,
        server_s2_endpoint_description: S2EndpointDescription {
            name: None,
            logo_uri: None,
            deployment: None,
        },
        selected_hmac_hashing_algorithm: HmacHashingAlgorithm::Sha256,
        client_hmac_challenge_response,
        server_hmac_challenge,
    };

    Json(resp)
}

async fn v1_post_connection_details(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PostConnectionDetailsRequest>,
) -> StatusCode {
    let Some(pairing_attempt_id) = PairingAttemptId::from_headers(&headers) else {
        return StatusCode::UNAUTHORIZED;
    };

    let reader = state.read().unwrap();

    let Some(client_state) = reader.attempts.get(&pairing_attempt_id) else {
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

    let reader = state.read().unwrap();

    let Some(client_state) = reader.attempts.get(&pairing_attempt_id) else {
        return StatusCode::UNAUTHORIZED;
    };

    if client_state.has_expired() {
        return StatusCode::UNAUTHORIZED;
    }

    StatusCode::NO_CONTENT
}
