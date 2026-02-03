use reqwest::Url;
use s2energy::pairing::{PairingState, Role, transport::*};

const PAIRING_TOKEN: &[u8] = &[1, 2, 3];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let node_description = S2NodeDescription {
        id: S2NodeId(String::from("12121212")),
        brand: String::from("super-reliable-corp"),
        logo_uri: None,
        type_: String::from("fancy"),
        model_name: String::from("the best"),
        user_defined_name: None,
        role: S2Role::Rm,
    };
    let endpoint_description = S2EndpointDescription {
        name: None,
        logo_uri: None,
        deployment: None,
    };
    let id = PairingS2NodeId(String::from("elfkje"));

    let url = Url::parse("http://127.0.0.1:8005").unwrap();
    let mut state = PairingState::init(
        url,
        Role::CommunicationServer {
            initiate_connection_url: Url::parse("http://fake.com").unwrap(),
            access_token: AccessToken(String::from("AABB")),
        },
        &[Version::V1],
        node_description,
        endpoint_description,
        id,
    )
    .await
    .unwrap();

    let mut rng = rand::rng();
    state.pair(&mut rng, &PAIRING_TOKEN).await.unwrap();
}
