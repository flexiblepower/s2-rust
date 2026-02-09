use reqwest::Url;
use s2energy::pairing::{Config, ConnectionVersion, PairingRemote, Role, S2EndpointDescription, S2NodeDescription, S2NodeId, S2Role, pair};

const PAIRING_TOKEN: &[u8] = &[1, 2, 3];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let config = Config {
        node_description: S2NodeDescription {
            id: S2NodeId(String::from("12121212")),
            brand: String::from("super-reliable-corp"),
            logo_uri: None,
            type_: String::from("fancy"),
            model_name: String::from("the best"),
            user_defined_name: None,
            role: S2Role::Rm,
        },
        endpoint_description: S2EndpointDescription {
            name: None,
            logo_uri: None,
            deployment: None,
        },
        supported_protocol_versions: vec![ConnectionVersion("v1".into())],
    };

    let pair_result = pair(
        config,
        PairingRemote {
            url: Url::parse("http://127.0.0.1:8005").unwrap(),
            id: S2NodeId(String::from("12121212")),
        },
        PAIRING_TOKEN,
        Role::CommunicationClient,
    )
    .await
    .unwrap();

    match pair_result.role {
        s2energy::pairing::PairingRole::CommunicationClient { initiate_url } => {
            println!("Paired as client, url: {initiate_url}, token: {}", pair_result.token.0)
        }
        s2energy::pairing::PairingRole::CommunicationServer => println!("Paired as server, token: {}", pair_result.token.0),
    }
}
