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

    let mut rng = rand::rng();
    let pair_result = pair(
        &mut rng,
        config,
        PairingRemote {
            url: Url::parse("http://127.0.0.1:8005").unwrap(),
            id: S2NodeId("elfkje".into()),
        },
        PAIRING_TOKEN,
        Role::CommunicationClient,
    )
    .await
    .unwrap();
    println!(
        "url: {:?}, token: {:?}",
        pair_result.initiate_connection_url,
        pair_result.access_token.map(|v| v.0)
    );
}
