use std::sync::Arc;

use s2energy_connection::pairing::{
    Client, ClientConfig, Deployment, EndpointConfig, MessageVersion, PairingRemote, S2NodeDescription, S2NodeId, S2Role,
};

const PAIRING_TOKEN: &[u8] = &[1, 2, 3];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let config = EndpointConfig::builder(
        S2NodeDescription {
            id: S2NodeId(String::from("12121212")),
            brand: String::from("super-reliable-corp"),
            logo_uri: None,
            type_: String::from("fancy"),
            model_name: String::from("the best"),
            user_defined_name: None,
            role: S2Role::Rm,
        },
        vec![MessageVersion("v1".into())],
    )
    .with_connection_initiate_url("client.example.com".into())
    .build()
    .unwrap();

    let client = Client::new(
        Arc::new(config),
        ClientConfig {
            additional_certificates: vec![],
            pairing_deployment: Deployment::Lan,
        },
    )
    .unwrap();

    let pair_result = client
        .pair(
            PairingRemote {
                url: "https://test.local:8005".into(),
                id: S2NodeId(String::from("12121212")),
            },
            PAIRING_TOKEN,
        )
        .await
        .unwrap();

    match pair_result.role {
        s2energy_connection::pairing::PairingRole::CommunicationClient { initiate_url } => {
            println!("Paired as client, url: {initiate_url}, token: {}", pair_result.token.0)
        }
        s2energy_connection::pairing::PairingRole::CommunicationServer => println!("Paired as server, token: {}", pair_result.token.0),
    }
}
