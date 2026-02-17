use std::sync::Arc;
use uuid::uuid;

use s2energy_connection::{
    Deployment, MessageVersion, S2NodeDescription, S2Role,
    pairing::{Client, ClientConfig, EndpointConfig, PairingRemote},
};

const PAIRING_TOKEN: &[u8] = &[1, 2, 3];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let config = EndpointConfig::builder(
        S2NodeDescription {
            id: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c7").into(),
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
                id: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8").into(),
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
