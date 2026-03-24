use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::path::PathBuf;
use uuid::uuid;

use s2energy_connection::{
    Deployment, EndpointDescription, MessageVersion, NodeDescription, Role,
    pairing::{Client, ClientConfig, NodeConfig, NodeIdAlias, PairingRemote},
};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

const PAIRING_TOKEN: &[u8] = &[1, 2, 3];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let config = NodeConfig::builder(
        NodeDescription {
            id: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c7").into(),
            brand: String::from("super-reliable-corp"),
            logo_url: None,
            type_: String::from("fancy"),
            model_name: String::from("the best"),
            user_defined_name: None,
            role: Role::Rm,
        },
        vec![MessageVersion("v1".into())],
    )
    .with_connection_initiate_url("client.example.com".into())
    .build()
    .unwrap();

    let client = Client::new(ClientConfig {
        additional_certificates: vec![
            CertificateDer::from_pem_file(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("root.pem")).unwrap(),
        ],
        endpoint_description: EndpointDescription::default(),
        pairing_deployment: Deployment::Lan,
    })
    .unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    client
        .pair(
            &config,
            PairingRemote {
                url: "https://localhost:8005".into(),
                id: Some(NodeIdAlias("ninechars".into())),
            },
            PAIRING_TOKEN,
            async |pairing| {
                tx.send(pairing).unwrap();
                Ok::<_, std::convert::Infallible>(())
            },
        )
        .await
        .unwrap();
    let pair_result = rx.await.unwrap();

    match pair_result.role {
        s2energy_connection::pairing::PairingRole::CommunicationClient { initiate_url } => {
            println!("Paired as client, url: {initiate_url}, token: {}", pair_result.token.0)
        }
        s2energy_connection::pairing::PairingRole::CommunicationServer => println!("Paired as server, token: {}", pair_result.token.0),
    }
}
