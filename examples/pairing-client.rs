use std::path::PathBuf;

use reqwest::Url;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use s2energy::pairing::{
    CommunicationProtocol, Config, ConnectionVersion, Deployment, PairingRemote, S2EndpointDescription, S2NodeDescription, S2NodeId,
    S2Role, pair,
};

const PAIRING_TOKEN: &[u8] = &[1, 2, 3];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let config = Config::builder(
        S2NodeDescription {
            id: S2NodeId(String::from("12121212")),
            brand: String::from("super-reliable-corp"),
            logo_uri: None,
            type_: String::from("fancy"),
            model_name: String::from("the best"),
            user_defined_name: None,
            role: S2Role::Rm,
        },
        S2EndpointDescription {
            name: None,
            logo_uri: None,
            deployment: None,
        },
        vec![ConnectionVersion("v1".into())],
        vec![CommunicationProtocol("WebSocket".into())],
        Deployment::Lan,
    )
    .with_connection_initiate_url("client.example.com".into())
    .build()
    .unwrap();

    let pair_result = pair(
        &config,
        vec![CertificateDer::from_pem_file(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("root.pem")).unwrap()],
        PairingRemote {
            url: Url::parse("https://test.local:8005").unwrap(),
            id: S2NodeId(String::from("12121212")),
        },
        PAIRING_TOKEN,
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
