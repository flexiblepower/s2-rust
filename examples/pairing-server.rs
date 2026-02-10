use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use s2energy::pairing::{
    CommunicationProtocol, Config, ConnectionVersion, PairingToken, S2EndpointDescription, S2NodeDescription, S2NodeId, S2Role, Server,
    ServerConfig,
};

#[allow(unused)]
const PAIRING_TOKEN: &[u8] = &[1, 2, 3];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let server = Server::new(ServerConfig {
        root_certificate: Some(
            CertificateDer::from_pem_file(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("root.pem")).unwrap(),
        ),
    });
    let config = Config::builder(
        S2NodeDescription {
            id: S2NodeId(String::from("12121212")),
            brand: String::from("super-reliable-corp"),
            logo_uri: None,
            type_: String::from("fancy"),
            model_name: String::from("the best"),
            user_defined_name: None,
            role: S2Role::Cem,
        },
        S2EndpointDescription {
            name: None,
            logo_uri: None,
            deployment: None,
        },
        vec![ConnectionVersion("v1".into())],
        vec![CommunicationProtocol("WebSocket".into())],
    )
    .with_connection_initiate_url("test.example.com".into())
    .build()
    .unwrap();
    let app = server.get_router();

    let addr = SocketAddr::from(([127, 0, 0, 1], 8005));

    let rustls_config = RustlsConfig::from_pem_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("test.local.chain.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("test.local.key"),
    )
    .await
    .unwrap();

    tokio::spawn(async move {
        println!("listening on http://{}", addr);
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    let pairing = server
        .pair_once(Arc::new(config.clone()), PairingToken(PAIRING_TOKEN.into()))
        .unwrap()
        .result()
        .await
        .unwrap();
    println!("token: {}", pairing.token.0);

    let mut repeated_pairing = server.pair_repeated(Arc::new(config), PairingToken(PAIRING_TOKEN.into())).unwrap();

    while let Some(result) = repeated_pairing.next().await {
        println!("token: {}", result.token.0);
    }
}
