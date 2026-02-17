use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use uuid::uuid;

use s2energy_connection::{
    MessageVersion, S2NodeDescription, S2Role,
    pairing::{EndpointConfig, PairingToken, Server, ServerConfig},
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
    let config = EndpointConfig::builder(
        S2NodeDescription {
            id: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8").into(),
            brand: String::from("super-reliable-corp"),
            logo_uri: None,
            type_: String::from("fancy"),
            model_name: String::from("the best"),
            user_defined_name: None,
            role: S2Role::Cem,
        },
        vec![MessageVersion("v1".into())],
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
