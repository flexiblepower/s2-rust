use axum_server::tls_rustls::RustlsConfig;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use uuid::uuid;

use s2energy_connection::{
    MessageVersion, S2EndpointDescription, S2NodeDescription, S2Role,
    pairing::{NodeConfig, PairingS2NodeId, PairingToken, Server, ServerConfig},
};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[allow(unused)]
const PAIRING_TOKEN: &[u8] = &[1, 2, 3];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let server = Server::new(ServerConfig {
        leaf_certificate: None,
        endpoint_description: S2EndpointDescription::default(),
        advertised_nodes: vec![],
    });
    let config = NodeConfig::builder(
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
            .join("localhost.chain.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("localhost.key"),
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

    let pairing_node_id = PairingS2NodeId("ninechars".into());

    let server_clone = server.clone();
    server
        .pair_once(
            Arc::new(config.clone()),
            Some(pairing_node_id.clone()),
            PairingToken(PAIRING_TOKEN.into()),
            async move |result| {
                let pairing = result.unwrap();
                println!("token: {}", pairing.token.0);
                server_clone
                    .pair_repeated(
                        Arc::new(config),
                        Some(pairing_node_id),
                        PairingToken(PAIRING_TOKEN.into()),
                        async |result| {
                            println!("token: {}", result.unwrap().token.0);
                            Ok::<_, std::io::Error>(())
                        },
                    )
                    .unwrap();
                Ok::<_, std::io::Error>(())
            },
        )
        .unwrap();
}
