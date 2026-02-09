use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;

use s2energy::pairing::{
    Config, ConnectionVersion, PairingToken, S2EndpointDescription, S2NodeDescription, S2NodeId, S2Role, Server, ServerConfig,
};

#[allow(unused)]
const PAIRING_TOKEN: &[u8] = &[1, 2, 3];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let server = Server::new(ServerConfig {});
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
    let app = server.get_router();

    let addr = SocketAddr::from(([127, 0, 0, 1], 8005));
    let listener = TcpListener::bind(addr).await.unwrap();

    tokio::spawn(async move {
        println!("listening on http://{}", addr);
        axum::serve(listener, app).await.unwrap();
    });

    let pairing = server
        .pair_once(Arc::new(config), PairingToken(PAIRING_TOKEN.into()))
        .unwrap()
        .result()
        .await
        .unwrap();
    println!("token: {}", pairing.token.0);
}
