use std::net::SocketAddr;
use tokio::net::TcpListener;

use s2energy::pairing::{Server, ServerConfig};

#[allow(unused)]
const PAIRING_TOKEN: &[u8] = &[1, 2, 3];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let server = Server::new(ServerConfig {});
    let app = server.get_router();

    let addr = SocketAddr::from(([127, 0, 0, 1], 8005));
    let listener = TcpListener::bind(addr).await.unwrap();

    println!("listening on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}
