use std::{convert::Infallible, path::PathBuf, sync::Arc};
use uuid::uuid;

use rustls::pki_types::{CertificateDer, pem::PemObject};
use s2energy_common::S2Transport;
use s2energy_connection::{
    AccessToken, MessageVersion, S2NodeId,
    communication::{Client, ClientConfig, ClientPairing, NodeConfig},
};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

struct MemoryPairing {
    communication_url: String,
    tokens: Vec<AccessToken>,
    server: S2NodeId,
    client: S2NodeId,
}

impl ClientPairing for &mut MemoryPairing {
    type Error = Infallible;

    fn client_id(&self) -> S2NodeId {
        self.client.clone()
    }

    fn server_id(&self) -> S2NodeId {
        self.server.clone()
    }

    fn access_tokens(&self) -> impl AsRef<[AccessToken]> {
        &self.tokens
    }

    fn communication_url(&self) -> impl AsRef<str> {
        &self.communication_url
    }

    async fn set_access_tokens(&mut self, tokens: Vec<AccessToken>) -> Result<(), Self::Error> {
        self.tokens = tokens;
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let client = Client::new(
        ClientConfig {
            additional_certificates: vec![
                CertificateDer::from_pem_file(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("root.pem")).unwrap(),
            ],
            endpoint_description: None,
        },
        Arc::new(NodeConfig::builder(vec![MessageVersion("v1".into())]).build()),
    );

    let mut pairing = MemoryPairing {
        communication_url: "https://localhost:8005/".into(),
        tokens: vec![AccessToken("0123456789ABCDEF".into())],
        server: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8").into(),
        client: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c7").into(),
    };

    let mut connection_info = client.connect(&mut pairing).await.unwrap();

    connection_info.transport.send("Hello from client").await.unwrap();
    let received: String = connection_info.transport.receive().await.unwrap();
    println!("{received}");
}
