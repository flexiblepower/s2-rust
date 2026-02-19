use std::{
    convert::Infallible,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum_server::tls_rustls::RustlsConfig;
use s2energy_connection::{
    AccessToken, MessageVersion, S2NodeId,
    communication::{NodeConfig, PairingLookupResult, Server, ServerConfig, ServerPairing, ServerPairingStore},
};

struct MemoryPairingStoreInner {
    token: AccessToken,
    config: Arc<NodeConfig>,
    server: S2NodeId,
    client: S2NodeId,
}

#[derive(Clone)]
struct MemoryPairingStore(Arc<Mutex<MemoryPairingStoreInner>>);

impl MemoryPairingStore {
    fn new() -> Self {
        MemoryPairingStore(Arc::new(Mutex::new(MemoryPairingStoreInner {
            token: AccessToken("0123456789ABCDEF".into()),
            config: Arc::new(NodeConfig::builder(vec![MessageVersion("v1".into())]).build()),
            server: S2NodeId("12".into()),
            client: S2NodeId("34".into()),
        })))
    }
}

impl ServerPairingStore for MemoryPairingStore {
    type Error = Infallible;

    type Pairing<'a>
        = MemoryPairingStore
    where
        Self: 'a;

    async fn lookup(
        &self,
        request: s2energy_connection::communication::PairingLookup,
    ) -> Result<s2energy_connection::communication::PairingLookupResult<Self::Pairing<'_>>, Self::Error> {
        let this = self.0.lock().unwrap();
        if this.client == request.client && this.server == request.server {
            Ok(PairingLookupResult::Pairing(self.clone()))
        } else {
            Ok(PairingLookupResult::NeverPaired)
        }
    }
}

impl ServerPairing for MemoryPairingStore {
    type Error = Infallible;

    fn access_token(&self) -> impl AsRef<AccessToken> {
        self.0.lock().unwrap().token.clone()
    }

    fn config(&self) -> impl AsRef<NodeConfig> {
        self.0.lock().unwrap().config.clone()
    }

    async fn set_access_token(&mut self, token: AccessToken) -> Result<(), Self::Error> {
        self.0.lock().unwrap().token = token;
        Ok(())
    }

    async fn update_remote_node_description(&mut self, _node_description: s2energy_connection::S2NodeDescription) {
        println!("Received updated node description");
    }

    async fn update_remote_endpoint_description(&mut self, _endpoint_description: s2energy_connection::S2EndpointDescription) {
        println!("Received updated endpoint description");
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let server = Server::new(
        ServerConfig {
            base_url: "localhost".into(),
            endpoint_description: None,
        },
        MemoryPairingStore::new(),
    );

    let addr = SocketAddr::from(([127, 0, 0, 1], 8005));

    let rustls_config = RustlsConfig::from_pem_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("localhost.chain.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("localhost.key"),
    )
    .await
    .unwrap();

    println!("listening on http://{}", addr);
    axum_server::bind_rustls(addr, rustls_config)
        .serve(server.get_router().into_make_service())
        .await
        .unwrap();
}
