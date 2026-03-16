use std::{
    convert::Infallible,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use uuid::uuid;

use axum_server::tls_rustls::RustlsConfig;
use s2energy_common::S2Transport;
use s2energy_connection::{
    AccessToken, MessageVersion, S2NodeId,
    communication::{NodeConfig, PairingLookupResult, Server, ServerConfig, ServerPairing, ServerPairingStore},
};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

struct MemoryPairingStoreInner {
    token: AccessToken,
    config: Arc<NodeConfig>,
    server: S2NodeId,
    client: S2NodeId,
    // indication of whether the client has unpaired with us.
    unpaired: bool,
}

#[derive(Clone)]
struct MemoryPairingStore(Arc<Mutex<MemoryPairingStoreInner>>);

impl MemoryPairingStore {
    fn new() -> Self {
        MemoryPairingStore(Arc::new(Mutex::new(MemoryPairingStoreInner {
            token: AccessToken("0123456789ABCDEF".into()),
            config: Arc::new(NodeConfig::builder(vec![MessageVersion("v1".into())]).build()),
            server: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8").into(),
            client: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c7").into(),
            unpaired: false,
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
            if this.unpaired {
                Ok(PairingLookupResult::Unpaired)
            } else {
                Ok(PairingLookupResult::Pairing(self.clone()))
            }
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

    async fn unpair(self) -> Result<(), Self::Error> {
        self.0.lock().unwrap().unpaired = true;
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let mut server = Server::new(
        ServerConfig {
            base_url: "localhost:8005".into(),
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

    let router = server.get_router();
    tokio::spawn(async move {
        println!("listening on http://{}", addr);
        axum_server::bind_rustls(addr, rustls_config)
            .serve(router.into_make_service())
            .await
            .unwrap();
    });

    loop {
        let (pairing, mut connection) = server.next_connection().await;
        tokio::spawn(async move {
            println!("New connection between {:?} and {:?}", pairing.client, pairing.server);
            connection.transport.send("Hello from server").await.unwrap();
            let received: String = connection.transport.receive().await.unwrap();
            println!("Received from {:?}: {received}", pairing.client);
        });
    }
}
