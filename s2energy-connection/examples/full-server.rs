use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use iocraft::prelude::*;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use s2energy_common::S2Transport;
use s2energy_connection::{
    EndpointDescription, MessageVersion, NodeDescription, NodeId, Role,
    combined_server::{self, CombinedServerPairingStore, ServerCertificates, ServerConfig},
    communication::{self, ConnectionInfo, PairingLookupResult, ServerPairing, ServerPairingStore},
    discovery::{DiscoverableS2Endpoint, advertise},
    pairing::{self, LongpollingHandle, PairingToken},
};
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tracing_subscriber::{
    EnvFilter,
    fmt::{self, MakeWriter},
};

#[derive(Default, Props)]
struct LongpollingListProps<'a> {
    width: u16,
    height: u16,
    focus: bool,
    longpolling_clients: &'a [NodeId],
    want_pair: Handler<NodeId>,
}

#[component]
fn LongpollingList<'a>(mut hooks: Hooks, props: &LongpollingListProps<'a>) -> impl Into<AnyElement<'a>> {
    let mut selected = hooks.use_state(|| 0usize);
    let focus = props.focus;

    if selected.get() != 0 && selected.get() > props.longpolling_clients.len() {
        selected.set(props.longpolling_clients.len());
    }

    hooks.use_terminal_events({
        move |event| match event {
            TerminalEvent::Key(KeyEvent { code, kind, .. }) if kind != KeyEventKind::Release => match code {
                KeyCode::Up if focus => selected.set(selected.get().saturating_sub(1)),
                KeyCode::Down if focus => selected.set(selected.get().saturating_add(1)),
                _ => {}
            },
            _ => {}
        }
    });

    element! {
        View (
            width: props.width,
            height: props.height,
            border_style: if props.focus { BorderStyle::Double } else { BorderStyle::Single },
            flex_direction: FlexDirection::Column,
        ) {
            Text(content: "Longpolling clients:", weight: Weight::Bold)
            ScrollView() {
                View(
                    width: props.width,
                    flex_direction: FlexDirection::Column,
                ) {
                    #(props.longpolling_clients.iter().enumerate().map(|(i, &id)| {
                        let handler = props.want_pair.bind(id);
                        let selected = props.focus && i == selected.get();
                        element! {
                            Button(has_focus: selected, handler) {
                                View(width: props.width, background_color: if selected { Color::White } else { Color::Black }) {
                                    Text(content: format!("{}", id), color: if selected { Color::Black } else { Color::White })
                                }
                            }
                        }
                    }))
                }
            }
        }
    }
}

#[derive(Default, Props)]
struct ClientUIProps {
    paired_clients: Vec<NodeId>,
    longpolling_clients: Vec<NodeId>,
    log: String,
    token: Option<String>,
    longpolling_pair: HandlerMut<'static, (NodeId, PairingToken)>,
    pair: HandlerMut<'static, ()>,
}

#[component]
fn ClientUI<'a>(mut hooks: Hooks, props: &'a mut ClientUIProps) -> impl Into<AnyElement<'a>> {
    let (width, height) = hooks.use_terminal_size();
    let mut focus = hooks.use_state(|| 0);
    let mut token = hooks.use_state(|| String::default());
    let mut want_pair_with = hooks.use_state(|| None);
    let mut last_error = hooks.use_state(|| "");
    let mut available_for_pairing = hooks.use_state(|| false);

    if available_for_pairing.get() != props.token.is_some() {
        available_for_pairing.set(props.token.is_some())
    }

    let mut longpolling_pair = props.longpolling_pair.take();
    let mut pair = props.pair.take();
    hooks.use_terminal_events({
        move |event| match event {
            TerminalEvent::Key(KeyEvent { code, kind, .. }) if kind != KeyEventKind::Release => match code {
                KeyCode::Tab if want_pair_with.read().is_none() => focus.set((focus.get() + 1) % 3),
                KeyCode::BackTab if want_pair_with.read().is_none() => focus.set((focus.get() + 2) % 3),
                KeyCode::End => want_pair_with.set(None),
                KeyCode::Enter => {
                    if token.read().len() != 0
                        && let Ok(token) = token.read().parse()
                    {
                        match want_pair_with.write().take() {
                            Some(remote) => longpolling_pair((remote, token)),
                            None => {}
                        }
                    } else if token.read().len() != 0 && want_pair_with.read().is_some() {
                        last_error.set("Invalid token");
                    }
                }
                KeyCode::Char('p') if want_pair_with.read().is_none() && !available_for_pairing.get() => {
                    pair(());
                }
                _ => {}
            },
            _ => {}
        }
    });
    let height_list = (height - 1) / 3;
    let height_log = height - 1 - 2 * height_list;
    element! {
       View(
            width,
            height,
            flex_direction: FlexDirection::Column,
            justify_content: JustifyContent::Stretch,
        ) {
            LongpollingList (
                width,
                height: height_list,
                focus: !available_for_pairing.get() && want_pair_with.read().is_none() && focus == 0,
                longpolling_clients: props.longpolling_clients.as_slice(),
                want_pair: move |id| {token.clone().set(String::default()); want_pair_with.clone().set(Some(id)); last_error.clone().set("")}
            )
            View(
                width,
                height: height_list,
                border_style: if !available_for_pairing.get() && want_pair_with.read().is_none() && focus == 1 { BorderStyle::Double } else { BorderStyle::Single },
                flex_direction: FlexDirection::Column,
            ) {
                Text(content: "Paired clients:", weight: Weight::Bold)
                #(props.paired_clients.iter().map(|id| element! { Text(content: id.to_string())} ))
            }
            View(
                width,
                height: height_log,
                border_style: if !available_for_pairing.get() && want_pair_with.read().is_none() && focus == 2 { BorderStyle::Double } else { BorderStyle::Single },
                flex_direction: FlexDirection::Column,
            ) {
                ScrollView (
                    auto_scroll: true,
                    keyboard_scroll: want_pair_with.read().is_none() && focus == 2,
                ) {
                    Text(content: &props.log)
                }
            }
            View(
                width,
                height: 1,
                flex_direction: FlexDirection::Row,
                justify_content: JustifyContent::SpaceBetween,
            ) {
                Text(content: "Become available for (p)airing")
            }
            #(if want_pair_with.read().is_some() {
                element! {
                    View(
                        position: Position::Absolute,
                        flex_direction: FlexDirection::Column,
                        top: 5,
                        left: 5,
                        bottom: 5,
                        right: 5,
                        border_style: BorderStyle::Double,
                        background_color: Color::Black,
                    ) {
                        Text(content: "Token:")
                        View( width: 30, height: 1, background_color: Color::DarkGrey, ) {
                            TextInput(
                                has_focus: true,
                                value: token.to_string(),
                                on_change: move |new_token| token.set(new_token),
                            )
                        }
                        Text(content: last_error.get())
                    }
                }
            } else if let Some(token) = props.token.as_ref() {
                element! {
                    View(
                        position: Position::Absolute,
                        flex_direction: FlexDirection::Column,
                        top: 5,
                        left: 5,
                        bottom: 5,
                        right: 5,
                        border_style: BorderStyle::Double,
                        background_color: Color::Black,
                    ) {
                        Text(content: format!("Available for pairing with token: {}", token))
                    }
                }
            } else {
                element! {View (display: Display::None) {}}
            })
        }
    }
}

struct LogWriter(State<String>);
impl<'a> MakeWriter<'a> for LogWriter {
    type Writer = &'a Self;

    fn make_writer(&'a self) -> Self::Writer {
        self
    }
}

impl std::io::Write for &LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.clone().write().push_str(&String::from_utf8_lossy(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct PairingStoreData {
    local_config: Arc<communication::NodeConfig>,
    pairings: HashMap<NodeId, pairing::Pairing>,
    log: State<String>,
}

#[derive(Clone)]
struct PairingStore(State<PairingStoreData>);

impl PairingStore {
    fn hook_new(hooks: &mut Hooks, log: State<String>, node_description: NodeDescription, message_versions: Vec<MessageVersion>) -> Self {
        Self(hooks.use_state(|| {
            let local_config = Arc::new(
                communication::NodeConfig::builder(message_versions)
                    .with_node_description(node_description)
                    .build(),
            );
            PairingStoreData {
                local_config,
                pairings: HashMap::new(),
                log,
            }
        }))
    }
}

struct Pairing {
    store: PairingStore,
    id: NodeId,
}

impl ServerPairingStore for PairingStore {
    type Error = std::convert::Infallible;

    type Pairing<'a>
        = Pairing
    where
        Self: 'a;

    async fn lookup(
        &self,
        request: s2energy_connection::communication::PairingLookup,
    ) -> Result<s2energy_connection::communication::PairingLookupResult<Self::Pairing<'_>>, Self::Error> {
        let this = self.0.read();
        if
        /*this.local_config.node_description().map_or(true, |v| v.id == request.server) &&*/
        this.pairings.contains_key(&request.client) {
            Ok(PairingLookupResult::Pairing(Pairing {
                store: self.clone(),
                id: request.client,
            }))
        } else {
            Ok(PairingLookupResult::NeverPaired)
        }
    }
}

impl CombinedServerPairingStore for PairingStore {
    async fn store(&self, _local_node: NodeId, pairing: pairing::Pairing) -> Result<(), Self::Error> {
        let mut this = self.0.clone();
        let mut this = this.write();
        this.log.write().push_str(&format!(
            "New pairing with {} ({} from {})\n",
            pairing.remote_node_description.id, pairing.remote_node_description.model_name, pairing.remote_node_description.brand
        ));
        this.pairings.insert(pairing.remote_node_description.id, pairing);
        Ok(())
    }
}

impl ServerPairing for Pairing {
    type Error = std::convert::Infallible;

    fn access_token(&self) -> impl AsRef<s2energy_connection::AccessToken> {
        self.store.0.read().pairings.get(&self.id).unwrap().token.clone()
    }

    fn config(&self) -> impl AsRef<s2energy_connection::communication::NodeConfig> {
        self.store.0.read().local_config.clone()
    }

    async fn set_access_token(&mut self, token: s2energy_connection::AccessToken) -> Result<(), Self::Error> {
        self.store.0.write().pairings.get_mut(&self.id).unwrap().token = token;
        Ok(())
    }

    async fn unpair(mut self) -> Result<(), Self::Error> {
        let mut this = self.store.0.write();
        if let Some(pairing) = this.pairings.remove(&self.id) {
            this.log.write().push_str(&format!(
                "Unpaired with {} ({} from {})\n",
                pairing.remote_node_description.id, pairing.remote_node_description.model_name, pairing.remote_node_description.brand
            ));
        }
        Ok(())
    }
}

#[derive(Default, Props)]
struct RootProps {
    hostname: String,
}

#[derive(Clone)]
struct LongpollerActions {
    pair: tokio::sync::mpsc::UnboundedSender<()>,
}

#[component]
fn Root(mut hooks: Hooks, props: &RootProps) -> impl Into<AnyElement<'static>> {
    let mut log = hooks.use_state(|| String::default());

    hooks.use_state(|| {
        fmt::fmt()
            .with_writer(LogWriter(log))
            .with_env_filter(EnvFilter::from_default_env())
            .init()
    });

    let mut token = hooks.use_state(|| None);
    let node_description = hooks.use_state(|| NodeDescription {
        id: NodeId::new(),
        brand: String::from("test"),
        logo_url: None,
        type_: String::from("fancy"),
        model_name: String::from("test server"),
        user_defined_name: None,
        role: Role::Cem,
    });

    let store = PairingStore::hook_new(&mut hooks, log, node_description.read().clone(), vec![MessageVersion("v1".into())]);

    let store_copy = store.clone();
    let server = hooks.use_state(|| {
        let hostname = props.hostname.clone();
        let cert_chain = CertificateDer::pem_file_iter(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("testdata")
                .join(format!("{hostname}.local.chain.pem")),
        )
        .expect(&format!("Unable to load certificates. Did you generate certificates for your hostname by running ./gen_cert {hostname}.local in the s2energy-connection/testdata folder?"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

        let server = combined_server::Server::new(
            ServerConfig {
                base_url: format!("{hostname}.local:8000"),
                certificates: Some(ServerCertificates {
                    leaf_certificate: cert_chain.first().unwrap().clone().into_owned(),
                    root_certificate: cert_chain.last().unwrap().clone().into_owned(),
                }),
                endpoint_description: EndpointDescription::default(),
                advertised_nodes: vec![node_description.read().clone()],
            },
            store_copy,
        ).unwrap();

        server
    });

    let mut active_longpollers = hooks.use_state(|| HashMap::new());

    let handle_longpoller = hooks.use_async_handler(move |mut handle: LongpollingHandle| async move {
        log.write()
            .push_str(&format!("New longpolling session from {}\n", handle.client_id()));
        let (pair, mut pair_rx) = tokio::sync::mpsc::unbounded_channel();
        active_longpollers.write().insert(handle.client_id(), LongpollerActions { pair });
        loop {
            tokio::select! {
                _ = pair_rx.recv() => {
                    if let Err(error) = handle.request_pairing().await {
                        log.write().push_str(&format!("Longpolling remote indicated inability to pair: {}", error));
                    }
                }
                _ = handle.wait_dropped() => {
                    log.write().push_str(&format!("Remote stopped longpolling"));
                    break;
                }
            }
        }
        log.write().push_str("Ended longpolling session.\n");
        active_longpollers.write().remove(&handle.client_id());
    });

    let server_copy = server.read().clone();
    hooks.use_future(async move {
        let server = server_copy;
        server.enable_longpolling().await;
        loop {
            let handle = server.get_longpolling().await;
            handle_longpoller(handle);
        }
    });

    let handle_connection = hooks.use_async_handler(
        move |(pairing, mut connection): (communication::PairingLookup, ConnectionInfo)| async move {
            log.write()
                .push_str(&format!("New communication session from {}\n", pairing.client));
            connection.transport.send("Hello from server").await.ok();
            while let Ok(value) = connection.transport.receive::<serde_json::Value>().await {
                log.write().push_str(&format!(
                    "Received message from {}: {}\n",
                    pairing.client,
                    serde_json::to_string_pretty(&value).unwrap()
                ));
            }
        },
    );

    let server_copy = server.read().clone();
    hooks.use_future(async move {
        let server = server_copy;
        loop {
            let connection = server.next_connection().await;
            handle_connection(connection);
        }
    });

    let hostname = props.hostname.clone();
    hooks.use_future(async move {
        let rustls_config = RustlsConfig::from_pem_file(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("testdata")
                .join(format!("{hostname}.local.chain.pem")),
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("testdata")
                .join(format!("{hostname}.local.key")),
        )
        .await
        .unwrap();

        let router = server.read().get_router();
        let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
        axum_server::bind_rustls(addr, rustls_config)
            .serve(router.into_make_service())
            .await
            .unwrap();
    });

    let hostname = props.hostname.clone();
    hooks.use_future(async move {
        let endpoint = DiscoverableS2Endpoint::build_with_pairing(vec![Role::Cem], format!("https://{hostname}.local:8000"))
            .unwrap()
            .with_endpoint_name("Example full server".into())
            .with_longpolling_url(format!("https://{hostname}.local:8000"))
            .unwrap()
            .build();
        log.write().push_str(&format!(
            "Advertising with lp: {:?}, pair: {:?}\n",
            endpoint.longpolling_url(),
            endpoint.pairing_url()
        ));
        let _advertisement = advertise(8000, endpoint).await.unwrap();
        std::future::pending().await
    });

    let mut paired_clients: Vec<_> = store.0.read().pairings.keys().copied().collect();
    paired_clients.sort();

    let mut longpolling_clients: Vec<_> = active_longpollers.read().keys().copied().collect();
    longpolling_clients.sort();

    let longpolling_pair = hooks.use_async_handler(move |(id, token): (NodeId, PairingToken)| async move {
        let Some(v) = active_longpollers.read().get(&id).cloned() else {
            log.write()
                .push_str("Unable to pair with requested node, it stopped longpolling.\n");
            return;
        };

        if let Err(error) = server.read().allow_pair_once(
            node_description.read().clone(),
            vec![MessageVersion("v1".into())],
            None,
            token,
            async |_| {},
        ) {
            log.write().push_str(&format!("Unable to pair: {}\n", error));
            return;
        }
        if v.pair.send(()).is_err() {
            log.write()
                .push_str("Unable to pair with requested node, it stopped longpolling.\n");
        } else {
            log.write().push_str("Requested remote to start pairing.\n");
        }
    });

    let pair = hooks.use_async_handler(move |_: ()| async move {
        let cur_token = PairingToken::new();
        token.set(Some(cur_token.clone()));

        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();

        if let Err(error) = server.read().allow_pair_once(
            node_description.read().clone(),
            vec![MessageVersion("v1".into())],
            None,
            cur_token,
            async move |_| {
                finished_tx.send(()).ok();
            },
        ) {
            log.write().push_str(&format!("Could not start pairing session: {}.", error));
        } else {
            tokio::time::timeout(Duration::from_mins(10), finished_rx).await.ok();
        }

        token.set(None);
    });

    let token = token.read().as_ref().map(|v| v.to_string());
    element! {
        ClientUI (
            log: log.to_string(),
            token,
            paired_clients,
            longpolling_clients,
            longpolling_pair,
            pair
        )
    }
}

/// Demonstration server for S2-connect
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    hostname: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let hostname = Args::parse().hostname;
    element!(Root(hostname))
        .render_loop()
        .await
        .expect("Unexpected failure of renderer");
}
