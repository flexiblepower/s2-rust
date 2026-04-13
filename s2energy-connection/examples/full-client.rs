use std::{collections::HashSet, sync::Arc, time::Duration};

use iocraft::prelude::*;
use s2energy_common::S2Transport;
use s2energy_connection::{
    AccessToken, CertificateHash, Deployment, EndpointDescription, MessageVersion, NodeDescription, NodeId, Role,
    communication::{self, ClientPairing, ConnectionInfo},
    discovery::{DiscoverableS2Endpoint, DiscoveryEvent, S2Discoverer},
    pairing::{self, LongpollHandler, PairingRemote, PairingToken, RemoteNodeIdentifier},
};
use tokio::sync::mpsc::UnboundedSender;
use tracing_subscriber::{
    EnvFilter,
    fmt::{self, MakeWriter},
};

#[derive(Default, Props)]
struct DiscoveryViewProps<'a> {
    width: u16,
    height: u16,
    focus: bool,
    discovered_nodes: Vec<(&'a str, Option<&'a str>, &'a NodeDescription)>,
    want_pairing: Handler<PairingRemote>,
}

#[component]
fn DiscoveryView<'a>(mut hooks: Hooks, props: &mut DiscoveryViewProps<'a>) -> impl Into<AnyElement<'a>> {
    let mut selected_discovery = hooks.use_state(|| 0usize);
    let focus = props.focus;

    if selected_discovery.get() != 0 && selected_discovery.get() > props.discovered_nodes.len() {
        selected_discovery.set(props.discovered_nodes.len());
    }

    hooks.use_terminal_events({
        move |event| match event {
            TerminalEvent::Key(KeyEvent { code, kind, .. }) if kind != KeyEventKind::Release => match code {
                KeyCode::Up if focus => selected_discovery.set(selected_discovery.get().saturating_sub(1)),
                KeyCode::Down if focus => selected_discovery.set(selected_discovery.get().saturating_add(1)),
                _ => {}
            },
            _ => {}
        }
    });

    element! {
        View(
            width: props.width,
            height: props.height,
            border_style: if props.focus { BorderStyle::Double } else { BorderStyle::Single },
            flex_direction: FlexDirection::Column,
        ) {
            Text(content: "Discovered CEMs:", weight: Weight::Bold)
            ScrollView() {
                View(
                    width: props.width,
                    flex_direction: FlexDirection::Column,
                ) {
                    #(props.discovered_nodes.iter().enumerate().map(|(i, (hostname, pairing_url, node))| {
                        let handler = if let Some(remote) = pairing_url.map(|url| PairingRemote{url: url.to_owned(), id: RemoteNodeIdentifier::Id(node.id)}) {
                            props.want_pairing.bind(remote)
                        } else {
                            Handler::default()
                        };
                        let selected = props.focus && i == selected_discovery.get();
                        element! {
                            Button(has_focus: selected, handler) {
                                View(width: props.width, background_color: if selected { Color::White } else { Color::Black }) {
                                    Text(content: format!("{} ({} from {}) at {}", node.id, node.model_name, node.brand, *hostname), color: if selected { Color::Black } else { Color::White })
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
    discovered_clients: Vec<(String, (DiscoverableS2Endpoint, EndpointDescription, Vec<NodeDescription>))>,
    initiate_pairing: HandlerMut<'static, PairingTrigger>,
    reconnect: HandlerMut<'static, ()>,
    send_message: HandlerMut<'static, ()>,
    unpair: HandlerMut<'static, ()>,
    log: String,
    token: String,
    have_pairing: bool,
}

#[component]
fn ClientUI<'a>(mut hooks: Hooks, props: &'a mut ClientUIProps) -> impl Into<AnyElement<'a>> {
    let (width, height) = hooks.use_terminal_size();
    let mut focus_top = hooks.use_state(|| true);
    let mut want_pair_with = hooks.use_state(|| None);
    let mut token = hooks.use_state(|| String::default());
    let mut last_error = hooks.use_state(|| "");

    let mut initiate_pairing = props.initiate_pairing.take();
    let mut reconnect = props.reconnect.take();
    let mut send_message = props.send_message.take();
    let mut unpair = props.unpair.take();
    hooks.use_terminal_events({
        move |event| match event {
            TerminalEvent::Key(KeyEvent { code, kind, .. }) if kind != KeyEventKind::Release => match code {
                KeyCode::Tab => focus_top.set(!focus_top.get()),
                KeyCode::Enter => {
                    if token.read().len() != 0
                        && let Ok(token) = token.read().parse()
                    {
                        match want_pair_with.write().take() {
                            Some(remote) => initiate_pairing(PairingTrigger { remote, token }),
                            None => {}
                        }
                    } else if token.read().len() != 0 && want_pair_with.read().is_some() {
                        last_error.set("Invalid token");
                    }
                }
                KeyCode::Esc => {
                    want_pair_with.write().take();
                }
                KeyCode::Char('r') if want_pair_with.read().is_none() => reconnect(()),
                KeyCode::Char('s') if want_pair_with.read().is_none() => send_message(()),
                KeyCode::Char('u') if want_pair_with.read().is_none() => unpair(()),
                _ => {}
            },
            _ => {}
        }
    });

    let discovered_nodes: Vec<_> = props
        .discovered_clients
        .iter()
        .flat_map(|(hostname, (endpoint, _, nodes))| nodes.iter().map(|node| (hostname.as_str(), endpoint.pairing_url(), node)))
        .collect();

    element! {
        View(
            width,
            height,
            flex_direction: FlexDirection::Column,
            justify_content: JustifyContent::Stretch,
        ) {
            DiscoveryView(
                width,
                height: height - (height/2 + 1),
                focus: want_pair_with.read().is_none() && focus_top.get(),
                discovered_nodes,
                want_pairing: move |remote| { want_pair_with.clone().set(Some(remote)); token.clone().set(String::default()); },
            )
            View(
                width,
                height: height/2,
                border_style: if want_pair_with.read().is_none() && !focus_top.get() { BorderStyle::Double } else { BorderStyle::Single },
            ) {
                ScrollView (
                    auto_scroll: true,
                    keyboard_scroll: want_pair_with.read().is_none() && !focus_top.get(),
                ) {
                    Text(content: &props.log)
                }
            }
            #(if props.have_pairing {
                element! {
                    View(
                        width,
                        height: 1,
                        flex_direction: FlexDirection::Row,
                        justify_content: JustifyContent::SpaceBetween,
                    ) {
                        Text(content: "(R)econnect")
                        Text(content: "(S)end message")
                        Text(content: "(U)npair")
                        Text(content: format!("Our token: {}", props.token))
                    }
                }
            } else {
                element! {
                    View(
                        width,
                        height: 1,
                        flex_direction: FlexDirection::Row,
                        justify_content: JustifyContent::SpaceBetween,
                    ) {
                        Text(content: "Start pairing by selecting a CEM with the arrow keys and pressing enter.")
                        Text(content: format!("Our token: {}", props.token))
                    }
                }
            })
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
            } else {
                element! {View (display: Display::None) {}}
            })
        }
    }
}

struct PairingData {
    client_id: NodeId,
    server_id: NodeId,
    communication_url: String,
    access_tokens: std::sync::Mutex<Vec<AccessToken>>,
    certificate_hash: Option<CertificateHash>,
}

#[derive(Clone)]
struct Pairing(Arc<PairingData>);

impl ClientPairing for Pairing {
    type Error = std::convert::Infallible;

    fn client_id(&self) -> NodeId {
        self.0.client_id
    }

    fn server_id(&self) -> NodeId {
        self.0.server_id
    }

    fn access_tokens(&self) -> impl AsRef<[AccessToken]> {
        self.0.access_tokens.lock().unwrap().clone()
    }

    fn communication_url(&self) -> impl AsRef<str> {
        &self.0.communication_url
    }

    fn certificate_hash(&self) -> Option<CertificateHash> {
        self.0.certificate_hash.clone()
    }

    async fn set_access_tokens(&mut self, tokens: Vec<AccessToken>) -> Result<(), Self::Error> {
        *self.0.access_tokens.lock().unwrap() = tokens;
        Ok(())
    }
}

struct PairingTrigger {
    remote: PairingRemote,
    token: PairingToken,
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

#[component]
fn Root(mut hooks: Hooks) -> impl Into<AnyElement<'static>> {
    let token = hooks.use_state(|| PairingToken::new_static());
    let client_config = hooks.use_state(|| pairing::ClientConfig {
        additional_certificates: vec![],
        endpoint_description: EndpointDescription::default(),
        pairing_deployment: Deployment::Lan,
    });

    let node_description = hooks.use_state(|| NodeDescription {
        id: NodeId::new(),
        brand: String::from("test"),
        logo_url: None,
        type_: String::from("fancy"),
        model_name: String::from("test client"),
        user_defined_name: None,
        role: Role::Rm,
    });

    let pairing_node_config = hooks.use_state(|| {
        pairing::NodeConfig::builder(node_description.read().clone(), vec![MessageVersion("v1".into())])
            .build()
            .unwrap()
    });

    let mut discovered_clients = hooks.use_state(|| vec![]);

    let mut log = hooks.use_state(|| String::default());

    hooks.use_state(|| {
        fmt::fmt()
            .with_writer(LogWriter(log))
            .with_env_filter(EnvFilter::from_default_env())
            .init()
    });

    let mut pairing_channel = hooks.use_state(|| tokio::sync::watch::channel::<Option<Pairing>>(None));
    let mut pairing_trigger_channel = hooks.use_state(|| {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<PairingTrigger>();
        (tx, Some(rx))
    });
    let mut active_longpollers = hooks.use_state(|| HashSet::new());

    // Handle longpolling
    let handle_longpolling_url = hooks.use_async_handler(move |url: String| async move {
        if !active_longpollers.write().insert(url.clone()) {
            return;
        }

        let client = pairing::Client::new(client_config.read().clone()).expect("Unable to create client");
        match client.longpoller(url.clone()).await {
            Ok(longpoller) => {
                let pairing_node_config = pairing_node_config.read().clone();
                longpoller.add_node(pairing_node_config).unwrap();
                struct LPHandler(UnboundedSender<PairingTrigger>, String, PairingToken);
                impl LongpollHandler for LPHandler {
                    async fn request_pairing(&mut self, _node: NodeId) -> bool {
                        self.0
                            .send(PairingTrigger {
                                remote: PairingRemote {
                                    url: self.1.clone(),
                                    id: RemoteNodeIdentifier::None,
                                },
                                token: self.2.clone(),
                            })
                            .unwrap();
                        true
                    }
                    async fn prepare_pairing(&mut self, _node: NodeId) {}
                    async fn cancel_prepare_pairing(&mut self, _node: NodeId) {}
                }
                log.write().push_str(&format!("Starting longpolling with {}.\n", url));
                let channel_sender = pairing_trigger_channel.read().0.clone();
                let token = token.read().clone();
                if let Err(error) = longpoller.run(&mut LPHandler(channel_sender, url.clone(), token)).await {
                    log.write().push_str(&format!("Error during longpolling with {}: {}\n", url, error));
                } else {
                    log.write().push_str(&format!("Finished longpolling with {}.\n", url));
                }
            }
            Err(error) => {
                log.write().push_str(&format!("Could not longpoll with {}: {}\n", url, error));
            }
        }

        active_longpollers.write().remove(&url);
    });

    // Handle discovery events
    hooks.use_future(async move {
        let mut discoverer = S2Discoverer::new(Role::Cem).await.unwrap();
        let client = pairing::Client::new(client_config.read().clone()).expect("Could not setup pairing client");
        loop {
            let event = discoverer.next_event().await;
            match event {
                Ok(DiscoveryEvent::NewEndpoint { hostname, endpoint }) => {
                    log.write().push_str(&format!(
                        "New endpoint lp: {:?}, pair: {:?}\n",
                        endpoint.longpolling_url(),
                        endpoint.pairing_url()
                    ));
                    if let Some(longpolling_url) = endpoint.longpolling_url() {
                        handle_longpolling_url(longpolling_url.to_owned());
                    }
                    if let Some(remote) = endpoint.pairing_url().or(endpoint.longpolling_url())
                        && let Ok((endpoint_description, node_descriptions)) = client.get_endpoint_descriptors(remote.into()).await
                    {
                        let mut clients = discovered_clients.write();
                        if let Some(i) = clients
                            .iter()
                            .enumerate()
                            .filter_map(|(i, (h, _))| if *h == *hostname { Some(i) } else { None })
                            .next()
                        {
                            clients[i] = (hostname, (endpoint, endpoint_description, node_descriptions));
                        } else {
                            clients.push((hostname, (endpoint, endpoint_description, node_descriptions)));
                        }
                    } else {
                        let mut clients = discovered_clients.write();
                        clients.retain(|(h, _)| *h != hostname);
                    }
                }
                Ok(DiscoveryEvent::RemovedEndpoint { hostname }) => {
                    let mut clients = discovered_clients.write();
                    clients.retain(|(h, _)| *h != hostname);
                }
                _ => {}
            }
        }
    });

    // Handle the actual pairing
    hooks.use_future(async move {
        let mut pair_receiver = pairing_trigger_channel.write().1.take().unwrap();
        let client = pairing::Client::new(client_config.read().clone()).expect("Unable to create client");
        while let Some(trigger) = pair_receiver.recv().await {
            let pairing_node_config = pairing_node_config.read().clone();
            let client_id = pairing_node_config.node_description().id;
            if let Err(error) = client
                .pair(
                    &pairing_node_config,
                    trigger.remote,
                    trigger.token.as_slice(),
                    async move |pairing| {
                        match pairing.role {
                            pairing::PairingRole::CommunicationClient { initiate_url, root_hash } => {
                                log.write()
                                    .push_str(&format!("Succesfully paired with {}\n", pairing.remote_node_description.id));
                                pairing_channel
                                    .write()
                                    .0
                                    .send(Some(Pairing(Arc::new(PairingData {
                                        client_id,
                                        server_id: pairing.remote_node_description.id,
                                        communication_url: initiate_url,
                                        access_tokens: std::sync::Mutex::new(vec![pairing.token]),
                                        certificate_hash: root_hash,
                                    }))))
                                    .unwrap();
                            }
                            pairing::PairingRole::CommunicationServer => unreachable!("Got a server connection as LAN RM"),
                        };
                        Ok::<_, std::convert::Infallible>(())
                    },
                )
                .await
            {
                log.write().push_str(&format!("Error during pairing: {}\n", error));
            }
        }
    });

    // Handle connecting to the remote.
    let mut message_trigger_channel = hooks.use_state(|| {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        (tx, Some(rx))
    });
    hooks.use_future(async move {
        let mut pairing_receiver = pairing_channel.read().1.clone();
        let mut send_message_trigger = message_trigger_channel.write().1.take().unwrap();
        let node_config = communication::NodeConfig::builder(vec![MessageVersion("v1".into())]).build();
        let client = communication::Client::new(
            communication::ClientConfig {
                additional_certificates: vec![],
                endpoint_description: None,
            },
            Arc::new(node_config),
        );
        loop {
            let current_pairing = pairing_receiver.borrow_and_update().clone();
            while send_message_trigger.try_recv().is_ok() {}
            if let Some(pairing) = current_pairing {
                log.write().push_str("Starting to connect\n");
                match client.connect(pairing).await {
                    Ok(ConnectionInfo {
                        mut transport,
                        ..
                    }) => {
                        log.write().push_str("Established new connection\n");
                        loop {
                            tokio::select! {
                                message = transport.receive::<serde_json::Value>() => {
                                    match message {
                                        Ok(message) => log.write().push_str(&format!("Received message: {}\n", serde_json::to_string_pretty(&message).unwrap())),
                                        Err(error) => {
                                            log.write().push_str(&format!("Error receiving from remote: {}\n", error));
                                            // Reconnect
                                            transport.disconnect().await;
                                            break;
                                        }
                                    };
                                }
                                _ = send_message_trigger.recv() => {
                                    if let Err(error) = transport.send("hello from client").await {
                                        log.write().push_str(&format!("Error sending to remote: {}\n", error));
                                        // Reconnect
                                        transport.disconnect().await;
                                        break;
                                    } else {
                                        log.write().push_str("Sent message to remote.\n");
                                    }
                                }
                                _ = pairing_receiver.changed() => {
                                    transport.disconnect().await;
                                    log.write().push_str("Disconnected from remote\n");
                                    break;
                                }
                            }
                        }
                    },
                    Err(error) => match error.kind() {
                        communication::ErrorKind::InvalidUrl | communication::ErrorKind::Unpaired | communication::ErrorKind::NotPaired => {
                            log.write().push_str(&format!("Failed to connect: {}\n", error));
                            // Forget the pairing
                            pairing_channel.write().0.send(None).unwrap();
                        }
                        communication::ErrorKind::TransportFailed
                        | communication::ErrorKind::ProtocolError
                        | communication::ErrorKind::NoSupportedVersion
                        | communication::ErrorKind::Storage => {
                            // Retry after waiting a bit
                            log.write().push_str(&format!("Failed to connect: {}\n", error));
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    },
                }
            } else {
                pairing_receiver.wait_for(|v| {
                    v.is_some()
                }).await.unwrap();
            }
        }
    });

    let unpair = hooks.use_async_handler(move |_| async move {
        let pairing = pairing_channel.write().0.send_replace(None);
        if let Some(pairing) = pairing {
            log.write().push_str("Unpairing...\n");
            let node_config = communication::NodeConfig::builder(vec![MessageVersion("v1".into())]).build();
            let client = communication::Client::new(
                communication::ClientConfig {
                    additional_certificates: vec![],
                    endpoint_description: None,
                },
                Arc::new(node_config),
            );
            if let Err(error) = client.unpair(pairing).await {
                log.write().push_str(&format!("Error during unpairing: {}\n", error));
            } else {
                log.write().push_str("Succesfully unpaired.\n");
            }
        }
    });

    element! {
        ClientUI (
            discovered_clients: discovered_clients.read().clone(),
            initiate_pairing: move |trigger| {pairing_trigger_channel.read().0.send(trigger).unwrap();},
            reconnect: move |_| { pairing_channel.read().0.send_modify(|_| {}); },
            unpair,
            send_message: move |_| { message_trigger_channel.read().0.send(()).unwrap(); },
            log: log.read().to_string(),
            have_pairing: pairing_channel.read().0.borrow().is_some(),
            token: token.to_string(),
        )
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    element!(Root).render_loop().await.expect("Unexpected failure of renderer");
}
