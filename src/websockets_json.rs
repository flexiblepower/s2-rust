//! Utilities for easily setting up a WebSocket connection to talk S2 over.
//!
//! This module contains functions to set up a WebSocket connection and send/receive S2 messages.
//! [`S2Connection`] is the primary API for doing this: it provides functions for easy sending/receiving of
//! S2 messages, and can perform the initial handshake and version negotiation for you. This module
//! uses [`tokio`] as its async runtime.
//!
//! If you want to connect as a WebSocket client, you can use [`connect_as_client`] to obtain an `S2Connection`.
//! If you want set up a WebSocket server, you should make an [`S2WebsocketServer`] and accept connections
//! via [`accept_connection`][S2WebsocketServer::accept_connection].
//!
//! # Examples
//! Setting up a WebSocket server and handling connections to it:
//! ```no_run
//! # use s2energy::websockets_json::{S2ConnectionError, S2WebsocketServer};
//! # async fn test() -> Result<(), S2ConnectionError> {
//! let server = S2WebsocketServer::new("0.0.0.0:8080").await?;
//! loop {
//!     let s2_connection = server.accept_connection().await?;
//!     // Use the S2 connection here, probably by spawning a task to handle it.
//! }
//! # Ok(()) };
//! ```
//!
//! Setting up a connection as a Resource Manager:
//! ```no_run
//! # use s2energy::common::{Commodity, CommodityQuantity, ControlType, Currency, Duration, Id, ResourceManagerDetails, Role, RoleType};
//! # use s2energy::frbc;
//! # use s2energy::websockets_json::{connect_as_client, S2ConnectionError};
//! # async fn test() -> Result<(), S2ConnectionError> {
//! // Connect to the CEM
//! let mut s2_connection = connect_as_client("wss://example.com/cem/394727").await?;
//!
//! // Create a `ResourceManagerDetails`, which will inform the CEM
//! // about some properties of our device
//! let rm_details = ResourceManagerDetails::builder()
//!     // Required fields
//!     .available_control_types(vec![ControlType::FillRateBasedControl])
//!     .roles(vec![Role { commodity: Commodity::Electricity, role: RoleType::EnergyStorage }])
//!     .provides_forecast(true)
//!     .provides_power_measurement_types(vec![CommodityQuantity::ElectricPower3PhaseSymmetric])
//!     .instruction_processing_delay(Duration(100))
//!     .resource_id(Id::try_from("00000000-1111-2222-3333-444444444444").unwrap())
//!     // Optional fields
//!     .name("Battery Model Q")
//!     .manufacturer("Battery Manufacturing BV")
//!     .model("BatteryQ_v3")
//!     .serial_number("A1-01234-56789")
//!     .firmware_version("0.2.0")
//!     .currency(Currency::Eur)
//!     .build();
//!
//! // Initialize the connection; this will perform
//! // the S2 handshake and version negotiation for you
//! s2_connection.initialize_as_rm(rm_details).await?;
//! # Ok(()) };
//! ```
//!
//! Once you've set up a connection, you can send and receive messages:
//! ```no_run
//! # use s2energy::{frbc, websockets_json::{connect_as_client, S2ConnectionError}};
//! # async fn test() -> Result<(), S2ConnectionError> {
//! # let mut s2_connection = connect_as_client("no_run").await?;
//! // Send a StorageStatus message:
//! s2_connection.send_message(frbc::StorageStatus::new(0.5)).await?;
//!
//! // Handle incoming messages:
//! while let Ok(message) = s2_connection.receive_message().await {
//!     match message.get_message() {
//!         // Validate the incoming message here...
//!         _ => { /* ... */ }
//!     }
//!     
//!     // Message looks good, send back an OK reception status:
//!     message.confirm().await?;
//! }
//! # Ok(()) };
//! ```
use crate::common::{
    ControlType, EnergyManagementRole, Handshake, Id, Message as S2Message, ReceptionStatus, ReceptionStatusValues, ResourceManagerDetails,
};
use futures_util::{SinkExt, StreamExt};
use semver::VersionReq;
use std::str::FromStr;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{self, client::IntoClientRequest, protocol::Message as TungsteniteMessage},
};

/// Errors that occur during an S2 connection over WebSockets.
#[derive(Error, Debug)]
pub enum S2ConnectionError {
    /// We sent a message, and got back a non-OK [`ReceptionStatus`].
    #[error("received non-OK reception status from other party: {0:?}")]
    ReceivedBadReceptionStatus(ReceptionStatus),
    /// Could not parse a received message into a valid S2 message. This is likely a bug on the other end of the connection.
    #[error("error parsing a received message into a valid S2 message")]
    S2MessageParseError(#[from] serde_json::Error),
    /// Could not parse the S2 version sent by the other end of the connection.
    #[error("error parsing the requested S2 version into a valid semver version")]
    S2VersionParseError(#[from] semver::Error),
    /// The CEM requested a version of S2 that is not supported by the build of the library you are using.
    #[error("the CEM requested an incompatible S2 version: {requested:?} was requested, {supported:?} is supported")]
    IncompatibleS2Version {
        supported: semver::Version,
        requested: semver::VersionReq,
    },
    /// Error performing a handshake with the CEM; received a message at a point where that message was not expected (e.g. a [`HandshakeResponse`](crate::common::HandshakeResponse) before we even sent a [`Handshake`])
    #[error(
        "received an unexpected message, or an expected message at an unexpected moment, during the S2 handshaking process: {message:?} ({} Handshake, {} HandshakeResponse)",
        if *handshake_received { "already received" } else { "not yet received" },
        if *handshake_response_received { "already received" } else { "not yet received" },
    )]
    InvalidHandshakeOrder {
        handshake_received: bool,
        handshake_response_received: bool,
        message: S2Message,
    },

    /// Encountered an error on the [`TcpListener`] used internally in [`S2WebsocketServer`].
    #[error("error originating from the internal TCPListener")]
    WebsocketServerError(#[from] tokio::io::Error),
    /// Encountered an error on the WebSocket connection.
    #[error("error from websocket connection")]
    WebsocketError(#[from] tungstenite::Error),
    /// The WebSocket has closed. This may be expected, and does not always indicate an actual error.
    #[error("the websocket has closed")]
    WebsocketClosed,
    /// Received a binary WebSocket message, instead of a text message. Only text messages are supported.
    #[error("received a websocket message in a binary format")]
    ReceivedBinaryMessage,
}

/// A simple S2 WebSocket server.
///
/// You can use this object to accept WebSocket client connections and turn them into [`S2Connection`]s.
///
/// **NOTE**: TLS is NOT set up or handled by this object; it is recommended you use a server in front
/// of this (such as nginx) to handle TLS.
///
/// For example usage, refer to the [module documentation].
///
/// [module documentation]: crate::websockets_json#examples
pub struct S2WebsocketServer {
    listener: TcpListener,
}

impl S2WebsocketServer {
    /// Create a new WebSocket server on the specified socket address.
    ///
    /// This will immediately bind the server to the specified address. To unbind the server,
    /// drop this object.
    pub async fn new(addr: impl ToSocketAddrs) -> Result<Self, S2ConnectionError> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
        })
    }

    /// Accept an S2 connection over WebSockets on this server.
    ///
    /// You probably want to do this in a loop, and spawn a new task to handle each connection (see the [example in the module documentation][crate::websockets_json#examples]).
    pub async fn accept_connection(&self) -> Result<S2Connection, S2ConnectionError> {
        let (tcp_stream, _) = self.listener.accept().await?;
        let ws_stream = tokio_tungstenite::accept_async(tcp_stream).await?;
        Ok(S2Connection::from_server_socket(ws_stream))
    }
}

/// Set up a new S2 connection as a Websocket client.
///
/// The `url` parameter will commonly be a string, but can be a variety of types (such as `httparse::Request`)
/// for convenience.
pub async fn connect_as_client(url: impl IntoClientRequest + Unpin) -> Result<S2Connection, S2ConnectionError> {
    let (socket, _) = tokio_tungstenite::connect_async(url).await?;
    Ok(S2Connection::from_client_socket(socket))
}

/// Wrapper around `WebsocketStream<T>` that unifies the different `T`s you get from tungstenite.
enum WebSocketWrapper {
    ClientSocket(WebSocketStream<MaybeTlsStream<TcpStream>>),
    ServerSocket(WebSocketStream<TcpStream>),
}

impl WebSocketWrapper {
    async fn send(&mut self, item: TungsteniteMessage) -> Result<(), tungstenite::Error> {
        match self {
            Self::ClientSocket(socket) => socket.send(item).await,
            Self::ServerSocket(socket) => socket.send(item).await,
        }
    }

    async fn next(&mut self) -> Option<Result<TungsteniteMessage, tungstenite::Error>> {
        match self {
            Self::ClientSocket(socket) => socket.next().await,
            Self::ServerSocket(socket) => socket.next().await,
        }
    }
}

/// Object representing an S2 connection.
///
/// You can use the methods on this object to easily send and receive S2 messages without worrying
/// about things like (de)serialization and handling [`ReceptionStatus`] messages.
///
/// For example usage, refer to the [module documentation].
///
/// [module documentation]: crate::websockets_json#examples
pub struct S2Connection {
    socket: WebSocketWrapper,
}

impl S2Connection {
    fn from_client_socket(socket: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        Self {
            socket: WebSocketWrapper::ClientSocket(socket),
        }
    }

    fn from_server_socket(socket: WebSocketStream<TcpStream>) -> Self {
        Self {
            socket: WebSocketWrapper::ServerSocket(socket),
        }
    }

    /// Performs an initial handshake with the other end of the connection, which should be a CEM.
    ///
    /// This function performs a handshake as a resource manager (RM). This will send a handshake,
    /// negotiate the correct S2 version with the CEM, and send the provided `ResourceManagerDetails`.
    /// If successful, returns the `ControlType` selected by the CEM.
    ///
    /// After this function returns, you can expect the connection to be 'active' and ready for control messages
    /// and status updates from both sides. If the selected control type is OMBC, FRBC or DDBC, you should probably
    /// send the respective `SystemDescription` after this function returns.
    ///
    /// You should only use this function when implementing an RM.
    pub async fn initialize_as_rm(&mut self, rm_details: ResourceManagerDetails) -> Result<ControlType, S2ConnectionError> {
        let handshake = Handshake::builder()
            .role(EnergyManagementRole::Rm)
            .supported_protocol_versions(vec![crate::s2_schema_version().to_string()])
            .build();
        self.send_message(handshake).await?;

        let mut need_handshake = false;
        let mut need_handshake_response = true;

        loop {
            let message = self.receive_message().await?;
            match message.get_message() {
                S2Message::Handshake(..) if need_handshake => {
                    need_handshake = false;
                }

                S2Message::HandshakeResponse(handshake_response) if need_handshake_response && !need_handshake => {
                    need_handshake_response = false;
                    let requested_version = VersionReq::parse(&handshake_response.selected_protocol_version)?;
                    if !requested_version.matches(&crate::s2_schema_version()) {
                        let error_msg = format!(
                            "CEM requested an incompatible version of S2: requested {}, which is not compatible with {}",
                            requested_version,
                            crate::s2_schema_version()
                        );
                        tracing::warn!("{error_msg:?}");
                        message.error(ReceptionStatusValues::InvalidContent, &error_msg).await?;
                        return Err(S2ConnectionError::IncompatibleS2Version {
                            supported: crate::s2_schema_version(),
                            requested: requested_version.clone(),
                        });
                    }

                    message.confirm().await?;
                    self.send_message(rm_details.clone()).await?;
                    continue;
                }

                S2Message::SelectControlType(select_control_type) if !need_handshake && !need_handshake_response => {
                    tracing::info!("Control type selected by CEM: {:?}", select_control_type.control_type);
                    let control_type = select_control_type.control_type;
                    message.confirm().await?;
                    return Ok(control_type);
                }

                other_message => {
                    let diagnostic = format!("Did not expect message at this point in the handshake process: {:?}", other_message);
                    let message = message.error(ReceptionStatusValues::InvalidContent, &diagnostic).await?;
                    return Err(S2ConnectionError::InvalidHandshakeOrder {
                        message,
                        handshake_received: !need_handshake,
                        handshake_response_received: !need_handshake_response,
                    });
                }
            }

            message.confirm().await?;
        }
    }

    /// Sends the given message over the websocket.
    pub async fn send_message(&mut self, message: impl Into<S2Message>) -> Result<(), S2ConnectionError> {
        let s2_message = message.into();
        tracing::trace!("Sending S2 message: {s2_message:?}");
        let message_str = serde_json::to_string(&s2_message)
            .expect("Could not serialize the given message into JSON; this is a bug and should be reported");
        self.socket.send(TungsteniteMessage::Text(message_str.into())).await?;
        Ok(())
    }

    /// Waits for a message to come over the websocket, and returns it.
    ///
    /// This function sends back a [`ReceptionStatus`] when it receives a message, so you don't need to do that yourself. Additionally, it filters out any received `ReceptionStatus` messages.
    pub async fn receive_message<'connection>(&'connection mut self) -> Result<UnconfirmedMessage<'connection>, S2ConnectionError> {
        // This is set up as a loop so we can harmlessly ignore empty messages and ping/pong messages.
        let message = loop {
            let msg = self.socket.next().await.ok_or(S2ConnectionError::WebsocketClosed)??;

            if msg.is_binary() {
                tracing::warn!("Received binary websocket message, which is not supported. Sending ReceptionStatus INVALID_DATA.");
                let _ = self
                    .send_message(ReceptionStatus {
                        diagnostic_label: Some("Binary messages are not supported".to_string()),
                        status: ReceptionStatusValues::InvalidData,
                        subject_message_id: Id::from_str("00000000-0000-0000-0000-000000000000").unwrap(),
                    })
                    .await;

                return Err(S2ConnectionError::ReceivedBinaryMessage);
            } else if msg.is_close() {
                tracing::info!("Received a websocket close message");
                return Err(S2ConnectionError::WebsocketClosed);
            } else if msg.is_text() {
                let msg_string = msg
                    .into_text()
                    .expect("Encountering a panic here should be impossible; please report a bug in s2energy if you encounter this anyway");

                let msg_parsed = match serde_json::from_str(&msg_string) {
                    Ok(msg) => msg,
                    Err(err) => {
                        tracing::warn!("Failed to parse incoming message. Message: {msg_string}. Error: {err}");
                        let _ = self
                            .send_message(ReceptionStatus {
                                diagnostic_label: Some(format!("Failed to parse message. Error: {err}")),
                                status: ReceptionStatusValues::InvalidData,
                                subject_message_id: Id::from_str("00000000-0000-0000-0000-000000000000").unwrap(),
                            })
                            .await;
                        return Err(err.into());
                    }
                };

                if let S2Message::ReceptionStatus(reception_status @ ReceptionStatus { status, .. }) = &msg_parsed {
                    if *status != ReceptionStatusValues::Ok {
                        return Err(S2ConnectionError::ReceivedBadReceptionStatus(reception_status.clone()));
                    }
                } else {
                    break msg_parsed;
                }
            }
        };

        tracing::trace!("Received S2 message: {message:?}");
        Ok(UnconfirmedMessage::new(message, self))
    }

    /// Wait for a message, and immediately send back a [`ReceptionStatus`].
    ///
    /// This is the equivalent of `connection.receive_message().await?.confirm().await?`.
    pub async fn receive_and_confirm(&mut self) -> Result<S2Message, S2ConnectionError> {
        self.receive_message().await?.confirm().await
    }
}

/// An S2 message for which no [`ReceptionStatus`] has been returned yet.
///
/// In S2, it is mandatory to send back a `ReceptionStatus` for each received message (except `ReceptionStatus` itself).
/// For this reason, an `UnconfirmedMessage` is returned from [`S2Connection::receive_message`]. This allows you to easily
/// send back a `ReceptionStatus` using either [`confirm`](UnconfirmedMessage::confirm) or [`error`](UnconfirmedMessage::error).
///
/// # Lifetimes
/// An `UnconfirmedMessage` contains a reference to the connection it was received on, in order to send back a response. This means
/// that you won't be able to send/receive messages on that connection for as long as you're holding the `UnconfirmedMessage`. For this reason,
/// we recommend a `validate > confirm > handle` pattern, where you validate that a message is valid (using [`get_message`](UnconfirmedMessage::get_message)
/// to inspect the message), confirm it using `confirm` or `error`, and only then do any operations you need to perform as a result of the message.
///
/// If you want to opt out of the hassle altogether, you can [`S2Connection::receive_and_confirm`] to receive messages. This immediately
/// confirms all received messages and gives you an owned [`S2Message`] to work with. The downside, of course, is that in the case of an invalid message
/// you won't be able to let the sending party know that you can't handle that message.
///
/// # Examples
/// ```no_run
/// # use s2energy::common::{ReceptionStatusValues, Message, Id};
/// # use s2energy::frbc;
/// # use s2energy::websockets_json::{connect_as_client, S2ConnectionError};
/// # async fn test() -> Result<(), S2ConnectionError> {
/// # let mut s2_connection = connect_as_client("wss://example.com/cem/394727").await?;
/// // Inspect the message and ensure its contents match our expectations:
/// let message = s2_connection.receive_message().await?;
/// if let Message::FrbcInstruction(instruction) = message.get_message() {
///     message.confirm().await?;
/// } else {
///     message.error(ReceptionStatusValues::InvalidContent, "Expected an FRBC.Instruction").await?;
/// }
/// # Ok(())
/// # }
/// ```
pub struct UnconfirmedMessage<'conn> {
    message: Option<S2Message>,
    connection: &'conn mut S2Connection,
}

impl<'conn> UnconfirmedMessage<'conn> {
    fn new(message: S2Message, connection: &'conn mut S2Connection) -> UnconfirmedMessage<'conn> {
        Self {
            message: Some(message),
            connection,
        }
    }

    /// Sends back an OK [`ReceptionStatus`].
    ///
    /// Use this to let the other side of the connection know that you've received and validated the message.
    /// If there is a problem with the message (e.g. you can't handle it, or its contents are invalid), use [`error`](`UnconfirmedMessage::error`) instead.
    pub async fn confirm(mut self) -> Result<S2Message, S2ConnectionError> {
        let message = self
            .message
            .take()
            .expect("No message contained in UnconfirmedMessage; this is a bug in s2energy and should be reported");
        let Some(message_id) = message.id() else { return Ok(message) };
        self.connection
            .send_message(
                ReceptionStatus::builder()
                    .status(ReceptionStatusValues::Ok)
                    .subject_message_id(message_id)
                    .build(),
            )
            .await?;
        Ok(message)
    }

    /// Sends back an error-valued [`ReceptionStatus`].
    ///
    /// Use this to let the other side of the connection know that there's a problem with the message. Use [`ReceptionStatusValues::InvalidContent`] for
    /// cases where the content of the message was somehow invalid (e.g. it refers to a non-existent actuator ID). Use [`ReceptionStatusValues::TemporaryError`] or
    /// [`ReceptionStatusValues::PermanentError`] for cases where the message was valid, but you can't handle it for some reason.
    ///
    /// You can use the `diagnostic_message` parameter to send along human-readable diagnostic information. This is helpful for people debugging
    /// their RM/CEM implementation or for logging issues.
    pub async fn error(mut self, status: ReceptionStatusValues, diagnostic_message: &str) -> Result<S2Message, S2ConnectionError> {
        let message = self
            .message
            .take()
            .expect("No message contained in UnconfirmedMessage; this is a bug in s2energy and should be reported");
        let Some(message_id) = message.id() else { return Ok(message) };
        tracing::warn!("Sending reception status {status:?} in response to message {message_id:?}");
        self.connection
            .send_message(
                ReceptionStatus::builder()
                    .diagnostic_label(diagnostic_message.to_string())
                    .status(status)
                    .subject_message_id(message_id)
                    .build(),
            )
            .await?;
        Ok(message)
    }

    /// Get a reference to the contained S2 message.
    ///
    /// This is useful for cases where you want to inspect the received message to determine whether to send back an OK or
    /// an error `ReceptionStatus`.
    pub fn get_message(&self) -> &S2Message {
        self.message
            .as_ref()
            .expect("No message contained in UnconfirmedMessage; this is a bug in s2energy and should be reported")
    }

    /// Extract the contained S2 message, without confirming it.
    ///
    /// **Warning**: when you use this function, you become responsible for sending back an appropriate `ReceptionStatus`.
    /// You must do so in order to comply to the S2 spec, and failure to do so may result in unexpected behaviour from other
    /// S2 implementations you are connecting with.
    pub fn into_inner(mut self) -> S2Message {
        self.message
            .take()
            .expect("No message contained in UnconfirmedMessage; this is a bug in s2energy and should be reported")
    }
}

impl<'conn> Drop for UnconfirmedMessage<'conn> {
    fn drop(&mut self) {
        if !std::thread::panicking() && self.message.is_some() {
            panic!(
                "Dropped an `UnconfirmedMessage` without calling `confirm`, `bad_status` or `into_inner`. Please refer to the `UnconfirmedMessage` documentation for proper usage."
            );
        }
    }
}
