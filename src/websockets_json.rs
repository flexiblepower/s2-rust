//! Utilities for easily setting up a WebSocket connection to talk S2 over.
//!
//! This module contains functions to set up a WebSocket connection and send/receive S2 messages.
//! [`S2Connection`] is the primary API for doing this: it provides functions for easy sending/receiving of
//! S2 messages, and can perform the initial handshake and version negotiation for you. This module
//! uses [`tokio`] as its async runtime.
//!
//! If you want to connect as a WebSocket client, you can use [`connect_as_client`] to obtain an `S2Connection`.
//! If you want to connect as a WebSocket server, you should make an [`S2WebsocketServer`] and accept connections
//! via [`accept_connection`][S2WebsocketServer::accept_connection].
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
//! Basic resource manager flow - setting up an S2 connection as a client and sending a message:
//! ```no_run
//! # use s2energy::common::{Commodity, CommodityQuantity, ControlType, Currency, Duration, Id, ResourceManagerDetails, Role, RoleType};
//! # use s2energy::frbc;
//! # use s2energy::websockets_json::{connect_as_client, S2ConnectionError};
//! # async fn test() -> Result<(), S2ConnectionError> {
//! // Connect to the CEM
//! let mut s2_connection = connect_as_client("wss://example.com/cem/394727").await?;
//!
//! // Create `ResourceManagerDetails`, which will inform the CEM about some properties of our device
//! let rm_details = ResourceManagerDetails {
//!     available_control_types: vec![ControlType::FillRateBasedControl],
//!     roles: vec![Role::new(Commodity::Electricity, RoleType::EnergyStorage)],
//!     provides_forecast: true,
//!     provides_power_measurement_types: vec![CommodityQuantity::ElectricPower3PhaseSymmetric],
//!     name: Some(String::from("Generic Battery Model Q")),
//!     manufacturer: Some(String::from("Battery Manufacturing BV")),
//!     model: Some(String::from("GenericBatteryQ_v3")),
//!     serial_number: Some(String::from("111-222-333")),
//!     firmware_version: Some(String::from("1.0.0")),
//!     instruction_processing_delay: Duration(100),
//!     currency: Some(Currency::Eur),
//!     resource_id: Id::generate(),
//!     message_id: Id::generate(),
//! };
//!
//! // Initialize the connection; this will perform the S2 handshake and version negotiation for you
//! s2_connection.initialize_as_rm(rm_details).await?;
//!
//! // Send a StorageStatus message; you probably want to send a frbc::SystemDescription as well
//! s2_connection.send_message(frbc::StorageStatus::new(0.5)).await?;
//!
//! # Ok(()) };
//! ```
use crate::common::{
    ControlType, EnergyManagementRole, Handshake, Message as S2Message, ReceptionStatus, ReceptionStatusValues, ResourceManagerDetails,
};
use futures_util::{SinkExt, StreamExt};
use semver::VersionReq;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_tungstenite::{
    tungstenite::{self, client::IntoClientRequest, protocol::Message as TungsteniteMessage},
    MaybeTlsStream, WebSocketStream,
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
    #[error("received an unexpected message, or an expected message at an unexpected moment, during the S2 handshaking process: {message:?}")]
    InvalidHandshakeOrder { message: S2Message },

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
pub struct S2Connection {
    socket: WebSocketWrapper,
}

impl S2Connection {
    fn from_client_socket(socket: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        Self { socket: WebSocketWrapper::ClientSocket(socket) }
    }

    fn from_server_socket(socket: WebSocketStream<TcpStream>) -> Self {
        Self { socket: WebSocketWrapper::ServerSocket(socket) }
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
        let handshake = Handshake::new(EnergyManagementRole::Rm, vec![crate::s2_schema_version().to_string()]);
        self.send_message(handshake).await?;

        let mut need_handshake = true;
        let mut need_handshake_response = true;

        while let Ok(message) = self.receive_message().await {
            if let S2Message::Handshake(..) = &message {
                if need_handshake {
                    need_handshake = false;
                } else {
                    return Err(S2ConnectionError::InvalidHandshakeOrder { message });
                }
            }

            if let S2Message::HandshakeResponse(handshake_response) = &message {
                if need_handshake_response {
                    need_handshake_response = false;
                    let requested_version = VersionReq::parse(&handshake_response.selected_protocol_version)?;
                    if !requested_version.matches(&crate::s2_schema_version()) {
                        return Err(S2ConnectionError::IncompatibleS2Version {
                            supported: crate::s2_schema_version(),
                            requested: requested_version.clone(),
                        });
                    }
                } else {
                    return Err(S2ConnectionError::InvalidHandshakeOrder { message });
                }
            }

            // Note that this is NOT exclusive with the if-blocks above
            if matches!(message, S2Message::Handshake(..) | S2Message::HandshakeResponse(..)) && !need_handshake && !need_handshake_response {
                self.send_message(rm_details.clone()).await?;
            }

            if let S2Message::SelectControlType(select_control_type) = &message {
                if need_handshake || need_handshake_response {
                    return Err(S2ConnectionError::InvalidHandshakeOrder { message });
                }

                return Ok(select_control_type.control_type);
            }
        }

        // If we reach this point, we've reached the end of the stream without exchanging handshakes.
        return Err(S2ConnectionError::WebsocketClosed);
    }

    /// Sends the given message over the websocket.
    pub async fn send_message(&mut self, message: impl Into<S2Message>) -> Result<(), S2ConnectionError> {
        let s2_message = message.into();
        let message_str = serde_json::to_string(&s2_message)
            .expect("Could not serialize the given message into JSON; this is a bug and should be reported");
        self.socket.send(TungsteniteMessage::Text(message_str)).await?;
        Ok(())
    }

    /// Waits for a message to come over the websocket, and returns it.
    ///
    /// This function sends back a [`ReceptionStatus`] when it receives a message, so you don't need to do that yourself. Additionally, it filters out any received `ReceptionStatus` messages.
    pub async fn receive_message(&mut self) -> Result<S2Message, S2ConnectionError> {
        // This is set up as a loop so we can harmlessly ignore empty messages and ping/pong messages.
        let message = loop {
            let msg = self.socket.next().await.ok_or(S2ConnectionError::WebsocketClosed)??;

            if msg.is_binary() {
                return Err(S2ConnectionError::ReceivedBinaryMessage);
            } else if msg.is_close() {
                return Err(S2ConnectionError::WebsocketClosed);
            } else if msg.is_text() {
                let msg_string = msg
                    .into_text()
                    .expect("Encountering a panic here should be impossible; please report a bug if you encounter this anyway");
                break serde_json::from_str(&msg_string)?;
            }
        };

        if !matches!(message, S2Message::Handshake(..)) && !matches!(message, S2Message::ReceptionStatus(..)) {
            let status = ReceptionStatus::new(None, ReceptionStatusValues::Ok, message.id().expect("Failed to extract ID from message; please report a bug if you encounter this"));
            self.send_message(S2Message::ReceptionStatus(status)).await?;
        }

        if let S2Message::ReceptionStatus(reception_status @ ReceptionStatus { status, .. }) = &message {
            if *status != ReceptionStatusValues::Ok {
                return Err(S2ConnectionError::ReceivedBadReceptionStatus(reception_status.clone()));
            }
        }

        Ok(message)
    }
}
