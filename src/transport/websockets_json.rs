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
//! # use s2energy::transport::websockets_json::{WebsocketServer, WebsocketTransport};
//! # use s2energy::connection::ConnectionError;
//! # async fn test() -> Result<(), ConnectionError<WebsocketTransport>> {
//! let server = WebsocketServer::new("0.0.0.0:8080").await?;
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
//! # use s2energy::transport::websockets_json::{connect_as_client, WebsocketTransport};
//! # use s2energy::connection::ConnectionError;
//! # async fn test() -> Result<(), ConnectionError<WebsocketTransport>> {
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
//! # use s2energy::{frbc, connection::ConnectionError, transport::websockets_json::{connect_as_client, WebsocketTransport}};
//! # async fn test() -> Result<(), ConnectionError<WebsocketTransport>> {
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
use crate::{
    common::{Id, Message as S2Message, ReceptionStatus, ReceptionStatusValues},
    connection::{ConnectionError, S2Connection},
    transport::S2Transport,
};
use futures_util::{SinkExt, StreamExt};
use std::str::FromStr;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{self, client::IntoClientRequest, protocol::Message as TungsteniteMessage},
};

/// Errors that can occur on the websocket connection.
#[derive(Error, Debug)]
pub enum WebsocketTransportError {
    /// Encountered an error on the [`TcpListener`] used internally in [`S2WebsocketServer`].
    #[error("error originating from the internal TCPListener: {0}")]
    WebsocketServerError(#[from] tokio::io::Error),

    /// Encountered an error on the WebSocket connection.
    #[error("error from websocket connection: {0}")]
    WebsocketError(#[from] tungstenite::Error),

    /// The WebSocket has closed. This may be expected, and does not always indicate an actual error.
    #[error("the websocket has closed")]
    WebsocketClosed,

    /// Received a binary WebSocket message, instead of a text message. Only text messages are supported.
    #[error("received a websocket message in a binary format")]
    ReceivedBinaryMessage,

    /// Could not parse a received JSON message into a valid S2 message. This is likely a bug on the other end of the connection.
    #[error("error parsing a received JSON message into a valid S2 message: {0}")]
    MessageParseError(#[from] serde_json::Error),
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
pub struct WebsocketServer {
    listener: TcpListener,
}

impl WebsocketServer {
    /// Create a new WebSocket server on the specified socket address.
    ///
    /// This will immediately bind the server to the specified address. To unbind the server,
    /// drop this object.
    pub async fn new(addr: impl ToSocketAddrs) -> Result<Self, ConnectionError<WebsocketTransportError>> {
        Ok(Self {
            listener: TcpListener::bind(addr)
                .await
                .map_err(Into::into)
                .map_err(ConnectionError::TransportError)?,
        })
    }

    /// Accept an S2 connection over WebSockets on this server.
    ///
    /// You probably want to do this in a loop, and spawn a new task to handle each connection (see the [example in the module documentation][crate::websockets_json#examples]).
    pub async fn accept_connection(&self) -> Result<S2Connection<WebsocketTransport>, ConnectionError<WebsocketTransportError>> {
        let (tcp_stream, _) = self
            .listener
            .accept()
            .await
            .map_err(Into::into)
            .map_err(ConnectionError::TransportError)?;
        let ws_stream = tokio_tungstenite::accept_async(tcp_stream)
            .await
            .map_err(Into::into)
            .map_err(ConnectionError::TransportError)?;
        let ws_transport = WebsocketTransport::from_server_socket(ws_stream);
        Ok(S2Connection::new(ws_transport))
    }
}

/// Set up a new S2 connection as a Websocket client.
///
/// The `url` parameter will commonly be a string, but can be a variety of types (such as `httparse::Request`)
/// for convenience.
pub async fn connect_as_client(
    url: impl IntoClientRequest + Unpin,
) -> Result<S2Connection<WebsocketTransport>, ConnectionError<WebsocketTransportError>> {
    let (socket, _) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(Into::into)
        .map_err(ConnectionError::TransportError)?;
    let ws_transport = WebsocketTransport::from_client_socket(socket);
    Ok(S2Connection::new(ws_transport))
}

pub enum WebsocketTransport {
    ClientSocket(WebSocketStream<MaybeTlsStream<TcpStream>>),
    ServerSocket(WebSocketStream<TcpStream>),
}

impl WebsocketTransport {
    fn from_client_socket(socket: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        WebsocketTransport::ClientSocket(socket)
    }

    fn from_server_socket(socket: WebSocketStream<TcpStream>) -> Self {
        WebsocketTransport::ServerSocket(socket)
    }
}

impl S2Transport for WebsocketTransport {
    type TransportError = WebsocketTransportError;

    async fn send(&mut self, message: S2Message) -> Result<(), WebsocketTransportError> {
        let serialized =
            serde_json::to_string(&message).expect("unable to seralize `Message` to JSON; if you see this, you've found a bug in s2energy");
        let tungstenite_message = TungsteniteMessage::text(serialized);
        match self {
            Self::ClientSocket(socket) => socket.send(tungstenite_message).await?,
            Self::ServerSocket(socket) => socket.send(tungstenite_message).await?,
        }

        Ok(())
    }

    async fn receive(&mut self) -> Result<S2Message, WebsocketTransportError> {
        // This is set up as a loop so we can harmlessly ignore empty messages and ping/pong messages.
        let message = loop {
            let next = match self {
                Self::ClientSocket(socket) => socket.next().await,
                Self::ServerSocket(socket) => socket.next().await,
            };
            let Some(msg) = next else {
                return Err(WebsocketTransportError::WebsocketClosed);
            };
            let msg = msg?;

            if msg.is_binary() {
                tracing::warn!("Received binary websocket message, which is not supported. Sending ReceptionStatus INVALID_DATA.");
                let _ = self
                    .send(
                        ReceptionStatus {
                            diagnostic_label: Some("Binary messages are not supported".to_string()),
                            status: ReceptionStatusValues::InvalidData,
                            subject_message_id: Id::from_str("00000000-0000-0000-0000-000000000000").unwrap(),
                        }
                        .into(),
                    )
                    .await;

                return Err(WebsocketTransportError::ReceivedBinaryMessage);
            } else if msg.is_close() {
                tracing::info!("Received a websocket close message");
                return Err(WebsocketTransportError::WebsocketClosed);
            } else if msg.is_text() {
                let msg_string = msg
                    .into_text()
                    .expect("Encountering a panic here should be impossible; please report a bug in s2energy if you encounter this anyway");

                let msg_parsed = match serde_json::from_str(&msg_string) {
                    Ok(msg) => msg,
                    Err(err) => {
                        tracing::warn!("Failed to parse incoming message. Message: {msg_string}. Error: {err}");
                        let _ = self
                            .send(
                                ReceptionStatus {
                                    diagnostic_label: Some(format!("Failed to parse message. Error: {err}")),
                                    status: ReceptionStatusValues::InvalidData,
                                    subject_message_id: Id::from_str("00000000-0000-0000-0000-000000000000").unwrap(),
                                }
                                .into(),
                            )
                            .await;
                        return Err(err.into());
                    }
                };
                break msg_parsed;
            }
        };

        Ok(message)
    }

    async fn disconnect(self) {
        let msg = TungsteniteMessage::Close(None);
        let _ = match self {
            Self::ClientSocket(mut socket) => socket.send(msg).await,
            Self::ServerSocket(mut socket) => socket.send(msg).await,
        };
    }
}
