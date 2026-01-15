//! Types and utilities for S2 connections.
//!
//! The most important type in this module is [`S2Connection`], which you can use to send/receive S2 messages.
//! An `S2Connection` is acquired from an implementing transport protocol, for example by using
//! [`websockets_json::connect_as_client`](crate::transport::websockets_json::connect_as_client).

use crate::{
    common::{ControlType, EnergyManagementRole, Handshake, Message, ReceptionStatus, ReceptionStatusValues, ResourceManagerDetails},
    transport::S2Transport,
};
use semver::VersionReq;
use thiserror::Error;

/// An error from the S2 connection.
#[derive(Error, Debug)]
pub enum ConnectionError<T: std::error::Error> {
    /// An error from the underlying `S2Transport`.
    #[error("an error occurred in the underlying transport: {0}")]
    TransportError(#[source] T),

    /// A situation occurred that is in violation of the S2 specification.
    #[error("a situation occurred that is in violation of the S2 specification: {0}")]
    ProtocolError(#[from] ProtocolError),
}

/// Errors for situations where a violation of the S2 specification has occurred.
#[derive(Error, Debug)]
pub enum ProtocolError {
    /// Could not parse the S2 version sent by the other end of the connection.
    #[error("error parsing the requested S2 version into a valid semver version: {0}")]
    S2VersionParseError(#[from] semver::Error),

    /// The CEM requested a version of S2 that is not supported by the build of the library you are using.
    #[error("the CEM requested an incompatible S2 version: {requested:?} was requested, {supported:?} is supported")]
    IncompatibleS2Version {
        /// The version of S2 supported by this implementation.
        supported: semver::Version,
        /// The version of S2 requested by the CEM.
        requested: VersionReq,
    },

    /// Error performing a handshake with the CEM; received a message at a point where that message was not expected (e.g. a [`HandshakeResponse`](crate::common::HandshakeResponse) before we even sent a [`Handshake`])
    #[error(
        "received an unexpected message, or an expected message at an unexpected moment, during the S2 handshaking process: {message:?} ({} Handshake, {} HandshakeResponse)",
        if *handshake_received { "already received" } else { "not yet received" },
        if *handshake_response_received { "already received" } else { "not yet received" },
    )]
    InvalidHandshakeOrder {
        /// The unexpectedly received message.
        message: Message,
        /// Did we already receive a [`Handshake`] before receiving this message?
        handshake_received: bool,
        /// Did we already receive a [`HandshakeResponse`](crate::common::HandshakeResponse) before receiving this message?
        handshake_response_received: bool,
    },
}

/// A connection able to send and receive S2 messages.
#[derive(Clone, Debug)]
pub struct S2Connection<T: S2Transport> {
    transport: T,
}

impl<T: S2Transport> S2Connection<T> {
    /// Creates a new `S2Connection` with `transport` as the underlying transport. Users generally won't
    /// use this, and instead receive `S2Connection` directly from the connector they're using
    /// (e.g. [`WebsocketServer`](crate::transport::websockets_json::WebsocketServer)).
    pub fn new(transport: T) -> S2Connection<T> {
        Self { transport }
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
    pub async fn initialize_as_rm(
        &mut self,
        rm_details: ResourceManagerDetails,
    ) -> Result<ControlType, ConnectionError<T::TransportError>> {
        let handshake = Handshake::builder()
            .role(EnergyManagementRole::Rm)
            .supported_protocol_versions(vec![crate::s2_schema_version().to_string()])
            .build();
        self.send_message(handshake).await?;

        let mut need_handshake = true;
        let mut need_handshake_response = true;

        loop {
            let message = self.receive_message().await?;
            match message.get_message() {
                Message::Handshake(..) if need_handshake => {
                    need_handshake = false;
                }

                Message::HandshakeResponse(handshake_response) if need_handshake_response && !need_handshake => {
                    need_handshake_response = false;
                    let requested_version = VersionReq::parse(&handshake_response.selected_protocol_version)
                        .map_err(|err| ProtocolError::S2VersionParseError(err))?;
                    if !requested_version.matches(&crate::s2_schema_version()) {
                        let error_msg = format!(
                            "CEM requested an incompatible version of S2: requested {}, which is not compatible with {}",
                            requested_version,
                            crate::s2_schema_version()
                        );
                        tracing::warn!("{error_msg:?}");
                        message.error(ReceptionStatusValues::InvalidContent, &error_msg).await?;
                        return Err(ProtocolError::IncompatibleS2Version {
                            supported: crate::s2_schema_version(),
                            requested: requested_version.clone(),
                        }
                        .into());
                    }

                    message.confirm().await?;
                    self.send_message(rm_details.clone()).await?;
                    continue;
                }

                Message::SelectControlType(select_control_type) if !need_handshake && !need_handshake_response => {
                    tracing::info!("Control type selected by CEM: {:?}", select_control_type.control_type);
                    let control_type = select_control_type.control_type;
                    message.confirm().await?;
                    return Ok(control_type);
                }

                other_message => {
                    let diagnostic = format!("Did not expect message at this point in the handshake process: {:?}", other_message);
                    let message = message.error(ReceptionStatusValues::InvalidContent, &diagnostic).await?;
                    return Err(ProtocolError::InvalidHandshakeOrder {
                        message,
                        handshake_received: !need_handshake,
                        handshake_response_received: !need_handshake_response,
                    }
                    .into());
                }
            }

            message.confirm().await?;
        }
    }

    /// Sends the given message over the websocket.
    pub async fn send_message(&mut self, message: impl Into<Message>) -> Result<(), ConnectionError<T::TransportError>> {
        self.transport.send(message.into()).await.map_err(ConnectionError::TransportError)?;
        Ok(())
    }

    /// Waits for a message to come over the websocket, and returns it.
    ///
    /// This function sends back a [`ReceptionStatus`] when it receives a message, so you don't need to do that yourself. Additionally, it filters out any received `ReceptionStatus` messages.
    pub async fn receive_message<'connection>(
        &'connection mut self,
    ) -> Result<UnconfirmedMessage<'connection, T>, ConnectionError<T::TransportError>> {
        let message = self.transport.receive().await.map_err(ConnectionError::TransportError)?;
        tracing::trace!("Received S2 message: {message:?}");
        Ok(UnconfirmedMessage::new(message, self))
    }

    /// Wait for a message, and immediately send back a [`ReceptionStatus`].
    ///
    /// This is the equivalent of `connection.receive_message().await?.confirm().await?`.
    pub async fn receive_and_confirm(&mut self) -> Result<Message, ConnectionError<T::TransportError>> {
        self.receive_message().await?.confirm().await
    }

    /// Properly disconnects this connection.
    ///
    /// Depending on the underlying transport, this can range from simply dropping the connection object to sending disconnection messages.
    pub async fn disconnect(self) {
        self.transport.disconnect().await
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
/// ```
/// # use s2energy::common::{ReceptionStatusValues, Message, Id};
/// # use s2energy::frbc;
/// # use s2energy::transport::{S2Transport, test::MockTransport};
/// # use s2energy::connection::ConnectionError;
/// # async fn test() -> Result<(), ConnectionError<<MockTransport as S2Transport>::TransportError>> {
/// # let mut s2_connection = MockTransport::new_connection();
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
pub struct UnconfirmedMessage<'conn, T: S2Transport> {
    message: Option<Message>,
    connection: &'conn mut S2Connection<T>,
}

impl<'conn, T: S2Transport> UnconfirmedMessage<'conn, T> {
    fn new(message: Message, connection: &'conn mut S2Connection<T>) -> UnconfirmedMessage<'conn, T> {
        Self {
            message: Some(message),
            connection,
        }
    }

    /// Sends back an OK [`ReceptionStatus`].
    ///
    /// Use this to let the other side of the connection know that you've received and validated the message.
    /// If there is a problem with the message (e.g. you can't handle it, or its contents are invalid), use [`error`](`UnconfirmedMessage::error`) instead.
    pub async fn confirm(mut self) -> Result<Message, ConnectionError<T::TransportError>> {
        let message = self
            .message
            .take()
            .expect("No message contained in UnconfirmedMessage; this is a bug in s2energy and should be reported");
        if matches!(message, Message::ReceptionStatus(..)) {
            return Ok(message);
        }

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
    pub async fn error(
        mut self,
        status: ReceptionStatusValues,
        diagnostic_message: &str,
    ) -> Result<Message, ConnectionError<T::TransportError>> {
        let message = self
            .message
            .take()
            .expect("No message contained in UnconfirmedMessage; this is a bug in s2energy and should be reported");
        if matches!(message, Message::ReceptionStatus(..)) {
            return Ok(message);
        }

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
    pub fn get_message(&self) -> &Message {
        self.message
            .as_ref()
            .expect("No message contained in UnconfirmedMessage; this is a bug in s2energy and should be reported")
    }

    /// Extract the contained S2 message, without confirming it.
    ///
    /// **Warning**: when you use this function, you become responsible for sending back an appropriate `ReceptionStatus`.
    /// You must do so in order to comply to the S2 spec, and failure to do so may result in unexpected behaviour from other
    /// S2 implementations you are connecting with.
    pub fn into_inner(mut self) -> Message {
        self.message
            .take()
            .expect("No message contained in UnconfirmedMessage; this is a bug in s2energy and should be reported")
    }
}

impl<'conn, T: S2Transport> Drop for UnconfirmedMessage<'conn, T> {
    fn drop(&mut self) {
        if !std::thread::panicking() && self.message.is_some() {
            panic!(
                "Dropped an `UnconfirmedMessage` without calling `confirm`, `bad_status` or `into_inner`. Please refer to the `UnconfirmedMessage` documentation for proper usage."
            );
        }
    }
}
