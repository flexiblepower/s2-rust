use futures_util::{SinkExt, StreamExt};
use s2energy_common::{S2ErrorExt, S2Transport};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Message};

use crate::common::websocket_extractor::TokioIo;

#[allow(clippy::large_enum_variant)]
enum WebSocketImplementation {
    Server(WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>),
    Client(WebSocketStream<MaybeTlsStream<TcpStream>>),
}

impl WebSocketImplementation {
    async fn send(&mut self, message: Message) -> Result<(), tokio_tungstenite::tungstenite::Error> {
        match self {
            WebSocketImplementation::Server(web_socket_stream) => web_socket_stream.send(message).await,
            WebSocketImplementation::Client(web_socket_stream) => web_socket_stream.send(message).await,
        }
    }

    async fn recv(&mut self) -> Option<Result<Message, tokio_tungstenite::tungstenite::Error>> {
        match self {
            WebSocketImplementation::Server(web_socket_stream) => web_socket_stream.next().await,
            WebSocketImplementation::Client(web_socket_stream) => web_socket_stream.next().await,
        }
    }

    async fn close(self) {
        match self {
            WebSocketImplementation::Server(mut web_socket_stream) => web_socket_stream.close(None).await.ok(),
            WebSocketImplementation::Client(mut web_socket_stream) => web_socket_stream.close(None).await.ok(),
        };
    }
}

#[derive(Debug)]
pub struct WebSocketError {
    kind: WebSocketErrorKind,
    wrapped_error: WrappedError,
}

impl WebSocketError {
    #[allow(
        private_bounds,
        reason = "WrappedError is an implementation detail, caller cares only that about whether the proper conversion exists for his type."
    )]
    pub(crate) fn new<E: Into<WrappedError>>(kind: WebSocketErrorKind, inner: E) -> Self {
        Self {
            kind,
            wrapped_error: inner.into(),
        }
    }

    pub fn kind(&self) -> WebSocketErrorKind {
        self.kind
    }
}

impl std::fmt::Display for WebSocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(inner) = self.wrapped_error.contents() {
            write!(f, "{}: {inner}", self.kind)
        } else {
            self.kind.fmt(f)
        }
    }
}

impl std::error::Error for WebSocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.wrapped_error.contents()
    }
}

impl S2ErrorExt for WebSocketError {
    fn is_serialization_error(&self) -> bool {
        match self.kind {
            WebSocketErrorKind::Encoding => true,
            WebSocketErrorKind::Transport | WebSocketErrorKind::Closed => false,
        }
    }
}

impl From<WebSocketErrorKind> for WebSocketError {
    fn from(kind: WebSocketErrorKind) -> Self {
        Self {
            kind,
            wrapped_error: WrappedError::None,
        }
    }
}

#[derive(Debug)]
enum WrappedError {
    None,
    Json(serde_json::Error),
    Tungstenite(tokio_tungstenite::tungstenite::Error),
}

impl WrappedError {
    fn contents(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::None => None,
            Self::Json(error) => Some(error),
            Self::Tungstenite(error) => Some(error),
        }
    }
}

impl From<serde_json::Error> for WrappedError {
    fn from(value: serde_json::Error) -> Self {
        WrappedError::Json(value)
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for WrappedError {
    fn from(value: tokio_tungstenite::tungstenite::Error) -> Self {
        WrappedError::Tungstenite(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebSocketErrorKind {
    Transport,
    Encoding,
    Closed,
}

impl std::fmt::Display for WebSocketErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport => f.write_str("Could not send or receive protocol message"),
            Self::Encoding => f.write_str("Could not encode or decode received protocol message"),
            Self::Closed => f.write_str("Connection is closed"),
        }
    }
}

pub struct WebSocketTransport {
    inner: WebSocketImplementation,
}

impl WebSocketTransport {
    pub(crate) fn new_server(inner: WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>) -> Self {
        Self {
            inner: WebSocketImplementation::Server(inner),
        }
    }

    pub(crate) fn new_client(inner: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        Self {
            inner: WebSocketImplementation::Client(inner),
        }
    }
}

impl S2Transport for WebSocketTransport {
    type TransportError = WebSocketError;

    async fn send(&mut self, message: impl serde::Serialize + Send) -> Result<(), Self::TransportError> {
        self.inner
            .send(Message::Text(
                serde_json::to_string(&message)
                    .map_err(|e| WebSocketError::new(WebSocketErrorKind::Encoding, e))?
                    .into(),
            ))
            .await
            .map_err(|e| WebSocketError::new(WebSocketErrorKind::Transport, e))
    }

    async fn receive<S2Message: serde::de::DeserializeOwned + Send>(&mut self) -> Result<S2Message, Self::TransportError> {
        while let Some(message) = self
            .inner
            .recv()
            .await
            .transpose()
            .map_err(|e| WebSocketError::new(WebSocketErrorKind::Transport, e))?
        {
            match message {
                Message::Text(utf8_bytes) => {
                    return serde_json::from_str::<S2Message>(&utf8_bytes)
                        .map_err(|e| WebSocketError::new(WebSocketErrorKind::Encoding, e));
                }
                Message::Binary(_) => return Err(WebSocketErrorKind::Encoding.into()),
                Message::Ping(_) | Message::Pong(_) | Message::Close(_) => { /* handled by tungstenite */ }
                Message::Frame(_) => return Err(WebSocketErrorKind::Encoding.into()),
            }
        }

        Err(WebSocketErrorKind::Closed.into())
    }

    async fn disconnect(self) {
        self.inner.close().await;
    }
}
