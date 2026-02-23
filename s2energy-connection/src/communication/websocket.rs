use futures_util::{SinkExt, StreamExt};
use s2energy_common::S2Transport;
use thiserror::Error;
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

#[derive(Debug, Clone, Error)]
pub enum WebSocketError {
    #[error("Transport failed")]
    Transport,
    #[error("Could not encode/decode message")]
    Encoding,
    #[error("Connection is closed")]
    Closed,
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
                serde_json::to_string(&message).map_err(|_| WebSocketError::Encoding)?.into(),
            ))
            .await
            .map_err(|_| WebSocketError::Transport)
    }

    async fn receive<S2Message: serde::de::DeserializeOwned + Send>(&mut self) -> Result<S2Message, Self::TransportError> {
        while let Some(message) = self.inner.recv().await.transpose().map_err(|_| WebSocketError::Transport)? {
            match message {
                Message::Text(utf8_bytes) => return serde_json::from_str::<S2Message>(&utf8_bytes).map_err(|_| WebSocketError::Encoding),
                Message::Binary(_) => return Err(WebSocketError::Encoding),
                Message::Ping(_) | Message::Pong(_) | Message::Close(_) => { /* handled by tungstenite */ }
                Message::Frame(_) => return Err(WebSocketError::Encoding),
            }
        }

        Err(WebSocketError::Closed)
    }

    async fn disconnect(self) {
        self.inner.close().await;
    }
}
