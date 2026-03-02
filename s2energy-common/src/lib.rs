//! Shared types for S2 protocols.
//!
//! This crate contains types shared between the communication and message layers of [the s2-ws-json protocol](https://github.com/flexiblepower/s2-ws-json).
#![warn(missing_docs)]

use std::error::Error;

use serde::{Serialize, de::DeserializeOwned};

/// Trait used to abstract the underlying transport protocol.
///
/// **End-users are not expected to use this trait directly.** Instead, libraries can implement this trait to provide additional
/// transport protocols that can be used to talk S2 over.
pub trait S2Transport {
    /// Error type for errors occurring at a transport level.
    type TransportError: Error + S2ErrorExt;

    /// Send an S2 message.
    fn send(&mut self, message: impl Serialize + Send) -> impl Future<Output = Result<(), Self::TransportError>> + Send;

    /// Recceive an S2 message.
    fn receive<Message: DeserializeOwned + Send>(&mut self) -> impl Future<Output = Result<Message, Self::TransportError>> + Send;

    /// Disconnect this connection.
    ///
    /// This should do whatever is appropriate for the implemented transport protocol. This may include sending
    /// e.g. a close frame. When the future resolves, the connection should be fully terminated.
    fn disconnect(self) -> impl Future<Output = ()> + Send;
}

/// Extension to the Error trait to allow transport layers to indicate that a specific
/// error was the result from serialization failures. This allows the messaging layer to
/// then generate the appropriate error message for to send in response.
pub trait S2ErrorExt {
    /// Was the error because of (de)serialization.
    fn is_serialization_error(&self) -> bool;
}

impl S2ErrorExt for std::convert::Infallible {
    fn is_serialization_error(&self) -> bool {
        false
    }
}
