//! Abstractions over transport protocols, and their implementations.
//!
//! The S2 specification does not mandate a specific transport protocol. This module provides the primary way
//! transport protocols are abstracted in this crate: [`S2Transport`]. Implementing this trait for your
//! desired transport protocol allows you to use all of the connection types in this library (like [`S2Connection`](crate::connection::S2Connection))
//! with that transport protocol.
//!
//! In addition, this module provides specific transport protocol implementations in its submodules.
//! The most relevant of these is [`websockets_json`], which provides an implementation for JSON over
//! WebSockets according to [the official JSON schema](https://github.com/flexiblepower/s2-ws-json).
//! This is currently the most common and well-supported way to use S2.

use std::error::Error;

use serde::{Serialize, de::DeserializeOwned};

/// Trait used to abstract the underlying transport protocol.
///
/// **End-users are not expected to use this trait directly.** Instead, libraries can implement this trait to provide additional
/// transport protocols that can be used to talk S2 over.
pub trait S2Transport {
    /// Error type for errors occurring at a transport level.
    type TransportError: Error;

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
