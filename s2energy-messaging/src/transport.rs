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

#[doc(hidden)]
#[cfg(feature = "dbus")]
pub mod dbus;
#[cfg(feature = "websockets-json")]
pub mod websockets_json;

// TODO: for some reason, this module is not visible to doctests when annotated with #[cfg(any(test, doctest))]
// So for now it's just unconditionally public (and it might be useful for other people doing tests, so maybe that's fine?).
#[doc(hidden)]
pub mod test {
    use s2energy_common::S2Transport;
    use serde::{Serialize, de::DeserializeOwned};

    use crate::{connection::S2Connection, frbc::StorageStatus};
    use std::convert::Infallible;

    pub struct MockTransport;

    impl MockTransport {
        pub fn new_connection() -> S2Connection<Self> {
            S2Connection::new(MockTransport)
        }
    }

    impl S2Transport for MockTransport {
        type TransportError = Infallible;

        async fn send(&mut self, _: impl Serialize + Send) -> Result<(), Self::TransportError> {
            Ok(())
        }

        async fn receive<Message: DeserializeOwned>(&mut self) -> Result<Message, Self::TransportError> {
            let serialized_message = serde_json::to_string(&crate::common::Message::FrbcStorageStatus(StorageStatus::new(0.0))).unwrap();
            Ok(serde_json::from_str(&serialized_message).unwrap())
        }

        async fn disconnect(self) {}
    }
}
