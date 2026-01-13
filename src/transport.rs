use crate::common::Message;
use std::error::Error;

#[cfg(feature = "dbus")]
pub mod dbus;
#[cfg(feature = "websockets-json")]
pub mod websockets_json;

/// Trait used to abstract the underlying transport protocol.
///
/// **Most users are not expected to use this trait directly.** Instead, libraries can implement this trait to provide additional
/// transport protocols that can be used to talk S2 over.
pub trait S2Transport {
    type TransportError: Error;

    fn send(&mut self, message: Message) -> impl Future<Output = Result<(), Self::TransportError>> + Send;
    fn receive(&mut self) -> impl Future<Output = Result<Message, Self::TransportError>> + Send;
    fn disconnect(self) -> impl Future<Output = ()> + Send;
}

// TODO: for some reason, this module is not visible to doctests when annotated with #[cfg(any(test, doctest))]
// So for now it's just unconditionally public (and it might be useful for other people doing tests, so maybe that's fine?).
pub mod test {
    use std::convert::Infallible;
    use crate::{connection::S2Connection, frbc::StorageStatus};
    use super::*;

    pub struct MockTransport;

    impl MockTransport {
        pub fn new_connection() -> S2Connection<Self> {
            S2Connection::new(MockTransport)
        }
    }

    impl S2Transport for MockTransport {
        type TransportError = Infallible;

        async fn send(&mut self, _: Message) -> Result<(), Self::TransportError> {
            Ok(())
        }

        async fn receive(&mut self) -> Result<Message, Self::TransportError> {
            Ok(Message::FrbcStorageStatus(StorageStatus::new(0.0)))
        }

        async fn disconnect(self) {}
    }
}
