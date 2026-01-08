use crate::common::Message;
use std::error::Error;

#[cfg(feature = "dbus")]
pub mod dbus;
#[cfg(feature = "websockets-json")]
pub mod websockets_json;

pub trait S2Transport {
    type TransportError: Error;

    fn send(&mut self, message: Message) -> impl Future<Output = Result<(), Self::TransportError>> + Send;
    fn receive(&mut self) -> impl Future<Output = Result<Message, Self::TransportError>> + Send;
    fn disconnect(self) -> impl Future<Output = ()> + Send;
}
