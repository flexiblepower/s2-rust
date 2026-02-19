pub(crate) mod common;
pub mod communication;
pub mod pairing;

pub use common::wire::{
    AccessToken, CommunicationProtocol, Deployment, MessageVersion, S2EndpointDescription, S2NodeDescription, S2NodeId, S2Role,
};
