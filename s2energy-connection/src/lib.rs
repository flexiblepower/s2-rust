//! This crate provides tools to establish connections between S2 nodes. It implements
//! discovery of nodes in the network, pairing with those nodes, and establishing the
//! transport between nodes. Together, this is a complete implementation of the [S2
//! communication layer](https://docs.s2standard.org/docs/communication-layer/discovery-pairing-authentication/)
//!
//! Each of these components is separated, as they do not necessarily need to run in the
//! same locations, with shared components for the information exchanged between
//! pairing, discovery and communication. See the documentation of the individual modules
//! for instruction how to setup the functions. Examples of end-to-end use are contained
//! in the examples folder of this crate.
#![warn(missing_docs)]

pub(crate) mod common;
pub mod communication;
pub mod discovery;
pub mod pairing;

pub use common::wire::{
    AccessToken, CommunicationProtocol, Deployment, EndpointDescription, InvalidNodeId, MessageVersion, NodeDescription, NodeId, Role,
};
