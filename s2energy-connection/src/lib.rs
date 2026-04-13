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

pub mod combined_server;
pub(crate) mod common;
pub mod communication;
pub mod discovery;
pub mod error;
pub mod pairing;

pub use common::wire::{
    AccessToken, CommunicationProtocol, Deployment, EndpointDescription, InvalidNodeId, MessageVersion, NodeDescription, NodeId, Role,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Hash of a TLS certificate.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct CertificateHash(CertificateHashInner);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
enum CertificateHashInner {
    Sha256(sha2::digest::generic_array::GenericArray<u8, <sha2::Sha256 as sha2::digest::OutputSizeUser>::OutputSize>),
}

impl CertificateHash {
    pub(crate) fn sha256(data: &[u8]) -> Self {
        Self(CertificateHashInner::Sha256(sha2::Sha256::digest(data)))
    }
}

impl AsRef<CertificateHash> for CertificateHash {
    fn as_ref(&self) -> &CertificateHash {
        self
    }
}

impl std::ops::Deref for CertificateHash {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match &self.0 {
            CertificateHashInner::Sha256(generic_array) => generic_array,
        }
    }
}
