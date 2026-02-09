#![allow(missing_docs)]
#![warn(clippy::clone_on_copy)]
mod client;
mod server;
pub mod transport;

use rand::Rng;

use reqwest::Url;

use transport::{AccessToken, HmacChallenge, HmacChallengeResponse};

pub use client::{PairingRemote, pair};
pub use server::{PairingToken, Server, ServerConfig};
pub use transport::{ConnectionVersion, S2EndpointDescription, S2NodeDescription, S2NodeId, S2Role};

#[derive(Debug, Clone)]
pub struct Config {
    pub node_description: S2NodeDescription,
    pub endpoint_description: S2EndpointDescription,
    pub supported_protocol_versions: Vec<ConnectionVersion>,
}

pub enum PairingRole {
    CommunicationClient { initiate_url: String },
    CommunicationServer,
}

pub struct Pairing {
    pub token: AccessToken,
    pub role: PairingRole,
}

pub enum Role {
    CommunicationServer {
        initiate_connection_url: Url,
        access_token: AccessToken,
    },
    CommunicationClient,
}

impl HmacChallenge {
    pub fn new(rng: &mut impl Rng) -> Self {
        Self(rng.random())
    }

    pub fn sha256(&self, network: &Network, pairing_token: &[u8]) -> HmacChallengeResponse {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC can take a key of any size");

        match network {
            Network::Wan => {
                // R = HMAC(C, T)
                mac.update(pairing_token);
            }
            Network::Lan { fingerprint } => {
                // R = HMAC(C, T || F)
                mac.update(pairing_token);
                mac.update(fingerprint);
            }
        }

        HmacChallengeResponse(mac.finalize().into_bytes().into())
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    NoSupportedVersion,
    Timeout,
    AlreadyPending,
    InvalidToken,
    Cancelled,
}

pub type PairingResult<T> = Result<T, Error>;

#[derive(Debug)]
pub enum Network {
    Wan,
    Lan { fingerprint: [u8; 32] },
}
