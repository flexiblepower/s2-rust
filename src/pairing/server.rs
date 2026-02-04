#![allow(unused)]
use super::Config;

pub struct Server {}

pub struct ServerConfig {}

pub struct PendingPairing {}

pub struct RepeatedPairing {}

impl Server {
    pub fn new(server_config: ServerConfig) -> Self {
        todo!()
    }

    pub fn get_router() -> axum::Router<()> {
        todo!()
    }

    pub fn pair_once(config: Config, pairing_token: Vec<u8>) -> PendingPairing {
        todo!()
    }

    pub fn pair_repeated(config: Config, pairing_token: Vec<u8>) -> RepeatedPairing {
        todo!()
    }
}
