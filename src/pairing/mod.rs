#![allow(missing_docs)]
pub mod transport;
use thiserror::Error;

use rand::Rng;
use reqwest::{Client, StatusCode, Url};

use transport::*;

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
        let tag = mac.finalize().into_bytes(); // 32 bytes
        assert_eq!(tag.len(), 32);
        let mut out = [0u8; 32];
        out.copy_from_slice(&tag);
        HmacChallengeResponse(out)
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    NoSupportedVersion,
}

#[derive(Error, Debug)]
enum PairingResponseErrorMessage {
    #[error("Invalid combination of roles")]
    InvalidCombinationOfRoles,
    #[error("Incompatible S2 message versions")]
    IncompatibleS2MessageVersions,
    #[error("Incompatible HMAC hashing algorithms")]
    IncompatibleHMACHashingAlgorithms,
    #[error("Incompatible communication protocols")]
    IncompatibleCommunicationProtocols,
    #[error("S2Node not found")]
    S2NodeNotFound,
    #[error("No S2Node provided")]
    S2NodeNotProvided,
    #[error("No valid pairingToken on PairingServer")]
    InvalidPairingToken,
    #[error("Parsing error")]
    ParsingError,
    #[error("Other")]
    Other,
}

type PairingResult<T> = Result<T, Error>;

pub enum Role {
    CommunicationServer {
        initiate_connection_url: Url,
        access_token: AccessToken,
    },
    CommunicationClient,
}

#[derive(Debug)]
pub enum Network {
    Wan,
    Lan { fingerprint: [u8; 32] },
}

pub struct PairingState {
    client: reqwest::Client,
    url: Url,

    role: Role,
    network: Network,
    version: Version,

    node_description: S2NodeDescription,
    endpoint_description: S2EndpointDescription,
    id: PairingS2NodeId,
}

impl PairingState {
    pub async fn init(
        url: Url,

        role: Role,
        supported_versions: &[Version],

        node_description: S2NodeDescription,
        endpoint_description: S2EndpointDescription,
        id: PairingS2NodeId,
    ) -> PairingResult<Self> {
        let client = reqwest::Client::new();
        let server_versions = get_supported_versions(&client, &url).await?;

        // TODO: make this depend on the connection from get_supported_versions
        // let network = Network::Wan;
        let network = Network::Lan { fingerprint: [0; 32] };

        let version = 'blk: {
            for candidate in supported_versions {
                if server_versions.0.iter().any(|v| v == candidate) {
                    break 'blk *candidate;
                }
            }

            return Err(Error::NoSupportedVersion);
        };

        let url = match version {
            Version::V1 => url.join("/v1/").unwrap(),
        };

        Ok(Self {
            client,
            url,

            role,
            network,
            version,

            node_description,
            endpoint_description,
            id,
        })
    }

    pub async fn post_request_pairing(&self, request_pairing: RequestPairing) -> PairingResult<RequestPairingResponse> {
        let url = self.url.join("requestPairing").unwrap();
        let response = self.client.post(url).json(&request_pairing).send().await.unwrap();

        let pairing_response = response.json::<RequestPairingResponse>().await.unwrap();
        Ok(pairing_response)
    }

    pub async fn pair(self, rng: &mut impl Rng, pairing_token: &[u8]) -> PairingResult<ConnectionDetails> {
        let client_hmac_challenge = HmacChallenge::new(rng);

        // FIXME: this still hardcodes some configuration (for now).
        let request_pairing = RequestPairing {
            node_description: self.node_description.clone(),
            endpoint_description: self.endpoint_description.clone(),
            id: self.id.clone(),
            supported_protocols: vec![CommunicationProtocol::WebSocket],
            supported_versions: vec![self.version],
            supported_hashing_algorithms: vec![HmacHashingAlgorithm::Sha256],
            client_hmac_challenge: client_hmac_challenge.clone(),
            force_pairing: false,
        };

        let request_pairing_response = match self.post_request_pairing(request_pairing).await {
            Ok(request_pairing_response) => request_pairing_response,
            Err(e) => {
                // NOTE: we don't have a pairing_attempt_id yet.
                todo!()
            }
        };

        let in_progress = PairingInProgress {
            client: self.client,
            url: self.url,

            role: self.role,
            network: self.network,
            version: self.version,

            pairing_token: pairing_token.to_vec(),
            pairing_attempt_id: request_pairing_response.pairing_attempt_id.clone(),
        };

        match in_progress.run(client_hmac_challenge, request_pairing_response).await {
            Ok(connection_details) => {
                let () = in_progress.finalize_pairing(true).await?;
                Ok(connection_details)
            }
            Err(e) => {
                let () = in_progress.finalize_pairing(false).await?;
                Err(e)
            }
        }
    }
}

struct PairingInProgress {
    client: reqwest::Client,
    url: Url,

    role: Role,
    network: Network,
    version: Version,

    pairing_token: Vec<u8>,
    pairing_attempt_id: PairingAttemptId,
}

impl PairingInProgress {
    async fn run(
        &self,
        client_hmac_challenge: HmacChallenge,
        request_pairing_response: RequestPairingResponse,
    ) -> PairingResult<ConnectionDetails> {
        match request_pairing_response.selected_hmac_hashing_algorithm {
            HmacHashingAlgorithm::Sha256 => {
                let expected = client_hmac_challenge.sha256(&self.network, &self.pairing_token);

                if expected != request_pairing_response.client_hmac_challenge_response {
                    todo!()
                }
            }
        }

        let server_hmac_challenge_response = match request_pairing_response.selected_hmac_hashing_algorithm {
            HmacHashingAlgorithm::Sha256 => request_pairing_response
                .server_hmac_challenge
                .sha256(&self.network, &self.pairing_token),
        };

        let connection_details = match &self.role {
            Role::CommunicationClient => {
                let request = RequestConnectionDetailsRequest {
                    server_hmac_challenge_response,
                };
                self.request_connection_details(request).await?
            }

            Role::CommunicationServer {
                initiate_connection_url,
                access_token,
            } => {
                let connection_details = ConnectionDetails {
                    initiate_connection_url: Some(initiate_connection_url.to_string()),
                    access_token: Some(access_token.clone()),
                };

                let request = PostConnectionDetailsRequest {
                    server_hmac_challenge_response,
                    connection_details: connection_details.clone(),
                };
                let () = self.post_connection_details(request).await?;

                connection_details
            }
        };

        Ok(connection_details)
    }
}

async fn get_supported_versions(client: &Client, url: &Url) -> PairingResult<SupportedVersions> {
    let url = url.join("/").unwrap();
    let response = client.get(url).send().await.unwrap();
    let status = response.status();

    if status != StatusCode::OK {
        todo!("invalid status code {status:?}");
    }

    let supported_versions = response.json::<SupportedVersions>().await.unwrap();

    Ok(supported_versions)
}

impl PairingInProgress {
    async fn request_connection_details(&self, request: RequestConnectionDetailsRequest) -> PairingResult<ConnectionDetails> {
        let url = self.url.join("requestConnectionDetails").unwrap();
        let response = self
            .client
            .post(url)
            .header(PairingAttemptId::header_name(), self.pairing_attempt_id.header_value())
            .json(&request)
            .send()
            .await
            .unwrap();

        let status = response.status();

        if status != StatusCode::OK {
            todo!("invalid status code {status:?}");
        }

        let connection_details = response.json::<ConnectionDetails>().await.unwrap();
        Ok(connection_details)
    }

    async fn post_connection_details(&self, request: PostConnectionDetailsRequest) -> PairingResult<()> {
        let url = self.url.join("postConnectionDetails").unwrap();
        let response = self
            .client
            .post(url)
            .header(PairingAttemptId::header_name(), self.pairing_attempt_id.header_value())
            .json(&request)
            .send()
            .await
            .unwrap();

        let status = response.status();

        if status != StatusCode::NO_CONTENT {
            todo!("invalid status code {status:?}");
        }

        Ok(())
    }

    async fn finalize_pairing(&self, success: bool) -> PairingResult<()> {
        let url = self.url.join("finalizePairing").unwrap();
        let response = self
            .client
            .post(url)
            .header(PairingAttemptId::header_name(), self.pairing_attempt_id.header_value())
            .json(&success)
            .send()
            .await
            .unwrap();

        let status = response.status();

        if status != StatusCode::NO_CONTENT {
            todo!("invalid status code {status:?}");
        }

        Ok(())
    }
}
