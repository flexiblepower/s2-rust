use rand::Rng;
use reqwest::{Client, StatusCode, Url};

use super::Config;
use super::transport::*;
use super::{Error, Network, PairingResult, Role};

//FIXME: Consider whether we want to use reqwest types in public interface.
pub struct PairingRemote {
    pub url: Url,
    pub id: S2NodeId,
}

//FIXME: Decide whether or not having the randomness configurable is usefull for the end user.
pub async fn pair(
    rng: &mut impl Rng,
    config: Config,
    remote: PairingRemote,
    pairing_token: &[u8],
    role: Role,
) -> PairingResult<ConnectionDetails> {
    let state = PairingState::init(
        remote.url,
        role,
        config.supported_protocol_versions,
        config.node_description,
        config.endpoint_description,
        remote.id,
    )
    .await?;

    state.pair(rng, pairing_token).await
}

struct PairingState {
    client: reqwest::Client,
    url: Url,

    role: Role,
    network: Network,
    version: PairingVersion,

    supported_versions: Vec<ConnectionVersion>,
    node_description: S2NodeDescription,
    endpoint_description: S2EndpointDescription,
    id: S2NodeId,
}

impl PairingState {
    pub async fn init(
        url: Url,

        role: Role,
        supported_versions: Vec<ConnectionVersion>,

        node_description: S2NodeDescription,
        endpoint_description: S2EndpointDescription,
        id: S2NodeId,
    ) -> PairingResult<Self> {
        let client = reqwest::Client::new();
        let server_versions = get_supported_versions(&client, &url).await?;

        // TODO: make this depend on the connection from get_supported_versions
        // let network = Network::Wan;
        let network = Network::Lan { fingerprint: [0; 32] };

        let version = 'blk: {
            for candidate in [PairingVersion::V1] {
                if server_versions.0.iter().any(|v| *v == candidate) {
                    break 'blk candidate;
                }
            }

            return Err(Error::NoSupportedVersion);
        };

        let url = match version {
            PairingVersion::V1 => url.join("/v1/").unwrap(),
        };

        Ok(Self {
            client,
            url,

            role,
            network,
            version,

            supported_versions,
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
            supported_versions: self.supported_versions.clone(),
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

        match self.version {
            PairingVersion::V1 => {
                let in_progress = V1PairingInProgress {
                    client: self.client,
                    url: self.url,

                    role: self.role,
                    network: self.network,

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
    }
}

struct V1PairingInProgress {
    client: reqwest::Client,
    url: Url,

    role: Role,
    network: Network,

    pairing_token: Vec<u8>,
    pairing_attempt_id: PairingAttemptId,
}

impl V1PairingInProgress {
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

async fn get_supported_versions(client: &Client, url: &Url) -> PairingResult<PairingSupportedVersions> {
    let url = url.join("/").unwrap();
    let response = client.get(url).send().await.unwrap();
    let status = response.status();

    if status != StatusCode::OK {
        todo!("invalid status code {status:?}");
    }

    let supported_versions = response.json::<PairingSupportedVersions>().await.unwrap();

    Ok(supported_versions)
}

impl V1PairingInProgress {
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
