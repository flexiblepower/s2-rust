use reqwest::{StatusCode, Url};

use crate::pairing::{Pairing, PairingRole, SUPPORTED_PAIRING_VERSIONS};

use super::Config;
use super::transport::*;
use super::{Error, Network, PairingResult, Role};

//FIXME: Consider whether we want to use reqwest types in public interface.
pub struct PairingRemote {
    pub url: Url,
    pub id: S2NodeId,
}

pub async fn pair(config: Config, remote: PairingRemote, pairing_token: &[u8], role: Role) -> PairingResult<Pairing> {
    let client = reqwest::Client::new();
    let pairing_version = negotiate_version(remote.url.clone(), &client).await?;

    match pairing_version {
        PairingVersion::V1 => pair_v1(config, remote, pairing_token, role, client).await,
    }
}

async fn negotiate_version(url: Url, client: &reqwest::Client) -> Result<PairingVersion, Error> {
    let response = client.get(url).send().await.unwrap();
    let status = response.status();

    if status != StatusCode::OK {
        todo!("invalid status code {status:?}");
    }

    let supported_versions = response.json::<PairingSupportedVersions>().await.unwrap();

    for version in SUPPORTED_PAIRING_VERSIONS {
        if supported_versions.0.contains(version) {
            return Ok(*version);
        }
    }

    Err(Error::NoSupportedVersion)
}

async fn pair_v1(
    config: Config,
    remote: PairingRemote,
    pairing_token: &[u8],
    role: Role,
    client: reqwest::Client,
) -> PairingResult<Pairing> {
    let base_url = remote.url.join("v1/").unwrap();

    // FIXME: Implement proper network autodetection and certificate handling.
    let network = Network::Lan { fingerprint: [0; 32] };

    let client_hmac_challenge = HmacChallenge::new(&mut rand::rng());

    let request = RequestPairing {
        node_description: config.node_description.clone(),
        endpoint_description: config.endpoint_description.clone(),
        id: remote.id,
        supported_protocols: vec![CommunicationProtocol::WebSocket],
        supported_versions: config.supported_protocol_versions.clone(),
        supported_hashing_algorithms: vec![HmacHashingAlgorithm::Sha256],
        client_hmac_challenge: client_hmac_challenge.clone(),
        force_pairing: false,
    };
    let response = client
        .post(base_url.join("requestPairing").unwrap())
        .json(&request)
        .send()
        .await
        .unwrap();
    if response.status() != StatusCode::OK {
        todo!()
    }
    let request_pairing_response = response.json::<RequestPairingResponse>().await.unwrap();
    let attempt_id = request_pairing_response.pairing_attempt_id;

    match request_pairing_response.selected_hmac_hashing_algorithm {
        HmacHashingAlgorithm::Sha256 => {
            let expected = client_hmac_challenge.sha256(&network, pairing_token);

            if expected != request_pairing_response.client_hmac_challenge_response {
                let _ = v1_finalize(&attempt_id, &base_url, &client, false).await;
                return Err(Error::InvalidToken);
            }
        }
    }

    let server_hmac_challenge_response = match request_pairing_response.selected_hmac_hashing_algorithm {
        HmacHashingAlgorithm::Sha256 => request_pairing_response.server_hmac_challenge.sha256(&network, pairing_token),
    };

    let pairing = match role {
        Role::CommunicationServer {
            initiate_connection_url,
            access_token,
        } => {
            let request = PostConnectionDetailsRequest {
                server_hmac_challenge_response,
                connection_details: ConnectionDetails {
                    initiate_connection_url: Some(initiate_connection_url.clone().into()),
                    access_token: Some(AccessToken(access_token.0.clone())),
                },
            };
            let response = client
                .post(base_url.join("postConnectionDetails").unwrap())
                .header(PairingAttemptId::HEADER_NAME, attempt_id.header_value())
                .json(&request)
                .send()
                .await
                .unwrap();
            if response.status() != StatusCode::NO_CONTENT {
                todo!()
            }
            Pairing {
                token: access_token,
                role: PairingRole::CommunicationServer,
            }
        }
        Role::CommunicationClient => {
            let request = RequestConnectionDetailsRequest {
                server_hmac_challenge_response,
            };
            let response = client
                .post(base_url.join("requestConnectionDetails").unwrap())
                .header(PairingAttemptId::HEADER_NAME, attempt_id.header_value())
                .json(&request)
                .send()
                .await
                .unwrap();
            if response.status() != StatusCode::OK {
                todo!()
            }
            let connection_details = response.json::<ConnectionDetails>().await.unwrap();
            Pairing {
                token: connection_details.access_token.unwrap(),
                role: PairingRole::CommunicationClient {
                    initiate_url: connection_details.initiate_connection_url.unwrap(),
                },
            }
        }
    };

    v1_finalize(&attempt_id, &base_url, &client, true).await?;

    Ok(pairing)
}

async fn v1_finalize(attempt_id: &PairingAttemptId, url: &Url, client: &reqwest::Client, success: bool) -> PairingResult<()> {
    let response = client
        .post(url.join("finalizePairing").unwrap())
        .header(PairingAttemptId::HEADER_NAME, attempt_id.header_value())
        .json(&success)
        .send()
        .await
        .unwrap();
    if response.status() != StatusCode::NO_CONTENT {
        todo!()
    }

    Ok(())
}
