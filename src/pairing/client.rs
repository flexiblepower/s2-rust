use reqwest::{StatusCode, Url};

use crate::pairing::{Pairing, PairingRole, SUPPORTED_PAIRING_VERSIONS};

use super::Config;
use super::wire::*;
use super::{Error, Network, PairingResult, Role};

//FIXME: Consider whether we want to use reqwest types in public interface.
pub struct PairingRemote {
    pub url: Url,
    pub id: S2NodeId,
}

pub async fn pair(config: Config, remote: PairingRemote, pairing_token: &[u8], role: Role) -> PairingResult<Pairing> {
    let client = reqwest::Client::new();
    let pairing_version = negotiate_version(&client, remote.url.clone()).await?;

    match pairing_version {
        PairingVersion::V1 => pair_v1(client, remote, config, pairing_token, role).await,
    }
}

async fn negotiate_version(client: &reqwest::Client, url: Url) -> Result<PairingVersion, Error> {
    let response = client.get(url).send().await.map_err(|_| Error::TransportFailed)?;
    let status = response.status();
    if status != StatusCode::OK {
        return Err(Error::ProtocolError);
    }

    let supported_versions = response.json::<Vec<WirePairingVersion>>().await.map_err(|_| Error::ProtocolError)?;

    for version in supported_versions.into_iter().filter_map(|v| v.try_into().ok()) {
        if SUPPORTED_PAIRING_VERSIONS.contains(&version) {
            return Ok(version);
        }
    }

    Err(Error::NoSupportedVersion)
}

async fn pair_v1(
    client: reqwest::Client,
    remote: PairingRemote,
    config: Config,
    pairing_token: &[u8],
    role: Role,
) -> PairingResult<Pairing> {
    let base_url = remote.url.join("v1/").unwrap();

    // FIXME: Implement proper network autodetection and certificate handling.
    let network = Network::Lan { fingerprint: [0; 32] };

    let client_hmac_challenge = HmacChallenge::new(&mut rand::rng());

    let request_pairing_response = v1_request_pairing(&client, &base_url, config, remote.id, &client_hmac_challenge).await?;
    let attempt_id = request_pairing_response.pairing_attempt_id;

    match request_pairing_response.selected_hmac_hashing_algorithm {
        HmacHashingAlgorithm::Sha256 => {
            let expected = client_hmac_challenge.sha256(&network, pairing_token);

            if expected != request_pairing_response.client_hmac_challenge_response {
                let _ = v1_finalize(&client, &base_url, &attempt_id, false).await;
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
            if let Err(e) = v1_post_connection_details(
                &client,
                &base_url,
                &attempt_id,
                server_hmac_challenge_response,
                initiate_connection_url.clone().into(),
                access_token.clone(),
            )
            .await
            {
                let _ = v1_finalize(&client, &base_url, &attempt_id, false).await;
                return Err(e);
            }
            Pairing {
                remote_endpoint_description: request_pairing_response.server_s2_endpoint_description,
                remote_node_description: request_pairing_response.server_s2_node_description,
                token: access_token,
                role: PairingRole::CommunicationServer,
            }
        }
        Role::CommunicationClient => {
            let connection_details = match v1_get_connection_details(&client, &base_url, &attempt_id, server_hmac_challenge_response).await
            {
                Ok(connection_details) => connection_details,
                Err(e) => {
                    let _ = v1_finalize(&client, &base_url, &attempt_id, false).await;
                    return Err(e);
                }
            };
            Pairing {
                remote_endpoint_description: request_pairing_response.server_s2_endpoint_description,
                remote_node_description: request_pairing_response.server_s2_node_description,
                token: connection_details.access_token,
                role: PairingRole::CommunicationClient {
                    initiate_url: connection_details.initiate_connection_url,
                },
            }
        }
    };

    v1_finalize(&client, &base_url, &attempt_id, true).await?;

    Ok(pairing)
}

async fn v1_get_connection_details(
    client: &reqwest::Client,
    base_url: &Url,
    attempt_id: &PairingAttemptId,
    server_hmac_challenge_response: HmacChallengeResponse,
) -> PairingResult<ConnectionDetails> {
    let request = RequestConnectionDetailsRequest {
        server_hmac_challenge_response,
    };
    let response = client
        .post(base_url.join("requestConnectionDetails").unwrap())
        .header(PairingAttemptId::HEADER_NAME, attempt_id.header_value())
        .json(&request)
        .send()
        .await
        .map_err(|_| Error::TransportFailed)?;
    if response.status() != StatusCode::OK {
        return Err(Error::ProtocolError);
    }
    let connection_details = response.json::<ConnectionDetails>().await.map_err(|_| Error::ProtocolError)?;
    Ok(connection_details)
}

async fn v1_post_connection_details(
    client: &reqwest::Client,
    base_url: &Url,
    attempt_id: &PairingAttemptId,
    server_hmac_challenge_response: HmacChallengeResponse,
    initiate_connection_url: String,
    access_token: AccessToken,
) -> PairingResult<()> {
    let request = PostConnectionDetailsRequest {
        server_hmac_challenge_response,
        connection_details: ConnectionDetails {
            initiate_connection_url,
            access_token,
        },
    };
    let response = client
        .post(base_url.join("postConnectionDetails").unwrap())
        .header(PairingAttemptId::HEADER_NAME, attempt_id.header_value())
        .json(&request)
        .send()
        .await
        .map_err(|_| Error::TransportFailed)?;
    if response.status() != StatusCode::NO_CONTENT {
        return Err(Error::ProtocolError);
    }

    Ok(())
}

async fn v1_request_pairing(
    client: &reqwest::Client,
    base_url: &Url,
    config: Config,
    id: S2NodeId,
    client_hmac_challenge: &HmacChallenge,
) -> PairingResult<RequestPairingResponse> {
    let request = RequestPairing {
        node_description: config.node_description.clone(),
        endpoint_description: config.endpoint_description.clone(),
        id,
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
        .map_err(|_| Error::TransportFailed)?;
    if response.status() != StatusCode::OK {
        return Err(Error::ProtocolError);
    }
    let request_pairing_response = response.json::<RequestPairingResponse>().await.map_err(|_| Error::ProtocolError)?;
    Ok(request_pairing_response)
}

async fn v1_finalize(client: &reqwest::Client, url: &Url, attempt_id: &PairingAttemptId, success: bool) -> PairingResult<()> {
    let response = client
        .post(url.join("finalizePairing").unwrap())
        .header(PairingAttemptId::HEADER_NAME, attempt_id.header_value())
        .json(&success)
        .send()
        .await
        .map_err(|_| Error::TransportFailed)?;
    if response.status() != StatusCode::NO_CONTENT {
        return Err(Error::ProtocolError);
    }

    Ok(())
}
