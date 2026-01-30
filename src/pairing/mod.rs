use rand::Rng;
use serde::*;

#[derive(Serialize, Deserialize)]
struct SupportedVersions(Vec<String>);

#[derive(Serialize, Deserialize)]
struct RequestPairing {
    #[serde(rename = "clientS2NodeDescription")]
    node_description: S2NodeDescription,
    #[serde(rename = "clientS2EndpointDescription")]
    endpoint_description: S2EndpointDescription,
    #[serde(rename = "pairingS2NodeId")]
    id: PairingS2NodeId,
    #[serde(rename = "supportedCommunicationProtocols")]
    supported_protocols: Vec<CommunicationProtocol>,
    /// The versions of the S2 JSON message schemas this S2Node implementation currently supports.
    #[serde(rename = "supportedS2MessageVersions")]
    supported_versions: Vec<String>,
    #[serde(rename = "supportedHmacHashingAlgorithms")]
    #[serde(default)]
    supported_hashing_algorithms: Vec<HmacHashingAlgorithm>,
    #[serde(rename = "clientHmacChallenge")]
    client_hmac_challenge: HmacChallenge,
    /// Forces the server to attempt pairing, even though the S2 message versions are not compatible. In this case the S2Nodes won't be able to communicate after pairing, but this could later be solved through a software update on one or both of the S2Nodes.
    #[serde(rename = "forcePairing")]
    #[serde(default)]
    force_pairing: bool,
}

#[serde(rename_all = "camelCase")]
#[derive(Serialize, Deserialize)]
struct S2EndpointDescription {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    logo_uri: Option<String>,
    #[serde(default)]
    deployment: Option<Deployment>,
}

/// NOTE: base-64 encoded.
#[derive(Serialize, Deserialize)]
struct PairingS2NodeId(String);

/// NOTE: base-64 encoded.
#[derive(Serialize, Deserialize, Clone)]
struct AccessToken(String);

#[derive(Serialize, Deserialize)]
struct S2NodeId(String);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct S2NodeDescription {
    id: S2NodeId,
    brand: String,
    #[serde(default)]
    logo_uri: Option<String>,
    type_: String,
    model_name: String,
    #[serde(default)]
    user_defined_name: Option<String>,
    role: S2Role,
}

#[derive(Serialize, Deserialize)]
enum CommunicationProtocol {
    WebSocket,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum S2Role {
    Cem,
    Rm,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum Deployment {
    Wan,
    Lan,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum HmacHashingAlgorithm {
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HmacChallenge([u8; 32]);

impl Serialize for HmacChallenge {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let encoded = STANDARD.encode(self.0);
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for HmacChallenge {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HmacChallengeVisitor;

        impl<'de> serde::de::Visitor<'de> for HmacChallengeVisitor {
            type Value = HmacChallenge;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a base64-encoded string representing 32 bytes")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                use base64::{Engine as _, engine::general_purpose::STANDARD};

                let decoded = STANDARD.decode(v).map_err(E::custom)?;

                if decoded.len() != 32 {
                    return Err(E::custom(format!("expected 32 bytes, got {}", decoded.len())));
                }

                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&decoded);
                Ok(HmacChallenge(bytes))
            }
        }

        deserializer.deserialize_str(HmacChallengeVisitor)
    }
}

impl HmacChallenge {
    fn new(rng: &mut impl Rng) -> Self {
        Self(rng.random())
    }

    /// WAN deployment:
    ///
    /// R = HMAC(C, T)
    pub fn sha256_wan(&self, pairing_token: &[u8]) -> HmacChallengeResponse {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC can take a key of any size");
        mac.update(pairing_token);
        let tag = mac.finalize().into_bytes(); // 32 bytes
        let mut out = [0u8; 32];
        out.copy_from_slice(&tag);
        HmacChallengeResponse(out)
    }

    /// LAN deployment:
    ///
    /// R = HMAC(C, T || F)
    ///
    /// where F is the SHA256 fingerprint of the TLS server certificate.
    pub fn sha256_lan(&self, pairing_token: &[u8], tls_cert_fingerprint_sha256: &[u8; 32]) -> HmacChallengeResponse {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC can take a key of any size");
        mac.update(pairing_token);
        mac.update(tls_cert_fingerprint_sha256);
        let tag = mac.finalize().into_bytes(); // 32 bytes
        let mut out = [0u8; 32];
        out.copy_from_slice(&tag);
        HmacChallengeResponse(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HmacChallengeResponse([u8; 32]);

impl Serialize for HmacChallengeResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let encoded = STANDARD.encode(self.0);
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for HmacChallengeResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HmacChallengeResponseVisitor;

        impl<'de> serde::de::Visitor<'de> for HmacChallengeResponseVisitor {
            type Value = HmacChallengeResponse;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a base64-encoded string representing 32 bytes")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                use base64::{Engine as _, engine::general_purpose::STANDARD};

                let decoded = STANDARD.decode(v).map_err(E::custom)?;

                if decoded.len() != 32 {
                    return Err(E::custom(format!("expected 32 bytes, got {}", decoded.len())));
                }

                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&decoded);
                Ok(HmacChallengeResponse(bytes))
            }
        }

        deserializer.deserialize_str(HmacChallengeResponseVisitor)
    }
}

enum Error {
    NoSupportedVersion,
}

type PairingResult<T> = Result<T, Error>;

enum Role {
    CommunicationServer {
        initiate_connection_url: String,
        access_token: AccessToken,
    },
    CommunicationClient,
}

struct PairingState {
    role: Role,
    version: String,

    node_description: S2NodeDescription,
    endpoint_description: S2EndpointDescription,
    id: PairingS2NodeId,
}

impl PairingState {
    async fn init(
        role: Role,
        supported_versions: &[&str],

        node_description: S2NodeDescription,
        endpoint_description: S2EndpointDescription,
        id: PairingS2NodeId,
    ) -> PairingResult<Self> {
        let server_versions = get_supported_versions().await?;

        let version = 'blk: {
            for candidate in supported_versions {
                if server_versions.0.iter().any(|v| v == candidate) {
                    break 'blk candidate;
                }
            }

            return Err(Error::NoSupportedVersion);
        };

        Ok(Self {
            role,
            version: version.to_string(),

            node_description,
            endpoint_description,
            id,
        })
    }

    async fn pair(self, rng: &mut impl Rng) -> PairingResult<ConnectionDetails> {
        match self.pair_help(rng).await {
            Ok(connection_details) => {
                let () = finalize_pairing(true).await?;
                Ok(connection_details)
            }
            Err(e) => {
                let () = finalize_pairing(false).await?;
                Err(e)
            }
        }
    }

    async fn pair_help(self, rng: &mut impl Rng) -> PairingResult<ConnectionDetails> {
        let pairing_token = vec![];

        let client_hmac_challenge = HmacChallenge::new(rng);
        let hmac_challenge_expected = client_hmac_challenge.sha256_wan(&pairing_token);

        let request_pairing = RequestPairing {
            node_description: self.node_description,
            endpoint_description: self.endpoint_description,
            id: self.id,
            supported_protocols: vec![CommunicationProtocol::WebSocket],
            supported_versions: vec![self.version.to_string()],
            supported_hashing_algorithms: vec![HmacHashingAlgorithm::Sha256],
            client_hmac_challenge: HmacChallenge::new(rng),
            force_pairing: false,
        };

        let request_pairing_response = post_request_pairing(request_pairing).await?;

        if hmac_challenge_expected != request_pairing_response.client_hmac_challenge_response {
            todo!()
        }

        let server_hmac_challenge_response = request_pairing_response.server_hmac_challenge.sha256_wan(&pairing_token);

        let connection_details = match self.role {
            Role::CommunicationClient => {
                let request = RequestConnectionDetailsRequest {
                    server_hmac_challenge_response,
                };
                request_connection_details(request).await?
            }

            Role::CommunicationServer {
                initiate_connection_url,
                access_token,
            } => {
                let connection_details = ConnectionDetails {
                    initiate_connection_url: Some(initiate_connection_url.clone()),
                    access_token: Some(access_token.clone()),
                };

                let request = PostConnectionDetailsRequest {
                    server_hmac_challenge_response,
                    connection_details: connection_details.clone(),
                };
                let () = post_connection_details(request).await?;

                connection_details
            }
        };

        Ok(connection_details)
    }
}

async fn get_supported_versions() -> PairingResult<SupportedVersions> {
    todo!()
}

/// An identifier that is generated by the server for each pairing attempt.
#[derive(Serialize, Deserialize)]
struct PairingAttemptId(String);

#[serde(rename_all = "camelCase")]
#[derive(Serialize, Deserialize)]
struct RequestPairingResponse {
    pairing_attempt_id: PairingAttemptId,
    server_s2_node_description: S2NodeDescription,
    server_s2_endpoint_description: S2EndpointDescription,
    selected_hmac_hashing_algorithm: HmacHashingAlgorithm,
    client_hmac_challenge_response: HmacChallengeResponse,
    server_hmac_challenge: HmacChallenge,
}

async fn post_request_pairing(request_pairing: RequestPairing) -> PairingResult<RequestPairingResponse> {
    todo!()
}

#[serde(rename_all = "camelCase")]
#[derive(Serialize, Deserialize)]
struct RequestConnectionDetailsRequest {
    server_hmac_challenge_response: HmacChallengeResponse,
}

/// Details the Connection client needs to set up an S2 session.
#[serde(rename_all = "camelCase")]
#[derive(Serialize, Deserialize, Clone)]
struct ConnectionDetails {
    #[serde(default)]
    initiate_connection_url: Option<String>,
    #[serde(default)]
    access_token: Option<AccessToken>,
}

async fn request_connection_details(request: RequestConnectionDetailsRequest) -> PairingResult<ConnectionDetails> {
    todo!()
}

#[serde(rename_all = "camelCase")]
#[derive(Serialize, Deserialize)]
struct PostConnectionDetailsRequest {
    server_hmac_challenge_response: HmacChallengeResponse,
    connection_details: ConnectionDetails,
}

async fn post_connection_details(request: PostConnectionDetailsRequest) -> PairingResult<()> {
    todo!()
}

async fn finalize_pairing(success: bool) -> PairingResult<()> {
    todo!()
}
