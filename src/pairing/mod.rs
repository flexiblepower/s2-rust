use serde::*;

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

#[derive(Serialize, Deserialize)]
struct HmacChallenge(String);

#[derive(Serialize, Deserialize)]
struct HmacChallengeResponse(String);
