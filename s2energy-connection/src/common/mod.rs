use axum::Json;

pub(crate) mod wire;

use reqwest::{StatusCode, Url};
use wire::PairingVersion;

use crate::common::wire::WirePairingVersion;

pub(crate) const SUPPORTED_PAIRING_VERSIONS: &[PairingVersion] = &[PairingVersion::V1];

pub(crate) async fn root() -> Json<&'static [PairingVersion]> {
    Json(SUPPORTED_PAIRING_VERSIONS)
}

pub(crate) enum BaseError {
    TransportFailed,
    ProtocolError,
    NoSupportedVersion,
}

pub(crate) async fn negotiate_version(client: &reqwest::Client, url: Url) -> Result<PairingVersion, BaseError> {
    let response = client.get(url).send().await.map_err(|_| BaseError::TransportFailed)?;

    if response.status() != StatusCode::OK {
        return Err(BaseError::ProtocolError);
    }

    let supported_versions = response
        .json::<Vec<WirePairingVersion>>()
        .await
        .map_err(|_| BaseError::ProtocolError)?;

    for version in supported_versions.into_iter().filter_map(|v| v.try_into().ok()) {
        if SUPPORTED_PAIRING_VERSIONS.contains(&version) {
            return Ok(version);
        }
    }

    Err(BaseError::NoSupportedVersion)
}
