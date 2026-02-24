use axum::Json;

pub(crate) mod websocket_extractor;
pub(crate) mod wire;

use reqwest::{StatusCode, Url};
use tracing::{debug, trace};
use wire::PairingVersion;

use crate::common::wire::WirePairingVersion;

pub(crate) const SUPPORTED_PAIRING_VERSIONS: &[PairingVersion] = &[PairingVersion::V1];

pub(crate) async fn root() -> Json<&'static [PairingVersion]> {
    Json(SUPPORTED_PAIRING_VERSIONS)
}

#[derive(Debug)]
pub(crate) struct BaseError {
    pub(crate) kind: BaseErrorKind,
    pub(crate) wrapped_error: BaseWrappedError,
}

impl BaseError {
    pub(crate) fn new<E: Into<BaseWrappedError>>(kind: BaseErrorKind, inner: E) -> Self {
        Self {
            kind,
            wrapped_error: inner.into(),
        }
    }
}

impl std::fmt::Display for BaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(inner) = self.wrapped_error.contents() {
            write!(f, "{}: {inner}", self.kind)
        } else {
            self.kind.fmt(f)
        }
    }
}

impl std::error::Error for BaseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.wrapped_error.contents()
    }
}

impl From<BaseErrorKind> for BaseError {
    fn from(kind: BaseErrorKind) -> Self {
        Self {
            kind,
            wrapped_error: BaseWrappedError::None,
        }
    }
}

#[derive(Debug)]
pub(crate) enum BaseWrappedError {
    None,
    Reqwest(reqwest::Error),
}

impl BaseWrappedError {
    pub fn contents(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BaseWrappedError::None => None,
            BaseWrappedError::Reqwest(error) => Some(error),
        }
    }
}

impl From<reqwest::Error> for BaseWrappedError {
    fn from(value: reqwest::Error) -> Self {
        BaseWrappedError::Reqwest(value)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) enum BaseErrorKind {
    TransportFailed,
    ProtocolError,
    NoSupportedVersion,
}

impl std::fmt::Display for BaseErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TransportFailed => f.write_str("Could not send or receive protocol message"),
            Self::ProtocolError => f.write_str("Unexpected response from remote"),
            Self::NoSupportedVersion => f.write_str("No overlap in versions"),
        }
    }
}

pub(crate) async fn negotiate_version(client: &reqwest::Client, url: Url) -> Result<PairingVersion, BaseError> {
    trace!("Start negotiating pairing protocol version.");
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| BaseError::new(BaseErrorKind::TransportFailed, e))?;

    if response.status() != StatusCode::OK {
        debug!(status = ?response.status(), "Unexpected status in response to version request.");
        return Err(BaseErrorKind::ProtocolError.into());
    }

    let supported_versions = response
        .json::<Vec<WirePairingVersion>>()
        .await
        .map_err(|e| BaseError::new(BaseErrorKind::ProtocolError, e))?;

    trace!(?supported_versions, "Received supported versions.");

    for version in supported_versions.into_iter().filter_map(|v| v.try_into().ok()) {
        if SUPPORTED_PAIRING_VERSIONS.contains(&version) {
            trace!(?version, "Negotiated version of pairing protocol.");
            return Ok(version);
        }
    }

    trace!("No shared pairing version between client and server.");
    Err(BaseErrorKind::NoSupportedVersion.into())
}
