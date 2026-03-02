use thiserror::Error;

use crate::common::{BaseError, BaseErrorKind, BaseWrappedError};

/// An error that occured during the pairing process.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    wrapped_error: WrappedError,
}

impl Error {
    #[allow(
        private_bounds,
        reason = "WrappedError is an implementation detail, caller cares only that about whether the proper conversion exists for his type."
    )]
    pub(crate) fn new<E: Into<WrappedError>>(kind: ErrorKind, inner: E) -> Self {
        Self {
            kind,
            wrapped_error: inner.into(),
        }
    }

    /// What kind of error occurred?
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(inner) = self.wrapped_error.contents() {
            write!(f, "{}: {inner}", self.kind)
        } else {
            self.kind.fmt(f)
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.wrapped_error.contents()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            wrapped_error: WrappedError::None,
        }
    }
}

impl From<BaseError> for Error {
    fn from(value: BaseError) -> Self {
        Self {
            kind: value.kind.into(),
            wrapped_error: value.wrapped_error.into(),
        }
    }
}

#[derive(Debug)]
enum WrappedError {
    None,
    Reqwest(reqwest::Error),
    UrlParse(url::ParseError),
    Rustls(rustls::Error),
}

impl WrappedError {
    fn contents(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::None => None,
            Self::Reqwest(error) => Some(error),
            Self::UrlParse(error) => Some(error),
            Self::Rustls(error) => Some(error),
        }
    }
}

impl From<BaseWrappedError> for WrappedError {
    fn from(value: BaseWrappedError) -> Self {
        match value {
            BaseWrappedError::None => Self::None,
            BaseWrappedError::Reqwest(error) => Self::Reqwest(error),
        }
    }
}

impl From<reqwest::Error> for WrappedError {
    fn from(value: reqwest::Error) -> Self {
        Self::Reqwest(value)
    }
}

impl From<url::ParseError> for WrappedError {
    fn from(value: url::ParseError) -> Self {
        Self::UrlParse(value)
    }
}

impl From<rustls::Error> for WrappedError {
    fn from(value: rustls::Error) -> Self {
        Self::Rustls(value)
    }
}

/// Kind of error that occured during the pairing process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Invalid URL for remote.
    InvalidUrl,
    /// Something went wrong in the transport layers.
    TransportFailed,
    /// The remote reacted outside our expectations.
    ProtocolError,
    /// No shared version with the remote.
    NoSupportedVersion,
    /// Session timed out.
    Timeout,
    /// Already a pending pairing session with that node id.
    AlreadyPending,
    /// Provided token was invalid.
    InvalidToken,
    /// The pairing session was cancelled.
    Cancelled,
    /// The remote is of the same type.
    RemoteOfSameType,
    /// The configuration was invalid.
    InvalidConfig(ConfigError),
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl => f.write_str("Invalid URL for remote"),
            Self::TransportFailed => f.write_str("Could not send or receive protocol message"),
            Self::ProtocolError => f.write_str("Unexpected response from remote"),
            Self::NoSupportedVersion => f.write_str("No overlap in versions"),
            Self::Timeout => f.write_str("Timed out"),
            Self::AlreadyPending => f.write_str("A pairing session for this node is already pending"),
            Self::InvalidToken => f.write_str("The token used does not match with that of the remote"),
            Self::Cancelled => f.write_str("Pairing was cancelled by remote"),
            Self::RemoteOfSameType => f.write_str("Remote is of same type of us"),
            Self::InvalidConfig(config_error) => config_error.fmt(f),
        }
    }
}

impl From<BaseErrorKind> for ErrorKind {
    fn from(value: BaseErrorKind) -> Self {
        match value {
            BaseErrorKind::TransportFailed => Self::TransportFailed,
            BaseErrorKind::ProtocolError => Self::ProtocolError,
            BaseErrorKind::NoSupportedVersion => Self::NoSupportedVersion,
        }
    }
}

impl From<ConfigError> for ErrorKind {
    fn from(value: ConfigError) -> Self {
        Self::InvalidConfig(value)
    }
}

/// Error for problems with inconsistent [`NodeConfig`](super::NodeConfig).
#[derive(Error, Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ConfigError {
    /// The [`NodeConfig`](super::NodeConfig) doesn't have an `connection_initiate_url` even though it is needed for the configuration to make sense.
    #[error("Missing connection_initiate_url, even though it is required for CEM and WAN endpoints")]
    MissingInitiateUrl,
}
