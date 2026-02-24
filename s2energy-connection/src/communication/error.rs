use axum::http;

use crate::common::{BaseError, BaseErrorKind, BaseWrappedError};

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
    Rustls(rustls::Error),
    Tungstenite(tokio_tungstenite::tungstenite::Error),
    UrlParse(url::ParseError),
    UriParse(http::uri::InvalidUri),
    Store(Box<dyn std::error::Error + 'static>),
}

impl WrappedError {
    fn contents(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::None => None,
            Self::Reqwest(error) => Some(error),
            Self::Rustls(error) => Some(error),
            Self::Tungstenite(error) => Some(error),
            Self::UrlParse(error) => Some(error),
            Self::UriParse(error) => Some(error),
            Self::Store(error) => Some(error.as_ref()),
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
        WrappedError::Reqwest(value)
    }
}

impl From<rustls::Error> for WrappedError {
    fn from(value: rustls::Error) -> Self {
        WrappedError::Rustls(value)
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for WrappedError {
    fn from(value: tokio_tungstenite::tungstenite::Error) -> Self {
        WrappedError::Tungstenite(value)
    }
}

impl From<url::ParseError> for WrappedError {
    fn from(value: url::ParseError) -> Self {
        WrappedError::UrlParse(value)
    }
}

impl From<http::uri::InvalidUri> for WrappedError {
    fn from(value: http::uri::InvalidUri) -> Self {
        WrappedError::UriParse(value)
    }
}

impl From<Box<dyn std::error::Error + 'static>> for WrappedError {
    fn from(value: Box<dyn std::error::Error + 'static>) -> Self {
        WrappedError::Store(value)
    }
}

/// Error that occured during the communication process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Invalid URL for remote
    InvalidUrl,
    /// Something went wrong in the transport layers
    TransportFailed,
    /// The remote reacted outside our expectations
    ProtocolError,
    /// No shared version with the remote.
    NoSupportedVersion,
    /// The nodes are no longer paired
    Unpaired,
    /// The nodes were not paired
    NotPaired,
    /// Storage failed to persist token
    Storage,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::InvalidUrl => f.write_str("Invalid URL for remote"),
            ErrorKind::TransportFailed => f.write_str("Could not send or receive protocol message"),
            ErrorKind::ProtocolError => f.write_str("Unexpected response from remote"),
            ErrorKind::NoSupportedVersion => f.write_str("No overlap in versions"),
            ErrorKind::Unpaired => f.write_str("Remote became unpaired from us"),
            ErrorKind::NotPaired => f.write_str("Remote has no knowledge of previous pairing with us"),
            ErrorKind::Storage => f.write_str("Storage failed to persist access token"),
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
