//! Combined error type for the crate.
//!
//! Pairing, communication, and discovery are mostly disjoint, and each have
//! fairly different error types. Therefore, we have individual error types for
//! each. However, when creating a device that combines multiple of these
//! functions, it can be useful to have a single error type that combines all
//! these errors. This module provides that error type, which is also used by
//! the combined pairing and communication server.
use crate::{
    common::{BaseError, BaseErrorKind, BaseWrappedError},
    communication::{self, wire::CommunicationDetailsErrorMessage},
    discovery,
    pairing::{
        self, ConfigError,
        wire::{PairingResponseErrorMessage, WaitForPairingErrorMessage},
    },
};

/// An error that occured during the pairing process.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    wrapped_error: WrappedError,
}

impl Error {
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

impl From<pairing::Error> for Error {
    fn from(value: pairing::Error) -> Self {
        Self {
            kind: value.kind.into(),
            wrapped_error: value.wrapped_error.into(),
        }
    }
}

impl From<discovery::Error> for Error {
    fn from(value: discovery::Error) -> Self {
        Self {
            kind: value.kind.into(),
            wrapped_error: value.wrapped_error.into(),
        }
    }
}

impl From<communication::Error> for Error {
    fn from(value: communication::Error) -> Self {
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
    UriParse(http::uri::InvalidUri),
    Rustls(rustls::Error),
    Tungstenite(tokio_tungstenite::tungstenite::Error),
    RemotePairing(PairingResponseErrorMessage),
    RemoteCommunication(CommunicationDetailsErrorMessage),
    Longpolling(WaitForPairingErrorMessage),
    Zeroconf(zeroconf_tokio::error::Error),
    Boxed(Box<dyn std::error::Error + Send + 'static>),
}

impl WrappedError {
    fn contents(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::None => None,
            Self::Reqwest(error) => Some(error),
            Self::UrlParse(error) => Some(error),
            Self::UriParse(error) => Some(error),
            Self::Rustls(error) => Some(error),
            Self::Tungstenite(error) => Some(error),
            Self::RemotePairing(error) => Some(error),
            Self::RemoteCommunication(error) => Some(error),
            Self::Longpolling(error) => Some(error),
            Self::Zeroconf(error) => Some(error),
            Self::Boxed(error) => Some(error.as_ref()),
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

impl From<pairing::WrappedError> for WrappedError {
    fn from(value: pairing::WrappedError) -> Self {
        match value {
            pairing::WrappedError::None => Self::None,
            pairing::WrappedError::Reqwest(error) => Self::Reqwest(error),
            pairing::WrappedError::UrlParse(parse_error) => Self::UrlParse(parse_error),
            pairing::WrappedError::Rustls(error) => Self::Rustls(error),
            pairing::WrappedError::Remote(pairing_response_error_message) => Self::RemotePairing(pairing_response_error_message),
            pairing::WrappedError::Longpolling(wait_for_pairing_error_message) => Self::Longpolling(wait_for_pairing_error_message),
            pairing::WrappedError::Boxed(error) => Self::Boxed(error),
        }
    }
}

impl From<discovery::WrappedError> for WrappedError {
    fn from(value: discovery::WrappedError) -> Self {
        match value {
            discovery::WrappedError::None => Self::None,
            discovery::WrappedError::Zeroconf(error) => Self::Zeroconf(error),
        }
    }
}

impl From<communication::WrappedError> for WrappedError {
    fn from(value: communication::WrappedError) -> Self {
        match value {
            communication::WrappedError::None => Self::None,
            communication::WrappedError::Reqwest(error) => Self::Reqwest(error),
            communication::WrappedError::Rustls(error) => Self::Rustls(error),
            communication::WrappedError::Tungstenite(error) => Self::Tungstenite(error),
            communication::WrappedError::UrlParse(parse_error) => Self::UrlParse(parse_error),
            communication::WrappedError::UriParse(invalid_uri) => Self::UriParse(invalid_uri),
            communication::WrappedError::Remote(communication_details_error_message) => {
                Self::RemoteCommunication(communication_details_error_message)
            }
            communication::WrappedError::Store(error) => Self::Boxed(error),
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

impl From<PairingResponseErrorMessage> for WrappedError {
    fn from(value: PairingResponseErrorMessage) -> Self {
        Self::RemotePairing(value)
    }
}

impl From<WaitForPairingErrorMessage> for WrappedError {
    fn from(value: WaitForPairingErrorMessage) -> Self {
        Self::Longpolling(value)
    }
}

impl From<zeroconf_tokio::error::Error> for WrappedError {
    fn from(value: zeroconf_tokio::error::Error) -> Self {
        WrappedError::Zeroconf(value)
    }
}

impl From<Box<dyn std::error::Error + Send + 'static>> for WrappedError {
    fn from(value: Box<dyn std::error::Error + Send + 'static>) -> Self {
        Self::Boxed(value)
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
    /// Unknown S2 Node
    UnknownNode,
    /// Session timed out.
    Timeout,
    /// Already have a pending pairing or longpolling session with that node id.
    AlreadyPending,
    /// Provided token was invalid.
    InvalidToken,
    /// Provided node alias was invalid.
    InvalidNodeAlias,
    /// Remote permanently rejects longpolling or querying of node information.
    Rejected,
    /// The pairing or longpolling session was cancelled.
    Cancelled,
    /// The remote is of the same type.
    RemoteOfSameType,
    /// The provided callback returned an error
    CallbackFailed,
    /// The configuration was invalid.
    InvalidConfig(ConfigError),
    /// The server configuration was invalid.
    InvalidServerConfig,
    /// Somehting went wrong with the mDNS protocol handling.
    MdnsError,
    /// The nodes are no longer paired.
    Unpaired,
    /// The nodes were not paired.
    NotPaired,
    /// Storage failed to persist token.
    Storage,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl => f.write_str("Invalid URL for remote"),
            Self::TransportFailed => f.write_str("Could not send or receive protocol message"),
            Self::ProtocolError => f.write_str("Unexpected response from remote"),
            Self::NoSupportedVersion => f.write_str("No overlap in versions"),
            Self::UnknownNode => f.write_str("Requested S2 Node not known to remote"),
            Self::Timeout => f.write_str("Timed out"),
            Self::AlreadyPending => f.write_str("A pairing or longpolling session for this node is already pending"),
            Self::InvalidToken => f.write_str("The token used does not match with that of the remote"),
            Self::InvalidNodeAlias => f.write_str("The node alias provided is not valid"),
            Self::Rejected => f.write_str("Longpolling was permanently rejected by remote"),
            Self::Cancelled => f.write_str("Pairing or longpolling was cancelled by remote"),
            Self::RemoteOfSameType => f.write_str("Remote is of same type of us"),
            Self::CallbackFailed => f.write_str("Pairing could not be handled by callback"),
            Self::InvalidConfig(config_error) => config_error.fmt(f),
            Self::InvalidServerConfig => f.write_str(""),
            Self::MdnsError => f.write_str("mDNS failed"),
            Self::Unpaired => f.write_str("Remote became unpaired from us"),
            Self::NotPaired => f.write_str("Remote has no knowledge of previous pairing with us"),
            Self::Storage => f.write_str("Storage failed to persist access token"),
        }
    }
}

impl From<pairing::ErrorKind> for ErrorKind {
    fn from(value: pairing::ErrorKind) -> Self {
        match value {
            pairing::ErrorKind::InvalidUrl => Self::InvalidUrl,
            pairing::ErrorKind::TransportFailed => Self::TransportFailed,
            pairing::ErrorKind::ProtocolError => Self::ProtocolError,
            pairing::ErrorKind::NoSupportedVersion => Self::NoSupportedVersion,
            pairing::ErrorKind::UnknownNode => Self::UnknownNode,
            pairing::ErrorKind::Timeout => Self::Timeout,
            pairing::ErrorKind::AlreadyPending => Self::AlreadyPending,
            pairing::ErrorKind::InvalidToken => Self::InvalidToken,
            pairing::ErrorKind::InvalidNodeAlias => Self::InvalidNodeAlias,
            pairing::ErrorKind::Rejected => Self::Rejected,
            pairing::ErrorKind::Cancelled => Self::Cancelled,
            pairing::ErrorKind::RemoteOfSameType => Self::RemoteOfSameType,
            pairing::ErrorKind::CallbackFailed => Self::CallbackFailed,
            pairing::ErrorKind::InvalidConfig(config_error) => Self::InvalidConfig(config_error),
        }
    }
}

impl From<discovery::ErrorKind> for ErrorKind {
    fn from(value: discovery::ErrorKind) -> Self {
        match value {
            discovery::ErrorKind::MdnsError => Self::MdnsError,
        }
    }
}

impl From<communication::ErrorKind> for ErrorKind {
    fn from(value: communication::ErrorKind) -> Self {
        match value {
            communication::ErrorKind::InvalidUrl => Self::InvalidUrl,
            communication::ErrorKind::TransportFailed => Self::TransportFailed,
            communication::ErrorKind::ProtocolError => Self::ProtocolError,
            communication::ErrorKind::NoSupportedVersion => Self::NoSupportedVersion,
            communication::ErrorKind::Unpaired => Self::Unpaired,
            communication::ErrorKind::NotPaired => Self::NotPaired,
            communication::ErrorKind::Storage => Self::Storage,
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
