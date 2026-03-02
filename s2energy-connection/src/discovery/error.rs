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

#[derive(Debug)]
enum WrappedError {
    None,
    Zeroconf(zeroconf_tokio::error::Error),
}

impl WrappedError {
    fn contents(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::None => None,
            Self::Zeroconf(error) => Some(error),
        }
    }
}

impl From<zeroconf_tokio::error::Error> for WrappedError {
    fn from(value: zeroconf_tokio::error::Error) -> Self {
        WrappedError::Zeroconf(value)
    }
}

/// The kind of error that occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Somehting went wrong with the mDNS protocol handling.
    MdnsError,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::MdnsError => f.write_str("mDNS failed"),
        }
    }
}
