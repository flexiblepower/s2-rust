//! Websocket extractor based on axums websocket extractor
//! uses code from:
//! - axums/src/extract/ws.rs
//! - axum-core/src/macros.rs
//!
//! Original license:
//!
//! Copyright (c) 2019 axum Contributors
//!
//! Permission is hereby granted, free of charge, to any
//! person obtaining a copy of this software and associated
//! documentation files (the "Software"), to deal in the
//! Software without restriction, including without
//! limitation the rights to use, copy, modify, merge,
//! publish, distribute, sublicense, and/or sell copies of
//! the Software, and to permit persons to whom the Software
//! is furnished to do so, subject to the following
//! conditions:
//!
//! The above copyright notice and this permission notice
//! shall be included in all copies or substantial portions
//! of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
//! ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
//! TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
//! PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
//! SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//! CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
//! OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
//! IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//! DEALINGS IN THE SOFTWARE.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    Error,
    body::{Body, Bytes},
    extract::FromRequestParts,
    http::{HeaderName, HeaderValue, request::Parts},
    response::Response,
};
use hyper::{HeaderMap, Method, StatusCode, Version, header};
use pin_project_lite::pin_project;
use sha1::{Digest, Sha1};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::protocol::{self, WebSocketConfig},
};

use rejection::*;

/// Extractor for establishing WebSocket connections.
///
/// For HTTP/1.1 requests, this extractor requires the request method to be `GET`;
/// in later versions, `CONNECT` is used instead.
/// To support both, it should be used with [`any`](crate::routing::any).
///
/// See the [module docs](self) for an example.
///
/// [`MethodFilter`]: crate::routing::MethodFilter
#[cfg_attr(docsrs, doc(cfg(feature = "ws")))]
#[must_use]
pub struct WebSocketUpgrade<F = DefaultOnFailedUpgrade> {
    config: WebSocketConfig,
    /// The chosen protocol sent in the `Sec-WebSocket-Protocol` header of the response.
    protocol: Option<HeaderValue>,
    /// `None` if HTTP/2+ WebSockets are used.
    sec_websocket_key: Option<HeaderValue>,
    on_upgrade: hyper::upgrade::OnUpgrade,
    on_failed_upgrade: F,
    sec_websocket_protocol: Option<HeaderValue>,
}

impl<F> std::fmt::Debug for WebSocketUpgrade<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketUpgrade")
            .field("config", &self.config)
            .field("protocol", &self.protocol)
            .field("sec_websocket_key", &self.sec_websocket_key)
            .field("sec_websocket_protocol", &self.sec_websocket_protocol)
            .finish_non_exhaustive()
    }
}

impl<F> WebSocketUpgrade<F> {
    /// Finalize upgrading the connection and call the provided callback with
    /// the stream.
    #[must_use = "to set up the WebSocket connection, this response must be returned"]
    pub fn on_upgrade<C, Fut>(self, callback: C) -> Response
    where
        C: FnOnce(WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
        F: OnFailedUpgrade,
    {
        let on_upgrade = self.on_upgrade;
        let config = self.config;
        let on_failed_upgrade = self.on_failed_upgrade;

        tokio::spawn(async move {
            let upgraded = match on_upgrade.await {
                Ok(upgraded) => upgraded,
                Err(err) => {
                    on_failed_upgrade.call(Error::new(err));
                    return;
                }
            };
            let upgraded = TokioIo::new(upgraded);

            let socket = WebSocketStream::from_raw_socket(upgraded, protocol::Role::Server, Some(config)).await;
            callback(socket).await;
        });

        let mut response = if let Some(sec_websocket_key) = &self.sec_websocket_key {
            // If `sec_websocket_key` was `Some`, we are using HTTP/1.1.

            #[allow(clippy::declare_interior_mutable_const)]
            const UPGRADE: HeaderValue = HeaderValue::from_static("upgrade");
            #[allow(clippy::declare_interior_mutable_const)]
            const WEBSOCKET: HeaderValue = HeaderValue::from_static("websocket");

            Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(header::CONNECTION, UPGRADE)
                .header(header::UPGRADE, WEBSOCKET)
                .header(header::SEC_WEBSOCKET_ACCEPT, sign(sec_websocket_key.as_bytes()))
                .body(Body::empty())
                .unwrap()
        } else {
            // Otherwise, we are HTTP/2+. As established in RFC 9113 section 8.5, we just respond
            // with a 2XX with an empty body:
            // <https://datatracker.ietf.org/doc/html/rfc9113#name-the-connect-method>.
            Response::new(Body::empty())
        };

        if let Some(protocol) = self.protocol {
            response.headers_mut().insert(header::SEC_WEBSOCKET_PROTOCOL, protocol);
        }

        response
    }
}

/// What to do when a connection upgrade fails.
///
/// See [`WebSocketUpgrade::on_failed_upgrade`] for more details.
pub trait OnFailedUpgrade: Send + 'static {
    /// Call the callback.
    fn call(self, error: Error);
}

impl<F> OnFailedUpgrade for F
where
    F: FnOnce(Error) + Send + 'static,
{
    fn call(self, error: Error) {
        self(error)
    }
}

/// The default `OnFailedUpgrade` used by `WebSocketUpgrade`.
///
/// It simply ignores the error.
#[non_exhaustive]
#[derive(Debug)]
pub struct DefaultOnFailedUpgrade;

impl OnFailedUpgrade for DefaultOnFailedUpgrade {
    #[inline]
    fn call(self, _error: Error) {}
}

impl<S> FromRequestParts<S> for WebSocketUpgrade<DefaultOnFailedUpgrade>
where
    S: Send + Sync,
{
    type Rejection = WebSocketUpgradeRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let sec_websocket_key = if parts.version <= Version::HTTP_11 {
            if parts.method != Method::GET {
                return Err(MethodNotGet.into());
            }

            if !header_contains(&parts.headers, header::CONNECTION, "upgrade") {
                return Err(InvalidConnectionHeader.into());
            }

            if !header_eq(&parts.headers, header::UPGRADE, "websocket") {
                return Err(InvalidUpgradeHeader.into());
            }

            Some(
                parts
                    .headers
                    .get(header::SEC_WEBSOCKET_KEY)
                    .ok_or(WebSocketKeyHeaderMissing)?
                    .clone(),
            )
        } else {
            if parts.method != Method::CONNECT {
                return Err(MethodNotConnect.into());
            }

            // if this feature flag is disabled, we won’t be receiving an HTTP/2 request to begin
            // with.
            if parts
                .extensions
                .get::<hyper::ext::Protocol>()
                .is_none_or(|p| p.as_str() != "websocket")
            {
                return Err(InvalidProtocolPseudoheader.into());
            }

            None
        };

        if !header_eq(&parts.headers, header::SEC_WEBSOCKET_VERSION, "13") {
            return Err(InvalidWebSocketVersionHeader.into());
        }

        let on_upgrade = parts
            .extensions
            .remove::<hyper::upgrade::OnUpgrade>()
            .ok_or(ConnectionNotUpgradable)?;

        let sec_websocket_protocol = parts.headers.get(header::SEC_WEBSOCKET_PROTOCOL).cloned();

        Ok(Self {
            config: Default::default(),
            protocol: None,
            sec_websocket_key,
            on_upgrade,
            sec_websocket_protocol,
            on_failed_upgrade: DefaultOnFailedUpgrade,
        })
    }
}

fn header_eq(headers: &HeaderMap, key: HeaderName, value: &'static str) -> bool {
    if let Some(header) = headers.get(&key) {
        header.as_bytes().eq_ignore_ascii_case(value.as_bytes())
    } else {
        false
    }
}

fn header_contains(headers: &HeaderMap, key: HeaderName, value: &'static str) -> bool {
    let header = if let Some(header) = headers.get(&key) {
        header
    } else {
        return false;
    };

    if let Ok(header) = std::str::from_utf8(header.as_bytes()) {
        header.to_ascii_lowercase().contains(value)
    } else {
        false
    }
}

fn sign(key: &[u8]) -> HeaderValue {
    use base64::engine::Engine as _;

    let mut sha1 = Sha1::default();
    sha1.update(key);
    sha1.update(&b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"[..]);
    let b64 = Bytes::from(base64::engine::general_purpose::STANDARD.encode(sha1.finalize()));
    HeaderValue::from_maybe_shared(b64).expect("base64 is a valid value")
}

pin_project! {
    /// A wrapper that implements Tokio's IO traits for an inner type that
    /// implements hyper's IO traits, or vice versa (implements hyper's IO
    /// traits for a type that implements Tokio's IO traits).
    #[derive(Debug)]
    pub struct TokioIo<T> {
        #[pin]
        inner: T,
    }
}

impl<T> TokioIo<T> {
    /// Wrap a type implementing Tokio's or hyper's IO traits.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> hyper::rt::Read for TokioIo<T>
where
    T: tokio::io::AsyncRead,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, mut buf: hyper::rt::ReadBufCursor<'_>) -> Poll<Result<(), std::io::Error>> {
        let n = unsafe {
            let mut tbuf = tokio::io::ReadBuf::uninit(buf.as_mut());
            match tokio::io::AsyncRead::poll_read(self.project().inner, cx, &mut tbuf) {
                Poll::Ready(Ok(())) => tbuf.filled().len(),
                other => return other,
            }
        };

        unsafe {
            buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<T> hyper::rt::Write for TokioIo<T>
where
    T: tokio::io::AsyncWrite,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        tokio::io::AsyncWrite::poll_write(self.project().inner, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_flush(self.project().inner, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_shutdown(self.project().inner, cx)
    }

    fn is_write_vectored(&self) -> bool {
        tokio::io::AsyncWrite::is_write_vectored(&self.inner)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        tokio::io::AsyncWrite::poll_write_vectored(self.project().inner, cx, bufs)
    }
}

impl<T> tokio::io::AsyncRead for TokioIo<T>
where
    T: hyper::rt::Read,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, tbuf: &mut tokio::io::ReadBuf<'_>) -> Poll<Result<(), std::io::Error>> {
        //let init = tbuf.initialized().len();
        let filled = tbuf.filled().len();
        let sub_filled = unsafe {
            let mut buf = hyper::rt::ReadBuf::uninit(tbuf.unfilled_mut());

            match hyper::rt::Read::poll_read(self.project().inner, cx, buf.unfilled()) {
                Poll::Ready(Ok(())) => buf.filled().len(),
                other => return other,
            }
        };

        let n_filled = filled + sub_filled;
        // At least sub_filled bytes had to have been initialized.
        let n_init = sub_filled;
        unsafe {
            tbuf.assume_init(n_init);
            tbuf.set_filled(n_filled);
        }

        Poll::Ready(Ok(()))
    }
}

impl<T> tokio::io::AsyncWrite for TokioIo<T>
where
    T: hyper::rt::Write,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        hyper::rt::Write::poll_write(self.project().inner, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        hyper::rt::Write::poll_flush(self.project().inner, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        hyper::rt::Write::poll_shutdown(self.project().inner, cx)
    }

    fn is_write_vectored(&self) -> bool {
        hyper::rt::Write::is_write_vectored(&self.inner)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        hyper::rt::Write::poll_write_vectored(self.project().inner, cx, bufs)
    }
}

pub mod rejection {
    //! WebSocket specific rejections.

    /// Private API.
    #[doc(hidden)]
    #[macro_export]
    macro_rules! __define_rejection {
        (
            #[status = $status:ident]
            #[body = $body:literal]
            $(#[$m:meta])*
            pub struct $name:ident;
        ) => {
            $(#[$m])*
            #[derive(Debug)]
            #[non_exhaustive]
            pub struct $name;

            impl $name {
                /// Get the status code used for this rejection.
                pub fn status(&self) -> axum::http::StatusCode {
                    axum::http::StatusCode::$status
                }
            }

            impl axum::response::IntoResponse for $name {
                fn into_response(self) -> axum::response::Response {
                    let status = self.status();

                    (status, $body).into_response()
                }
            }

            impl std::fmt::Display for $name {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, "{}", $body)
                }
            }

            impl std::error::Error for $name {}

            impl Default for $name {
                fn default() -> Self {
                    Self
                }
            }
        };

        (
            #[status = $status:ident]
            #[body = $body:literal]
            $(#[$m:meta])*
            pub struct $name:ident (Error);
        ) => {
            $(#[$m])*
            #[derive(Debug)]
            pub struct $name(pub(crate) $crate::Error);

            impl $name {
                pub(crate) fn from_err<E>(err: E) -> Self
                where
                    E: Into<$crate::BoxError>,
                {
                    Self($crate::Error::new(err))
                }

                /// Get the response body text used for this rejection.
                #[must_use]
                pub fn body_text(&self) -> String {
                    self.to_string()
                }

                /// Get the status code used for this rejection.
                #[must_use]
                pub fn status(&self) -> http::StatusCode {
                    http::StatusCode::$status
                }
            }

            impl $crate::response::IntoResponse for $name {
                fn into_response(self) -> $crate::response::Response {
                    let status = self.status();
                    let body_text = self.body_text();

                    (status, body_text).into_response()
                }
            }

            impl std::fmt::Display for $name {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str($body)?;
                    f.write_str(": ")?;
                    self.0.fmt(f)
                }
            }

            impl std::error::Error for $name {
                fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                    Some(&self.0)
                }
            }
        };
    }

    /// Private API.
    #[doc(hidden)]
    #[macro_export]
    macro_rules! __composite_rejection {
        (
            $(#[$m:meta])*
            pub enum $name:ident {
                $($variant:ident),+
                $(,)?
            }
        ) => {
            $(#[$m])*
            #[derive(Debug)]
            #[non_exhaustive]
            pub enum $name {
                $(
                    #[allow(missing_docs)]
                    $variant($variant)
                ),+
            }

            impl axum::response::IntoResponse for $name {
                fn into_response(self) -> axum::response::Response {
                    match self {
                        $(
                            Self::$variant(inner) => inner.into_response(),
                        )+
                    }
                }
            }

            $(
                impl From<$variant> for $name {
                    fn from(inner: $variant) -> Self {
                        Self::$variant(inner)
                    }
                }
            )+

            impl std::fmt::Display for $name {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    match self {
                        $(
                            Self::$variant(inner) => write!(f, "{inner}"),
                        )+
                    }
                }
            }

            impl std::error::Error for $name {
                fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                    match self {
                        $(
                            Self::$variant(inner) => inner.source(),
                        )+
                    }
                }
            }
        };
    }

    use __composite_rejection as composite_rejection;
    use __define_rejection as define_rejection;

    define_rejection! {
        #[status = METHOD_NOT_ALLOWED]
        #[body = "Request method must be `GET`"]
        /// Rejection type for [`WebSocketUpgrade`](super::WebSocketUpgrade).
        pub struct MethodNotGet;
    }

    define_rejection! {
        #[status = METHOD_NOT_ALLOWED]
        #[body = "Request method must be `CONNECT`"]
        /// Rejection type for [`WebSocketUpgrade`](super::WebSocketUpgrade).
        pub struct MethodNotConnect;
    }

    define_rejection! {
        #[status = BAD_REQUEST]
        #[body = "Connection header did not include 'upgrade'"]
        /// Rejection type for [`WebSocketUpgrade`](super::WebSocketUpgrade).
        pub struct InvalidConnectionHeader;
    }

    define_rejection! {
        #[status = BAD_REQUEST]
        #[body = "`Upgrade` header did not include 'websocket'"]
        /// Rejection type for [`WebSocketUpgrade`](super::WebSocketUpgrade).
        pub struct InvalidUpgradeHeader;
    }

    define_rejection! {
        #[status = BAD_REQUEST]
        #[body = "`:protocol` pseudo-header did not include 'websocket'"]
        /// Rejection type for [`WebSocketUpgrade`](super::WebSocketUpgrade).
        pub struct InvalidProtocolPseudoheader;
    }

    define_rejection! {
        #[status = BAD_REQUEST]
        #[body = "`Sec-WebSocket-Version` header did not include '13'"]
        /// Rejection type for [`WebSocketUpgrade`](super::WebSocketUpgrade).
        pub struct InvalidWebSocketVersionHeader;
    }

    define_rejection! {
        #[status = BAD_REQUEST]
        #[body = "`Sec-WebSocket-Key` header missing"]
        /// Rejection type for [`WebSocketUpgrade`](super::WebSocketUpgrade).
        pub struct WebSocketKeyHeaderMissing;
    }

    define_rejection! {
        #[status = UPGRADE_REQUIRED]
        #[body = "WebSocket request couldn't be upgraded since no upgrade state was present"]
        /// Rejection type for [`WebSocketUpgrade`](super::WebSocketUpgrade).
        ///
        /// This rejection is returned if the connection cannot be upgraded for example if the
        /// request is HTTP/1.0.
        ///
        /// See [MDN] for more details about connection upgrades.
        ///
        /// [MDN]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Upgrade
        pub struct ConnectionNotUpgradable;
    }

    composite_rejection! {
        /// Rejection used for [`WebSocketUpgrade`](super::WebSocketUpgrade).
        ///
        /// Contains one variant for each way the [`WebSocketUpgrade`](super::WebSocketUpgrade)
        /// extractor can fail.
        pub enum WebSocketUpgradeRejection {
            MethodNotGet,
            MethodNotConnect,
            InvalidConnectionHeader,
            InvalidUpgradeHeader,
            InvalidProtocolPseudoheader,
            InvalidWebSocketVersionHeader,
            WebSocketKeyHeaderMissing,
            ConnectionNotUpgradable,
        }
    }
}
