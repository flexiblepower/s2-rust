use std::sync::{Arc, OnceLock};

use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::CertificateDer,
};
use sha2::Digest;

use crate::pairing::Error;

use super::{ErrorKind, PairingResult};

#[derive(Debug)]
struct HashingCertificateVerifier {
    inner: rustls_platform_verifier::Verifier,
    self_signed_state: Arc<OnceLock<SelfSignedState>>,
}

#[derive(Debug)]
struct SelfSignedState {
    hash: CertificateHash,
    verifier: SelfVerifier,
}

#[derive(Debug)]
enum SelfVerifier {
    WebPki(WebPkiServerVerifier),
    None,
}

impl ServerCertVerifier for SelfVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match self {
            SelfVerifier::WebPki(web_pki_server_verifier) => {
                web_pki_server_verifier.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            }
            SelfVerifier::None => Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        match self {
            SelfVerifier::WebPki(web_pki_server_verifier) => web_pki_server_verifier.verify_tls12_signature(message, cert, dss),
            SelfVerifier::None => Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)),
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        match self {
            SelfVerifier::WebPki(web_pki_server_verifier) => web_pki_server_verifier.verify_tls13_signature(message, cert, dss),
            SelfVerifier::None => Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        match self {
            SelfVerifier::WebPki(web_pki_server_verifier) => web_pki_server_verifier.supported_verify_schemes(),
            SelfVerifier::None => vec![],
        }
    }
}

type CertificateHash = sha2::digest::generic_array::GenericArray<u8, <sha2::Sha256 as sha2::digest::OutputSizeUser>::OutputSize>;

impl ServerCertVerifier for HashingCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
        {
            Ok(v) => Ok(v),
            Err(_) => {
                let state = self.self_signed_state.get_or_init(|| {
                    let fallback = CertificateDer::from_slice(&[]);
                    let root_cert = intermediates.last().unwrap_or(&fallback);
                    let hash = sha2::Sha256::digest(end_entity);
                    let mut root_store = RootCertStore::empty();
                    // conciously ignore errors here, we just want to initialize
                    root_store.add(root_cert.clone()).ok();
                    let verifier = match WebPkiServerVerifier::builder(Arc::new(root_store)).build() {
                        Ok(verifier) => SelfVerifier::WebPki(Arc::try_unwrap(verifier).unwrap()),
                        Err(_) => SelfVerifier::None,
                    };

                    SelfSignedState { hash, verifier }
                });
                state
                    .verifier
                    .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub(crate) struct HashProvider {
    state: Arc<OnceLock<SelfSignedState>>,
}

impl HashProvider {
    pub(crate) fn hash(&self) -> Option<&[u8]> {
        match self.state.get() {
            Some(state) => Some(&state.hash),
            None => None,
        }
    }
}

pub(crate) fn hash_providing_https_client() -> PairingResult<(reqwest::Client, HashProvider)> {
    let rustls_config_builder = rustls::ClientConfig::builder();
    let crypto_provider = rustls_config_builder.crypto_provider().clone();
    let self_signed_state = Arc::new(OnceLock::new());
    let state = self_signed_state.clone();
    let verifier = HashingCertificateVerifier {
        inner: rustls_platform_verifier::Verifier::new(crypto_provider).map_err(|e| Error::new(ErrorKind::TransportFailed, e))?,
        self_signed_state,
    };
    let client_config = rustls_config_builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    let client = reqwest::Client::builder()
        .use_preconfigured_tls(client_config)
        .build()
        .map_err(|e| Error::new(ErrorKind::TransportFailed, e))?;

    Ok((client, HashProvider { state }))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use axum::{Router, routing::get};
    use axum_server::tls_rustls::RustlsConfig;

    use crate::pairing::transport::hash_providing_https_client;

    #[tokio::test]
    async fn matching_certificates() {
        let rustls_config = RustlsConfig::from_pem(
            include_bytes!("../../testdata/localhost.chain.pem").into(),
            include_bytes!("../../testdata/localhost.key").into(),
        )
        .await
        .unwrap();
        let router = Router::new().route("/", get(|| async { "Hello world" }));
        let https_server_handle = axum_server::Handle::new();
        let https_server_handle_clone = https_server_handle.clone();
        tokio::spawn(async move {
            axum_server::bind_rustls(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0), rustls_config)
                .handle(https_server_handle_clone)
                .serve(router.into_make_service())
                .await
                .unwrap();
        });
        let addr = https_server_handle.listening().await.unwrap();

        let (client, hash_provider) = hash_providing_https_client().unwrap();
        assert!(client.get(format!("https://localhost:{}/", addr.port())).send().await.is_ok());
        assert!(hash_provider.hash().is_some());
        assert!(client.get(format!("https://localhost:{}/", addr.port())).send().await.is_ok());

        https_server_handle.shutdown();
    }

    #[tokio::test]
    async fn matching_root_certificates() {
        let rustls_config = RustlsConfig::from_pem(
            include_bytes!("../../testdata/localhost.chain.pem").into(),
            include_bytes!("../../testdata/localhost.key").into(),
        )
        .await
        .unwrap();
        let router = Router::new().route("/", get(|| async { "Hello world" }));
        let https_server_handle = axum_server::Handle::new();
        let https_server_handle_clone = https_server_handle.clone();
        tokio::spawn(async move {
            axum_server::bind_rustls(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0), rustls_config)
                .handle(https_server_handle_clone)
                .serve(router.into_make_service())
                .await
                .unwrap();
        });
        let addr = https_server_handle.listening().await.unwrap();

        let (client, hash_provider) = hash_providing_https_client().unwrap();
        assert!(client.get(format!("https://localhost:{}/", addr.port())).send().await.is_ok());
        assert!(hash_provider.hash().is_some());

        https_server_handle.shutdown();

        let rustls_config = RustlsConfig::from_pem(
            include_bytes!("../../testdata/localhost-alt.chain.pem").into(),
            include_bytes!("../../testdata/localhost-alt.key").into(),
        )
        .await
        .unwrap();
        let router = Router::new().route("/", get(|| async { "Hello world" }));
        let https_server_handle = axum_server::Handle::new();
        let https_server_handle_clone = https_server_handle.clone();
        tokio::spawn(async move {
            axum_server::bind_rustls(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0), rustls_config)
                .handle(https_server_handle_clone)
                .serve(router.into_make_service())
                .await
                .unwrap();
        });
        let addr = https_server_handle.listening().await.unwrap();

        assert!(client.get(format!("https://localhost:{}/", addr.port())).send().await.is_ok());
    }

    #[tokio::test]
    async fn detects_mismatched_roots() {
        let rustls_config = RustlsConfig::from_pem(
            include_bytes!("../../testdata/localhost.chain.pem").into(),
            include_bytes!("../../testdata/localhost.key").into(),
        )
        .await
        .unwrap();
        let router = Router::new().route("/", get(|| async { "Hello world" }));
        let https_server_handle = axum_server::Handle::new();
        let https_server_handle_clone = https_server_handle.clone();
        tokio::spawn(async move {
            axum_server::bind_rustls(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0), rustls_config)
                .handle(https_server_handle_clone)
                .serve(router.into_make_service())
                .await
                .unwrap();
        });
        let addr = https_server_handle.listening().await.unwrap();

        let (client, hash_provider) = hash_providing_https_client().unwrap();
        assert!(client.get(format!("https://localhost:{}/", addr.port())).send().await.is_ok());
        assert!(hash_provider.hash().is_some());

        https_server_handle.shutdown();

        let rustls_config = RustlsConfig::from_pem(
            include_bytes!("../../testdata/localhost-altroot.chain.pem").into(),
            include_bytes!("../../testdata/localhost-altroot.key").into(),
        )
        .await
        .unwrap();
        let router = Router::new().route("/", get(|| async { "Hello world" }));
        let https_server_handle = axum_server::Handle::new();
        let https_server_handle_clone = https_server_handle.clone();
        tokio::spawn(async move {
            axum_server::bind_rustls(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0), rustls_config)
                .handle(https_server_handle_clone)
                .serve(router.into_make_service())
                .await
                .unwrap();
        });
        let addr = https_server_handle.listening().await.unwrap();

        assert!(client.get(format!("https://localhost:{}/", addr.port())).send().await.is_err());
    }
}
