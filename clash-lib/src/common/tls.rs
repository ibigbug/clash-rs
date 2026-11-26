use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
};
use tracing::warn;

use std::sync::{Arc, LazyLock};

pub static GLOBAL_ROOT_STORE: LazyLock<Arc<RootCertStore>> =
    LazyLock::new(global_root_store);

fn global_root_store() -> Arc<RootCertStore> {
    let root_store = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    Arc::new(root_store)
}

pub(crate) fn is_inline_pem(value: &str) -> bool {
    value.contains("-----BEGIN")
}

pub(crate) fn read_pem(value: &str) -> std::io::Result<String> {
    if is_inline_pem(value) {
        Ok(value.to_owned())
    } else {
        std::fs::read_to_string(value)
    }
}

/// Load a PEM certificate chain and private key from either inline PEM strings
/// or file paths. A string containing `-----BEGIN` is treated as inline PEM;
/// otherwise it is interpreted as a file path.
///
/// Returns `(cert_chain, private_key)` suitable for both rustls client auth
/// (mTLS, via `with_client_auth_cert`) and rustls server config
/// (`with_single_cert`).
pub fn load_cert_and_key(
    cert: &str,
    key: &str,
) -> std::io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_pem = read_pem(cert).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("failed to read certificate '{cert}': {e}"),
        )
    })?;

    let key_pem = read_pem(key).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("failed to read private key '{key}': {e}"),
        )
    })?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .filter_map(|r| {
                r.map_err(|e| warn!("failed to parse certificate entry: {e}"))
                    .ok()
            })
            .collect();

    if certs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no valid certificates found in PEM",
        ));
    }

    let private_key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("failed to parse private key: {e}"),
            )
        })?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no private key found in PEM",
            )
        })?;

    Ok((certs, private_key))
}

/// Resolve a server certificate chain and key for an inbound listener.
///
/// - both provided → loaded via [`load_cert_and_key`] (inline PEM or file path)
/// - both absent → an ephemeral self-signed certificate for `localhost`
/// - exactly one provided → an error
///
/// `who` names the caller (e.g. `"anytls"`, `"hysteria2"`) for error messages.
pub fn resolve_server_cert_and_key(
    certificate: Option<&str>,
    private_key: Option<&str>,
    who: &str,
) -> std::io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    match (certificate, private_key) {
        (Some(cert), Some(key)) => load_cert_and_key(cert, key),
        (None, None) => {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "failed to generate ephemeral {who} certificate: {e}"
                        ))
                    })?;
            let cert_der = CertificateDer::from(cert.der().to_vec());
            let key_der = PrivateKeyDer::try_from(signing_key.serialize_der())
                .map_err(|e| {
                    std::io::Error::other(format!(
                        "failed to serialize ephemeral {who} key: {e}"
                    ))
                })?;
            Ok((vec![cert_der], key_der))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{who} inbound: certificate and private-key must both be set, or \
                 both omitted"
            ),
        )),
    }
}

/// Build a `rustls` [`ClientConfig`] with a custom certificate verifier and
/// optional mTLS client certificate.
///
/// When `tls_cert` and `tls_key` are both `Some`, mutual TLS (mTLS) is
/// enabled by presenting the client certificate during the TLS handshake.
/// Both must be either `None` (no client auth) or `Some` (mTLS); mixing
/// them returns an [`io::Error`].
pub fn build_tls_client_config(
    verifier: Arc<dyn ServerCertVerifier>,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
) -> std::io::Result<rustls::ClientConfig> {
    match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            let (certs, private_key) = load_cert_and_key(cert, key)?;
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_client_auth_cert(certs, private_key)
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid mTLS client cert/key: {e}"),
                    )
                })
        }
        (None, None) => Ok(rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tls-cert and tls-key must both be set or both omitted",
        )),
    }
}

#[derive(Debug)]
pub struct DefaultTlsVerifier {
    fingerprint: Option<String>,
    skip: bool,
    pki: Arc<WebPkiServerVerifier>,
}

impl DefaultTlsVerifier {
    pub fn new(fingerprint: Option<String>, skip: bool) -> Self {
        Self {
            fingerprint,
            skip,
            pki: WebPkiServerVerifier::builder(GLOBAL_ROOT_STORE.clone())
                .build()
                .unwrap(),
        }
    }
}

impl ServerCertVerifier for DefaultTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(ref fingerprint) = self.fingerprint {
            let cert_hex =
                super::utils::encode_hex(&super::utils::sha256(end_entity.as_ref()));
            if &cert_hex != fingerprint {
                return Err(rustls::Error::General(format!(
                    "cert hash mismatch: found: {cert_hex}\nexcept: {fingerprint}"
                )));
            }
        }

        if self.skip {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        self.pki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        if self.skip {
            return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
        }
        self.pki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        if self.skip {
            return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
        }
        self.pki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.pki.supported_verify_schemes()
    }
}

#[derive(Debug)]
pub struct NoHostnameTlsVerifier(Arc<WebPkiServerVerifier>);

impl NoHostnameTlsVerifier {
    pub fn new() -> Self {
        Self(
            WebPkiServerVerifier::builder(GLOBAL_ROOT_STORE.clone())
                .build()
                .unwrap(),
        )
    }
}

impl ServerCertVerifier for NoHostnameTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match self.0.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Err(rustls::Error::UnsupportedNameType) => {
                warn!(
                    "skipping TLS cert name verification for server name: {:?}",
                    server_name
                );
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}
