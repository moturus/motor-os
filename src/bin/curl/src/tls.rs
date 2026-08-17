use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, RootCertStore};

use crate::{CurlError, CurlResult};

#[cfg(target_os = "motor")]
const DEFAULT_CA_BUNDLE: &str = "/system/cfg/ssl/ca-certificates.crt";
#[cfg(not(target_os = "motor"))]
const DEFAULT_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

pub fn client_config(ca_cert: Option<&Path>) -> CurlResult<Arc<ClientConfig>> {
    let path = ca_cert.map_or_else(|| PathBuf::from(DEFAULT_CA_BUNDLE), Path::to_owned);
    let file = File::open(&path).map_err(|error| {
        ca_error(format!(
            "failed opening CA certificate file `{}`: {error}",
            path.display()
        ))
    })?;
    config_from_reader(BufReader::new(file))
}

fn config_from_reader(mut reader: impl BufRead) -> CurlResult<Arc<ClientConfig>> {
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ca_error(format!("failed parsing CA certificate file: {error}")))?;
    if certificates.is_empty() {
        return Err(ca_error("CA certificate file contains no certificates"));
    }

    let mut roots = RootCertStore::empty();
    let (accepted, _) = roots.add_parsable_certificates(certificates);
    if accepted == 0 {
        return Err(ca_error("CA certificate file contains no usable roots"));
    }

    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&TLS13, &TLS12])
            .map_err(|error| {
                CurlError::new(
                    CurlError::TLS_CONNECT,
                    format!("failed configuring TLS versions: {error}"),
                )
            })?;
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn ca_error(message: impl Into<String>) -> CurlError {
    CurlError::new(CurlError::CA_CERTIFICATE, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const TEST_CERTIFICATE: &[u8] =
        include_bytes!("../../../../img_files/motor-os-base/system/cfg/ssl/ssl-cert.pem");

    #[test]
    fn builds_tls_12_and_13_client_with_http_11_alpn() {
        let config = config_from_reader(Cursor::new(TEST_CERTIFICATE)).unwrap();
        assert_eq!(config.alpn_protocols, [b"http/1.1"]);
    }

    #[test]
    fn rejects_missing_empty_and_malformed_ca_files() {
        let missing =
            client_config(Some(Path::new("/definitely/missing/curl-ca.pem"))).unwrap_err();
        assert_eq!(missing.code(), CurlError::CA_CERTIFICATE);

        for contents in [b"".as_slice(), b"-----BEGIN CERTIFICATE-----\n!"] {
            let error = config_from_reader(Cursor::new(contents)).unwrap_err();
            assert_eq!(error.code(), CurlError::CA_CERTIFICATE);
        }
    }
}
