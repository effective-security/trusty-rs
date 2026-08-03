//! TLS key-material helpers (cert chain + signing key; no rustls types).

use pem::parse_many;
use std::fs;
use std::sync::Arc;
use trusty_cryptoprov_core::{Crypto, Error, Result, Signer};
use x509_cert::Certificate;
use x509_cert::der::Decode;

/// Parsed certificate chain and associated private key.
#[derive(Clone, Debug)]
pub struct TlsKeyMaterial {
    /// DER certificates, leaf first then intermediates.
    pub cert_chain_der: Vec<Vec<u8>>,
    /// Private key (software or PKCS#11).
    pub key: Arc<dyn Signer>,
    /// Parsed leaf certificate (sanity check).
    pub leaf_parsed: Certificate,
}

/// Load TLS key material from PEM certificate and key files.
///
/// Crate-private: see [`crate::ext::CryptoExt::load_tls_key_pair`] for the
/// public entry point (an inherent method can't be added to `Crypto`, which
/// lives in `trusty-cryptoprov-core`).
///
/// # Errors
///
/// I/O or parse failures from [`tls_key_pair`].
pub(crate) fn load_tls_key_pair(
    crypto: &Crypto,
    cert_file: &str,
    key_file: &str,
) -> Result<TlsKeyMaterial> {
    let cert_pem = fs::read(cert_file)?;
    let key_pem = fs::read(key_file)?;
    tls_key_pair(crypto, &cert_pem, &key_pem)
}

/// Parse TLS key material from PEM certificate and key bytes.
///
/// # Errors
///
/// Missing CERTIFICATE blocks, leaf parse failure, or private-key load errors.
pub(crate) fn tls_key_pair(
    crypto: &Crypto,
    cert_pem_block: &[u8],
    key_pem_block: &[u8],
) -> Result<TlsKeyMaterial> {
    let blocks = parse_many(cert_pem_block)
        .map_err(|e| Error::Config(format!("tls: failed to parse certificate PEM: {e}")))?;

    let mut cert_chain_der = Vec::new();
    let mut skipped_block_types = Vec::new();
    for block in &blocks {
        if block.tag() == "CERTIFICATE" {
            cert_chain_der.push(block.contents().to_vec());
        } else {
            skipped_block_types.push(block.tag().to_string());
        }
    }

    if cert_chain_der.is_empty() {
        if skipped_block_types.is_empty() {
            return Err(Error::Config(
                "tls: failed to find any PEM data in certificate input".into(),
            ));
        }
        if skipped_block_types.len() == 1 && skipped_block_types[0].ends_with("PRIVATE KEY") {
            return Err(Error::Config(
                "tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched".into(),
            ));
        }
        return Err(Error::Config(format!(
            "tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: {skipped_block_types:?}"
        )));
    }

    let leaf_parsed = Certificate::from_der(&cert_chain_der[0])
        .map_err(|e| Error::Config(format!("tls: failed to parse leaf certificate: {e}")))?;

    let (_provider, key) = crate::keys::load_private_key(crypto, key_pem_block)?;

    Ok(TlsKeyMaterial { cert_chain_der, key, leaf_parsed })
}

#[cfg(all(test, feature = "inmem"))]
mod tests {
    use crate::CryptoExt;
    use crate::test_support::inmem_crypto;
    use std::path::PathBuf;

    #[test]
    fn load_testdata_tls_pair() {
        let crypto = inmem_crypto();
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata");
        let mat = crypto
            .load_tls_key_pair(
                dir.join("test-cert.pem").to_str().unwrap(),
                dir.join("test-key.pem").to_str().unwrap(),
            )
            .unwrap();
        assert!(!mat.cert_chain_der.is_empty());
        use sha2::{Digest, Sha256};
        use trusty_cryptoprov_core::{DigestAlgorithm, RsaSignScheme};
        let digest = Sha256::digest(b"tls smoke test");
        let scheme = RsaSignScheme::Pkcs1v15 { hash: DigestAlgorithm::Sha256 };
        assert!(mat.key.sign_rsa(&digest, &scheme).is_ok() || mat.key.sign_ecdsa(&digest).is_ok());
    }
}
