//! Signer helpers loading PEM / PKCS#11 URI material into a [`Signer`].

use std::fs;
use std::sync::Arc;
use trusty_cryptoprov_core::{Crypto, Error, Result, Signer};

/// Load a signer from a PEM file or PKCS#11 URI file contents.
///
/// Trailing whitespace is trimmed.
///
/// Crate-private: see [`crate::ext::CryptoExt::new_signer_from_file`] for the
/// public entry point (an inherent method can't be added to `Crypto`, which
/// lives in `trusty-cryptoprov-core`).
///
/// # Errors
///
/// I/O errors or parse failures.
pub(crate) fn new_signer_from_file(crypto: &Crypto, ca_key_file: &str) -> Result<Arc<dyn Signer>> {
    let mut cakey = fs::read(ca_key_file).map_err(|e| Error::Io(e).context("load key file"))?;
    let trimmed = String::from_utf8_lossy(&cakey).trim().as_bytes().to_vec();
    cakey.clear();
    new_signer_from_pem(crypto, &trimmed)
        .map_err(|e| e.context(format!("load key from file: {ca_key_file}")))
}

/// Load a signer from PEM bytes or a PKCS#11 private-key URI.
///
/// # Errors
///
/// Parse failures.
pub(crate) fn new_signer_from_pem(crypto: &Crypto, ca_key: &[u8]) -> Result<Arc<dyn Signer>> {
    let (_provider, signer) = crate::keys::load_private_key(crypto, ca_key)?;
    Ok(signer)
}

#[cfg(all(test, feature = "inmem"))]
mod tests {
    use crate::CryptoExt;
    use crate::test_support::inmem_crypto;
    use std::path::PathBuf;
    use trusty_cryptoprov_core::Error;

    #[test]
    fn signer_from_testdata_pem() {
        let crypto = inmem_crypto();
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("test-key.pem");
        let key = crypto.new_signer_from_file(path.to_str().unwrap()).unwrap();
        use sha2::{Digest, Sha256};
        use trusty_cryptoprov_core::{DigestAlgorithm, RsaSignScheme};
        let digest = Sha256::digest(b"signer smoke test");
        let scheme = RsaSignScheme::Pkcs1v15 { hash: DigestAlgorithm::Sha256 };
        assert!(key.sign_rsa(&digest, &scheme).is_ok() || key.sign_ecdsa(&digest).is_ok());
    }

    #[test]
    fn signer_missing_file() {
        let crypto = inmem_crypto();
        let err = crypto.new_signer_from_file("/nonexistent/cryptoprov-key.pem").unwrap_err();
        assert!(matches!(err.root_cause(), Error::Io(_)));
    }
}
