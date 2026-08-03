//! Private-key loading glue: PEM bytes or a PKCS#11 private-key URI.
//!
//! Software-key material and PEM/DER parsing live in `trusty-cryptoprov-inmem`
//! and are re-exported from this facade when the `inmem` feature is enabled.

#[cfg(feature = "inmem")]
pub use trusty_cryptoprov_inmem::{
    EcdsaSoftwareKey, SoftwareEcdsaKey, SoftwareKey, SoftwareRsaKey, get_private_key_der_from_pem,
    key_purpose_from_int, parse_private_key_der, parse_private_key_pem,
    parse_private_key_pem_with_password,
};

use std::sync::Arc;
use trusty_cryptoprov_core::{Crypto, Provider, Result, Signer};

/// A signer loaded from PEM or a PKCS#11 URI, plus the provider that owns it
/// (`Some` only when resolved from a `pkcs11:` URI; `None` for PEM keys,
/// which aren't backed by any provider).
pub type LoadedKey = (Option<Arc<dyn Provider>>, Arc<dyn Signer>);

/// Load a private key from PEM bytes or a PKCS#11 private-key URI string.
///
/// Returns `(optional provider, signer)`. Provider is set only for
/// `pkcs11:` URIs resolved via [`Crypto::find_provider`].
///
/// Crate-private: `Crypto` lives in `trusty-cryptoprov-core`, so this crate
/// can't add an inherent method to it (only trait impls on a foreign type
/// are allowed). [`crate::ext::CryptoExt::load_private_key`] is the public,
/// method-call-syntax entry point.
///
/// # Errors
///
/// URI/PEM parse failures, provider lookup, or `get_key` errors. Returns
/// [`trusty_cryptoprov_core::Error::UnableToDecodePrivateKey`] for PEM input
/// when the `inmem` feature (PEM/software-key parsing) is disabled.
// `crypto` is unused when the `pkcs11` feature is off: neither the disabled
// `pkcs11:` branch nor the PEM branch below touches it.
#[cfg_attr(not(feature = "pkcs11"), allow(unused_variables))]
pub(crate) fn load_private_key(crypto: &Crypto, key: &[u8]) -> Result<LoadedKey> {
    let key_pem = String::from_utf8_lossy(key);
    if key_pem.starts_with("pkcs11") {
        #[cfg(feature = "pkcs11")]
        {
            let pkuri = trusty_cryptoprov_pkcs11::parse_private_key_uri(key_pem.trim())
                .map_err(|e| e.context("failed to parse key"))?;
            let provider =
                crypto.find_provider(pkuri.manufacturer(), pkuri.model()).map_err(|e| {
                    e.context(format!(
                        "provider not found: {} model: {}",
                        pkuri.manufacturer(),
                        pkuri.model()
                    ))
                })?;
            let pvk = provider
                .get_key(pkuri.id())
                .map_err(|e| e.context(format!("unable to get key: {}", pkuri.id())))?;
            Ok((Some(provider), pvk))
        }
        #[cfg(not(feature = "pkcs11"))]
        {
            Err(trusty_cryptoprov_core::Error::InvalidUri
                .context("pkcs11: URI parsing requires the `pkcs11` feature"))
        }
    } else {
        #[cfg(feature = "inmem")]
        {
            let pvk = parse_private_key_pem(key).map_err(|e| e.context("failed to parse key"))?;
            Ok((None, pvk))
        }
        #[cfg(not(feature = "inmem"))]
        {
            Err(trusty_cryptoprov_core::Error::UnableToDecodePrivateKey
                .context("PEM key parsing requires the `inmem` feature"))
        }
    }
}

#[cfg(all(test, feature = "inmem"))]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    // rsa 0.9 is on digest 0.10; `Pkcs1v15Sign::new::<_>()` needs its
    // re-exported `Sha256`, not the crate-root `sha2` 0.11 one used to hash.
    use rsa::sha2::Sha256 as Sha256Scheme;
    use rsa::{Pkcs1v15Sign, RsaPublicKey};
    use sha2::{Digest, Sha256};
    use trusty_cryptoprov_core::{DigestAlgorithm, Error, RsaSignScheme};

    #[test]
    fn parse_testdata_key_pem() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("test-key.pem");
        let pem = std::fs::read(path).unwrap();
        let key = parse_private_key_pem(&pem).unwrap();
        let digest = Sha256::digest(b"is-a-signer-check");
        let scheme = RsaSignScheme::Pkcs1v15 { hash: DigestAlgorithm::Sha256 };
        assert!(key.sign_rsa(&digest, &scheme).is_ok() || key.sign_ecdsa(&digest).is_ok());
    }

    #[test]
    fn pem_testdata_key_sign_rsa() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("test-key.pem");
        let pem = std::fs::read(path).unwrap();
        let key = parse_private_key_pem(&pem).unwrap();
        let digest = Sha256::digest(b"pem sign");
        let scheme = RsaSignScheme::Pkcs1v15 { hash: DigestAlgorithm::Sha256 };
        if let Ok(sig) = key.sign_rsa(&digest, &scheme) {
            // Re-derive the public key straight from the PEM's DER (independently
            // of the `Signer` trait object) to verify the signature really
            // matches the testdata key, not just that signing didn't error.
            let der = get_private_key_der_from_pem(&pem, None).unwrap();
            let rsa_key = RsaPrivateKey::from_pkcs8_der(&der)
                .or_else(|_| RsaPrivateKey::from_pkcs1_der(&der))
                .unwrap();
            let pub_key = RsaPublicKey::from(&rsa_key);
            pub_key.verify(Pkcs1v15Sign::new::<Sha256Scheme>(), &digest, &sig).unwrap();
        } else {
            let sig = key.sign_ecdsa(&digest).unwrap();
            assert!(!sig.is_empty());
        }
    }

    #[test]
    fn key_purpose_from_int_mapping() {
        use trusty_cryptoprov_core::KeyPurpose;
        assert_eq!(key_purpose_from_int(1), KeyPurpose::Signing);
    }

    #[test]
    fn encrypted_pem_rejected() {
        let pem = b"-----BEGIN RSA PRIVATE KEY-----\n\
Proc-Type: 4,ENCRYPTED\n\
DEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF\n\
\n\
AAAA\n\
-----END RSA PRIVATE KEY-----\n";
        let err = parse_private_key_pem(pem).unwrap_err();
        assert!(matches!(err, Error::EncryptedPemUnsupported));
    }
}
