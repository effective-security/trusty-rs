//! Convenience methods on [`Crypto`].
//!
//! `Crypto` is defined in `trusty-cryptoprov-core`, so this crate cannot add
//! inherent methods to it — only a trait impl on a foreign type is allowed.
//! [`CryptoExt`] covers private-key/signer loading and TLS key material so a
//! caller needs a single `use` for method-call ergonomics on `Crypto`.

use crate::keys::LoadedKey;
use crate::tls::TlsKeyMaterial;
use crate::{keys, signer, tls};
use std::sync::Arc;
use trusty_cryptoprov_core::{Crypto, Result, Signer};

/// Facade-level convenience methods layered on top of [`Crypto`].
pub trait CryptoExt {
    /// Load a private key from PEM bytes or a PKCS#11 private-key URI string.
    ///
    /// # Errors
    ///
    /// URI/PEM parse failures, provider lookup, or `get_key` errors.
    fn load_private_key(&self, key: &[u8]) -> Result<LoadedKey>;

    /// Load a signer from a PEM file or PKCS#11 URI file contents.
    ///
    /// # Errors
    ///
    /// I/O errors or parse failures.
    fn new_signer_from_file(&self, ca_key_file: &str) -> Result<Arc<dyn Signer>>;

    /// Load a signer from PEM bytes or a PKCS#11 private-key URI.
    ///
    /// # Errors
    ///
    /// Parse failures.
    fn new_signer_from_pem(&self, ca_key: &[u8]) -> Result<Arc<dyn Signer>>;

    /// Load TLS key material from PEM certificate and key files.
    ///
    /// # Errors
    ///
    /// I/O or parse failures.
    fn load_tls_key_pair(&self, cert_file: &str, key_file: &str) -> Result<TlsKeyMaterial>;

    /// Parse TLS key material from PEM certificate and key bytes.
    ///
    /// # Errors
    ///
    /// Missing CERTIFICATE blocks, leaf parse failure, or private-key load errors.
    fn tls_key_pair(&self, cert_pem_block: &[u8], key_pem_block: &[u8]) -> Result<TlsKeyMaterial>;
}

impl CryptoExt for Crypto {
    fn load_private_key(&self, key: &[u8]) -> Result<LoadedKey> {
        keys::load_private_key(self, key)
    }

    fn new_signer_from_file(&self, ca_key_file: &str) -> Result<Arc<dyn Signer>> {
        signer::new_signer_from_file(self, ca_key_file)
    }

    fn new_signer_from_pem(&self, ca_key: &[u8]) -> Result<Arc<dyn Signer>> {
        signer::new_signer_from_pem(self, ca_key)
    }

    fn load_tls_key_pair(&self, cert_file: &str, key_file: &str) -> Result<TlsKeyMaterial> {
        tls::load_tls_key_pair(self, cert_file, key_file)
    }

    fn tls_key_pair(&self, cert_pem_block: &[u8], key_pem_block: &[u8]) -> Result<TlsKeyMaterial> {
        tls::tls_key_pair(self, cert_pem_block, key_pem_block)
    }
}
