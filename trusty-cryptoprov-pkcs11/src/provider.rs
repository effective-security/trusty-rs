//! PKCS#11 adapter wrapping [`trusty_crypto11::Pkcs11Lib`].

use std::sync::Arc;
use trusty_crypto11::{OwnedTokenConfig, Pkcs11Lib};
use trusty_cryptoprov_core::{
    DigestAlgorithm, Error, KeyGenerator, KeyInfo, KeyManager, KeyPurpose, NamedCurve, Provider,
    ProviderLoader, PssSaltLen, Result, RsaSignScheme, Signer, TokenConfig, TokenInfo,
};

/// PKCS#11 provider implementing [`Provider`] + [`KeyManager`].
#[derive(Debug, Clone)]
pub struct Pkcs11Provider {
    lib: Pkcs11Lib,
}

impl Pkcs11Provider {
    /// Wrap an already-initialized crypto11 library handle.
    #[must_use]
    pub fn from_lib(lib: Pkcs11Lib) -> Self {
        Self { lib }
    }

    /// Convert cryptoprov token config into crypto11 [`OwnedTokenConfig`].
    #[must_use]
    pub fn to_owned_token_config(cfg: &dyn TokenConfig) -> OwnedTokenConfig {
        OwnedTokenConfig {
            manufacturer: cfg.manufacturer().to_string(),
            model: cfg.model().to_string(),
            path: cfg.path().to_string(),
            token_serial: cfg.token_serial().to_string(),
            token_label: cfg.token_label().to_string(),
            pin: cfg.pin().clone(),
            attributes: cfg.attributes().to_string(),
        }
    }

    /// Load PKCS#11 from cryptoprov token config via crypto11.
    ///
    /// # Errors
    ///
    /// Propagates [`trusty_crypto11::load_provider`] failures.
    pub fn load(cfg: &dyn TokenConfig) -> Result<Self> {
        let owned = Self::to_owned_token_config(cfg);
        let lib = trusty_crypto11::load_provider(owned).map_err(crypto11_err)?;
        Ok(Self { lib })
    }

    /// Access the underlying PKCS#11 library.
    #[must_use]
    pub fn lib(&self) -> &Pkcs11Lib {
        &self.lib
    }
}

impl KeyGenerator for Pkcs11Provider {
    fn generate_rsa_key(
        &self,
        label: &str,
        bits: usize,
        purpose: KeyPurpose,
    ) -> Result<Arc<dyn Signer>> {
        let generated = self
            .lib
            .generate_rsa_key(label, bits, key_purpose_to_crypto11(purpose))
            .map_err(crypto11_err)?;
        Ok(Arc::new(Pkcs11Signer { key: generated.key, id: generated.id, label: generated.label }))
    }

    fn generate_ecdsa_key(&self, label: &str, curve: NamedCurve) -> Result<Arc<dyn Signer>> {
        let generated = self
            .lib
            .generate_ecdsa_key(label, named_curve_to_crypto11(curve))
            .map_err(crypto11_err)?;
        Ok(Arc::new(Pkcs11Signer { key: generated.key, id: generated.id, label: generated.label }))
    }

    fn export_key(&self, key_id: &str) -> Result<(String, Vec<u8>)> {
        let uri = self.lib.export_key(key_id).map_err(crypto11_err)?;
        Ok((uri, Vec::new()))
    }

    fn get_key(&self, key_id: &str) -> Result<Arc<dyn Signer>> {
        let key = self.lib.get_key(key_id).map_err(crypto11_err)?;
        // `get_key` looks up by id, so the id is already known; label isn't
        // resolved here (would need a separate HSM attribute read).
        Ok(Arc::new(Pkcs11Signer { key, id: key_id.to_string(), label: String::new() }))
    }
}

impl KeyManager for Pkcs11Provider {
    fn current_slot_id(&self) -> u64 {
        self.lib.current_slot_id()
    }

    fn enum_tokens(&self, current_slot_only: bool) -> Result<Vec<TokenInfo>> {
        let list = self.lib.enum_tokens(current_slot_only).map_err(crypto11_err)?;
        Ok(list.into_iter().map(token_info_from_crypto11).collect())
    }

    fn enum_keys(&self, slot_id: u64, prefix: &str) -> Result<Vec<KeyInfo>> {
        let list = self.lib.enum_keys(slot_id, prefix).map_err(crypto11_err)?;
        Ok(list.into_iter().map(key_info_from_crypto11).collect())
    }

    fn destroy_key_pair_on_slot(&self, slot_id: u64, key_id: &str) -> Result<()> {
        self.lib.destroy_key_pair_on_slot(slot_id, key_id).map_err(crypto11_err)
    }

    fn find_key_pair_on_slot(
        &self,
        slot_id: u64,
        key_id: &str,
        label: &str,
    ) -> Result<Arc<dyn Signer>> {
        let key = self.lib.find_key_pair(key_id, label, Some(slot_id)).map_err(crypto11_err)?;
        Ok(Arc::new(Pkcs11Signer { key, id: key_id.to_string(), label: label.to_string() }))
    }

    fn key_info(&self, slot_id: u64, key_id: &str, include_public: bool) -> Result<KeyInfo> {
        let info = self.lib.key_info(slot_id, key_id, include_public).map_err(crypto11_err)?;
        Ok(key_info_from_crypto11(info))
    }
}

impl Provider for Pkcs11Provider {
    fn manufacturer(&self) -> &str {
        self.lib.manufacturer()
    }

    fn model(&self) -> &str {
        self.lib.model()
    }

    fn as_key_manager(&self) -> Option<&dyn KeyManager> {
        Some(self)
    }
}

/// PKCS#11-backed [`Signer`] (any compatible HSM via `trusty-crypto11`).
///
/// Separate from the software `trusty_cryptoprov_inmem::SoftwareKey` types —
/// the two never share a concrete type.
///
/// `id`/`label` are captured at construction time (from
/// [`trusty_crypto11::keys::GeneratedKey`] on generation, or from the lookup
/// arguments on `get_key`/`find_key_pair_on_slot`) rather than looked up
/// on demand — the PKCS#11 equivalent of storing id/label inline on a
/// software key handle.
#[derive(Debug, Clone)]
pub struct Pkcs11Signer {
    key: trusty_crypto11::PrivateKey,
    id: String,
    label: String,
}

impl Signer for Pkcs11Signer {
    fn sign_rsa(&self, digest: &[u8], scheme: &RsaSignScheme) -> Result<Vec<u8>> {
        match &self.key {
            trusty_crypto11::PrivateKey::Rsa(k) => {
                k.sign(digest, &rsa_scheme_to_crypto11(scheme)).map_err(crypto11_err)
            }
            trusty_crypto11::PrivateKey::Ecdsa(_) => Err(Error::UnsupportedKeyType),
        }
    }

    fn sign_ecdsa(&self, digest: &[u8]) -> Result<Vec<u8>> {
        match &self.key {
            trusty_crypto11::PrivateKey::Ecdsa(k) => k.sign(digest).map_err(crypto11_err),
            trusty_crypto11::PrivateKey::Rsa(_) => Err(Error::UnsupportedKeyType),
        }
    }

    fn key_id(&self) -> Option<&str> {
        if self.id.is_empty() { None } else { Some(&self.id) }
    }

    fn label(&self) -> Option<&str> {
        if self.label.is_empty() { None } else { Some(&self.label) }
    }
}

/// Convert a `trusty_crypto11` error into this crate's [`Error::Provider`].
///
/// `cryptoprov-core` doesn't depend on `trusty_crypto11`, so its `Error`
/// can't have a `#[from]` variant for it; this crate (the only one that
/// depends on both) converts at the boundary instead.
fn crypto11_err(e: trusty_crypto11::Error) -> Error {
    Error::Provider(e.to_string())
}

fn key_purpose_to_crypto11(purpose: KeyPurpose) -> trusty_crypto11::KeyPurpose {
    match purpose {
        KeyPurpose::Undefined => trusty_crypto11::KeyPurpose::Undefined,
        KeyPurpose::Signing => trusty_crypto11::KeyPurpose::Signing,
        KeyPurpose::Encryption => trusty_crypto11::KeyPurpose::Encryption,
    }
}

fn named_curve_to_crypto11(curve: NamedCurve) -> trusty_crypto11::NamedCurve {
    match curve {
        NamedCurve::P224 => trusty_crypto11::NamedCurve::P224,
        NamedCurve::P256 => trusty_crypto11::NamedCurve::P256,
        NamedCurve::P384 => trusty_crypto11::NamedCurve::P384,
        NamedCurve::P521 => trusty_crypto11::NamedCurve::P521,
    }
}

fn digest_algorithm_to_crypto11(hash: DigestAlgorithm) -> trusty_crypto11::DigestAlgorithm {
    match hash {
        DigestAlgorithm::Sha1 => trusty_crypto11::DigestAlgorithm::Sha1,
        DigestAlgorithm::Sha224 => trusty_crypto11::DigestAlgorithm::Sha224,
        DigestAlgorithm::Sha256 => trusty_crypto11::DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384 => trusty_crypto11::DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512 => trusty_crypto11::DigestAlgorithm::Sha512,
    }
}

fn pss_salt_len_to_crypto11(salt_len: PssSaltLen) -> trusty_crypto11::PssSaltLen {
    match salt_len {
        PssSaltLen::EqualsHash => trusty_crypto11::PssSaltLen::EqualsHash,
        PssSaltLen::Explicit(n) => trusty_crypto11::PssSaltLen::Explicit(n),
    }
}

fn rsa_scheme_to_crypto11(scheme: &RsaSignScheme) -> trusty_crypto11::RsaSignScheme {
    match scheme {
        RsaSignScheme::Pkcs1v15 { hash } => {
            trusty_crypto11::RsaSignScheme::Pkcs1v15 { hash: digest_algorithm_to_crypto11(*hash) }
        }
        RsaSignScheme::Pss { hash, salt_len } => trusty_crypto11::RsaSignScheme::Pss {
            hash: digest_algorithm_to_crypto11(*hash),
            salt_len: pss_salt_len_to_crypto11(*salt_len),
        },
    }
}

fn token_info_from_crypto11(t: trusty_crypto11::TokenInfo) -> TokenInfo {
    TokenInfo {
        slot_id: t.slot_id,
        description: t.description,
        label: t.label,
        manufacturer: t.manufacturer,
        model: t.model,
        serial: t.serial,
    }
}

fn key_info_from_crypto11(k: trusty_crypto11::KeyInfo) -> KeyInfo {
    KeyInfo {
        id: k.id,
        label: k.label,
        key_type: k.key_type,
        class: k.class,
        current_version_id: String::new(),
        creation_time: None,
        public_key: k.public_key,
        meta: Default::default(),
    }
}

/// A [`ProviderLoader`] that builds a [`Pkcs11Provider`] from token config.
///
/// Works with any PKCS#11-compatible HSM. Register with
/// [`trusty_cryptoprov_core::ProviderRegistry`] under kind `"pkcs11"`.
#[must_use]
pub fn loader() -> ProviderLoader {
    Arc::new(|cfg: &dyn TokenConfig| Ok(Arc::new(Pkcs11Provider::load(cfg)?) as Arc<dyn Provider>))
}

/// Convert [`trusty_cryptoprov_core::FileTokenConfig`] to crypto11 owned
/// config (helper for tests).
#[must_use]
pub fn file_config_to_owned(cfg: &trusty_cryptoprov_core::FileTokenConfig) -> OwnedTokenConfig {
    Pkcs11Provider::to_owned_token_config(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusty_cryptoprov_core::FileTokenConfig;

    #[test]
    fn config_conversion_maps_fields() {
        let cfg = FileTokenConfig {
            kind: "pkcs11".into(),
            manufacturer: "SoftHSM".into(),
            model: "SoftHSM v2".into(),
            path: "/usr/lib/softhsm/libsofthsm2.so".into(),
            token_serial: "123".into(),
            token_label: "token".into(),
            pin: "1234".into(),
            attributes: "a=b".into(),
        };
        let owned = file_config_to_owned(&cfg);
        assert_eq!(owned.manufacturer, "SoftHSM");
        assert_eq!(owned.model, "SoftHSM v2");
        assert_eq!(owned.path, "/usr/lib/softhsm/libsofthsm2.so");
        assert_eq!(owned.token_serial, "123");
        assert_eq!(owned.token_label, "token");
        assert_eq!(owned.attributes, "a=b");
        use secrecy::ExposeSecret;
        assert_eq!(owned.pin.expose_secret(), "1234");
    }
}
