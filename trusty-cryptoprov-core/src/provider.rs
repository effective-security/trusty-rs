//! Provider traits and the multi-provider [`Crypto`] registry.

use crate::error::{Error, Result};
use crate::signing::{KeyPurpose, NamedCurve, Signer};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::info;

/// PKCS#11 token information.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TokenInfo {
    /// Slot ID.
    pub slot_id: u64,
    /// Slot description.
    pub description: String,
    /// Token label.
    pub label: String,
    /// Manufacturer.
    pub manufacturer: String,
    /// Model.
    pub model: String,
    /// Serial number.
    pub serial: String,
}

/// Key information.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyInfo {
    /// Key ID.
    pub id: String,
    /// Key label.
    pub label: String,
    /// Key type name (e.g. `"RSA"`).
    pub key_type: String,
    /// Object class name.
    pub class: String,
    /// Optional current version ID (KMS providers).
    pub current_version_id: String,
    /// Optional creation time.
    pub creation_time: Option<SystemTime>,
    /// Optional PEM-encoded public key.
    pub public_key: String,
    /// Optional metadata map.
    pub meta: HashMap<String, String>,
}

/// Optional key-management operations (enumeration, destroy, find).
///
/// Not a supertrait of [`Provider`] — PKCS#11 implements this; inmem does not.
pub trait KeyManager: Send + Sync {
    /// Current PKCS#11 slot ID.
    fn current_slot_id(&self) -> u64;

    /// Enumerate tokens; if `current_slot_only`, return only the selected slot.
    ///
    /// # Errors
    ///
    /// Provider-specific enumeration failures.
    fn enum_tokens(&self, current_slot_only: bool) -> Result<Vec<TokenInfo>>;

    /// Enumerate keys on `slot_id`, optionally filtering by label prefix.
    ///
    /// # Errors
    ///
    /// Provider-specific enumeration failures.
    fn enum_keys(&self, slot_id: u64, prefix: &str) -> Result<Vec<KeyInfo>>;

    /// Destroy a key pair on `slot_id`.
    ///
    /// # Errors
    ///
    /// Provider-specific destroy failures.
    fn destroy_key_pair_on_slot(&self, slot_id: u64, key_id: &str) -> Result<()>;

    /// Find a key pair on `slot_id` by id and/or label.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] or provider errors.
    fn find_key_pair_on_slot(
        &self,
        slot_id: u64,
        key_id: &str,
        label: &str,
    ) -> Result<Arc<dyn Signer>>;

    /// Retrieve key info; optionally include PEM public key.
    ///
    /// # Errors
    ///
    /// Provider-specific lookup failures.
    fn key_info(&self, slot_id: u64, key_id: &str, include_public: bool) -> Result<KeyInfo>;
}

/// Key generation and lookup operations.
pub trait KeyGenerator: Send + Sync {
    /// Generate an RSA key for the given [`KeyPurpose`].
    ///
    /// # Errors
    ///
    /// Provider-specific generation failures.
    fn generate_rsa_key(
        &self,
        label: &str,
        bits: usize,
        purpose: KeyPurpose,
    ) -> Result<Arc<dyn Signer>>;

    /// Generate an ECDSA key on `curve`.
    ///
    /// # Errors
    ///
    /// Provider-specific generation failures, or [`Error::UnsupportedCurve`].
    fn generate_ecdsa_key(&self, label: &str, curve: NamedCurve) -> Result<Arc<dyn Signer>>;

    /// Export key by ID.
    ///
    /// Returns `(uri_or_empty, optional_pem_bytes)`. PKCS#11 returns a `pkcs11:`
    /// URI and empty bytes; inmem returns `""` and PEM-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] or provider errors.
    fn export_key(&self, key_id: &str) -> Result<(String, Vec<u8>)>;

    /// Get a private key by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] or provider errors.
    fn get_key(&self, key_id: &str) -> Result<Arc<dyn Signer>>;
}

/// Crypto provider: key generation plus manufacturer/model identity.
pub trait Provider: KeyGenerator + Send + Sync {
    /// Manufacturer / backend identity (token-reported name, not the registry
    /// `kind` used for loader routing).
    fn manufacturer(&self) -> &str;

    /// Model / product identity for this provider instance.
    fn model(&self) -> &str;

    /// Optional downcast to [`KeyManager`] (PKCS#11: `Some`; inmem: `None`).
    fn as_key_manager(&self) -> Option<&dyn KeyManager> {
        None
    }
}

/// Multi-provider registry keyed by `(manufacturer, model)`.
pub struct Crypto {
    provider: Arc<dyn Provider>,
    by_manufacturer: HashMap<(String, String), Arc<dyn Provider>>,
}

impl Crypto {
    /// Create a registry with a default provider and optional additional providers.
    #[must_use]
    pub fn new(default_provider: Arc<dyn Provider>, providers: Vec<Arc<dyn Provider>>) -> Self {
        info!(
            manufacturer = %default_provider.manufacturer(),
            model = %default_provider.model(),
            "default crypto provider"
        );
        let mut c = Self { provider: default_provider, by_manufacturer: HashMap::new() };
        for p in providers {
            c.add(p);
        }
        c
    }

    /// Default crypto provider.
    #[must_use]
    pub fn default_provider(&self) -> Arc<dyn Provider> {
        Arc::clone(&self.provider)
    }

    /// Add (or replace) a provider under its exact `(manufacturer, model)` identity.
    pub fn add(&mut self, p: Arc<dyn Provider>) {
        let key = (p.manufacturer().to_string(), p.model().to_string());
        info!(manufacturer = %key.0, model = %key.1, "add crypto provider");
        self.by_manufacturer.insert(key, p);
    }

    /// Look up a provider by manufacturer and model.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProviderNotFound`] if neither the default nor the map match.
    pub fn find_provider(&self, manufacturer: &str, model: &str) -> Result<Arc<dyn Provider>> {
        if self.provider.manufacturer() == manufacturer && self.provider.model() == model {
            return Ok(Arc::clone(&self.provider));
        }
        let key = (manufacturer.to_string(), model.to_string());
        self.by_manufacturer.get(&key).cloned().ok_or_else(|| Error::ProviderNotFound {
            manufacturer: manufacturer.to_string(),
            model: model.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeProvider;

    #[test]
    fn add_same_identity_ok() {
        let p: Arc<dyn Provider> = Arc::new(FakeProvider { manufacturer: "SoftHSM", model: "v2" });
        let mut c = Crypto::new(Arc::clone(&p), vec![]);
        c.add(Arc::clone(&p));
        c.add(p);
    }

    #[test]
    fn find_provider_default_and_map() {
        let def: Arc<dyn Provider> =
            Arc::new(FakeProvider { manufacturer: "SoftHSM", model: "v2" });
        let other: Arc<dyn Provider> = Arc::new(FakeProvider { manufacturer: "inmem", model: "" });
        let mut c = Crypto::new(Arc::clone(&def), vec![]);
        c.add(Arc::clone(&other));

        assert_eq!(c.find_provider("SoftHSM", "v2").unwrap().manufacturer(), "SoftHSM");
        assert_eq!(c.find_provider("inmem", "").unwrap().manufacturer(), "inmem");
        assert!(matches!(c.find_provider("NetHSM", ""), Err(Error::ProviderNotFound { .. })));
    }

    #[test]
    fn manufacturer_and_model_with_at_sign_do_not_collide() {
        // Regression test: a string-concatenated `"{manufacturer}@{model}"` key
        // would alias these two distinct identities onto the same key
        // ("a@b" @ "c" == "a" @ "b@c"). The tuple key must keep them distinct.
        let def: Arc<dyn Provider> =
            Arc::new(FakeProvider { manufacturer: "default", model: "default" });
        let a: Arc<dyn Provider> = Arc::new(FakeProvider { manufacturer: "a@b", model: "c" });
        let b: Arc<dyn Provider> = Arc::new(FakeProvider { manufacturer: "a", model: "b@c" });
        let mut c = Crypto::new(Arc::clone(&def), vec![]);
        c.add(a);
        c.add(b);

        assert_eq!(c.find_provider("a@b", "c").unwrap().manufacturer(), "a@b");
        assert_eq!(c.find_provider("a", "b@c").unwrap().model(), "b@c");
    }
}
