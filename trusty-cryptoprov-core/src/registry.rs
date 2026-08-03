//! Instance-owned provider registry.
//!
//! A [`ProviderRegistry`] is built explicitly by an application's composition
//! root and registers exactly the provider crates that application links in —
//! no global mutable state and no self-registration at link time.
//!
//! Callers of `trusty-cryptoprov` use this type directly; there is no
//! facade-level convenience wrapper.

use crate::config::TokenConfig;
use crate::error::{Error, Result};
use crate::provider::{Crypto, Provider};
use std::collections::HashMap;
use std::sync::Arc;

/// Builds a [`Provider`] from token config.
///
/// Takes `&dyn TokenConfig` rather than a concrete config type so a
/// third-party crate can register its own [`Provider`] without depending on
/// any particular config-loading implementation.
pub type ProviderLoader = Arc<dyn Fn(&dyn TokenConfig) -> Result<Arc<dyn Provider>> + Send + Sync>;

/// A registry of provider loaders, keyed by provider `kind` (`"pkcs11"`,
/// `"inmem"`, `"aws-kms"`, ...) — a routing key for config, distinct from
/// [`Provider::manufacturer`], which is the token/backend's own reported
/// identity.
#[derive(Default)]
pub struct ProviderRegistry {
    loaders: HashMap<String, ProviderLoader>,
}

impl ProviderRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self { loaders: HashMap::new() }
    }

    /// Register a provider loader under `kind`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyRegistered`] if `kind` is already present.
    pub fn register(&mut self, kind: impl Into<String>, loader: ProviderLoader) -> Result<()> {
        let kind = kind.into();
        if self.loaders.contains_key(&kind) {
            return Err(Error::AlreadyRegistered { kind });
        }
        self.loaders.insert(kind, loader);
        Ok(())
    }

    /// Whether `kind` has a registered loader.
    #[must_use]
    pub fn is_registered(&self, kind: &str) -> bool {
        self.loaders.contains_key(kind)
    }

    /// Load a single provider from a config path (`""` / `"inmem"` shortcuts OK).
    ///
    /// The config's `kind` field (see [`TokenConfig::kind`]) selects which
    /// registered loader builds the provider.
    ///
    /// # Errors
    ///
    /// Config load failures, or [`Error::ProviderNotRegistered`], or loader errors.
    pub fn load_provider(&self, config_location: &str) -> Result<Arc<dyn Provider>> {
        let tc = crate::config::load_token_config(config_location)?;
        let kind = tc.kind().to_string();
        let loader = self
            .loaders
            .get(&kind)
            .ok_or_else(|| Error::ProviderNotRegistered { kind: kind.clone() })?;
        loader(&tc)
    }

    /// Load a [`Crypto`] set: default config plus optional additional configs.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::load_provider`] failures.
    pub fn load(&self, default_config: &str, extra_configs: &[&str]) -> Result<Crypto> {
        let p = self.load_provider(default_config)?;
        let mut c = Crypto::new(Arc::clone(&p), vec![]);
        c.add(p);
        for config_location in extra_configs {
            let p = self.load_provider(config_location)?;
            c.add(p);
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeProvider;

    fn stub_loader() -> ProviderLoader {
        Arc::new(|_cfg| {
            Ok(Arc::new(FakeProvider { manufacturer: "stub", model: "m" }) as Arc<dyn Provider>)
        })
    }

    #[test]
    fn register_duplicate_kind_fails() {
        let mut registry = ProviderRegistry::new();
        registry.register("stub", stub_loader()).unwrap();
        assert!(registry.is_registered("stub"));
        assert!(matches!(
            registry.register("stub", stub_loader()).unwrap_err(),
            Error::AlreadyRegistered { .. }
        ));
    }

    #[test]
    fn independent_registries_do_not_share_state() {
        // Unlike the old global static, two registries in the same process
        // (or the same test binary running in parallel) never see each
        // other's registrations.
        let mut a = ProviderRegistry::new();
        let mut b = ProviderRegistry::new();
        a.register("stub", stub_loader()).unwrap();
        assert!(a.is_registered("stub"));
        assert!(!b.is_registered("stub"));
        b.register("stub", stub_loader()).unwrap();
    }

    #[test]
    fn load_provider_unregistered_kind_errors() {
        let registry = ProviderRegistry::new();
        // `Arc<dyn Provider>` isn't `Debug`, so match instead of `unwrap_err`.
        match registry.load_provider("") {
            Err(Error::ProviderNotRegistered { .. }) => {}
            other => panic!("expected ProviderNotRegistered, got {}", other.is_ok()),
        }
    }

    #[test]
    fn load_builds_default_and_extra_providers() {
        let mut registry = ProviderRegistry::new();
        registry.register("inmem", stub_loader()).unwrap();
        let crypto = registry.load("", &["inmem"]).unwrap();
        assert_eq!(crypto.default_provider().manufacturer(), "stub");
    }
}
