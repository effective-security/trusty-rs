//! GCP KMS provider stub.
//!
//! No `google-cloud-kms` dependency yet. Every operation returns
//! [`Error::NotImplemented`] so application and config plumbing for this
//! provider can be written and tested ahead of a real integration.

use std::sync::Arc;
use trusty_cryptoprov_core::{
    Error, KeyGenerator, KeyPurpose, NamedCurve, Provider, ProviderLoader, Result, Signer,
    TokenConfig,
};

/// Placeholder for GCP KMS-specific config (project, location, key ring,
/// key name, ...).
///
/// Not wired into [`TokenConfig`] yet — `TokenConfig`'s free-form
/// `attributes()` bag is the escape hatch until a real implementation
/// clarifies whether `TokenConfig` needs a per-provider extension point.
/// The type exists so provider-specific fields are visible in the API
/// before they are filled in.
#[derive(Debug, Clone, Default)]
pub struct GcpKmsConfig {
    /// GCP project ID.
    pub project: String,
    /// Full KMS key resource name.
    pub key_name: String,
}

/// GCP KMS signing provider. Every [`KeyGenerator`] method currently returns
/// [`Error::NotImplemented`].
#[derive(Debug, Clone, Default)]
pub struct GcpKmsProvider;

impl GcpKmsProvider {
    /// Build a stub provider. Config is accepted (and ignored) so the
    /// constructor matches real providers; there is nothing to configure yet.
    #[must_use]
    pub fn from_config(_cfg: &dyn TokenConfig) -> Self {
        Self
    }
}

impl KeyGenerator for GcpKmsProvider {
    fn generate_rsa_key(
        &self,
        _label: &str,
        _bits: usize,
        _purpose: KeyPurpose,
    ) -> Result<Arc<dyn Signer>> {
        Err(Error::NotImplemented("gcp-kms: generate_rsa_key"))
    }

    fn generate_ecdsa_key(&self, _label: &str, _curve: NamedCurve) -> Result<Arc<dyn Signer>> {
        Err(Error::NotImplemented("gcp-kms: generate_ecdsa_key"))
    }

    fn export_key(&self, _key_id: &str) -> Result<(String, Vec<u8>)> {
        Err(Error::NotImplemented("gcp-kms: export_key"))
    }

    fn get_key(&self, _key_id: &str) -> Result<Arc<dyn Signer>> {
        Err(Error::NotImplemented("gcp-kms: get_key"))
    }
}

impl Provider for GcpKmsProvider {
    fn manufacturer(&self) -> &str {
        "gcp-kms"
    }

    fn model(&self) -> &str {
        ""
    }
}

/// A [`ProviderLoader`] that builds a [`GcpKmsProvider`].
///
/// Ready to register with a [`trusty_cryptoprov_core::ProviderRegistry`]
/// under `kind = "gcp-kms"`.
#[must_use]
pub fn loader() -> ProviderLoader {
    Arc::new(|cfg: &dyn TokenConfig| {
        Ok(Arc::new(GcpKmsProvider::from_config(cfg)) as Arc<dyn Provider>)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusty_cryptoprov_core::FileTokenConfig;

    #[test]
    fn every_key_operation_is_not_implemented() {
        let p = GcpKmsProvider;
        assert!(matches!(
            p.generate_rsa_key("k", 2048, KeyPurpose::Signing),
            Err(Error::NotImplemented(_))
        ));
        assert!(matches!(
            p.generate_ecdsa_key("k", NamedCurve::P256),
            Err(Error::NotImplemented(_))
        ));
        assert!(matches!(p.export_key("id"), Err(Error::NotImplemented(_))));
        assert!(matches!(p.get_key("id"), Err(Error::NotImplemented(_))));
    }

    #[test]
    fn loader_builds_provider() {
        let cfg = FileTokenConfig::default();
        let built = loader();
        let p = built(&cfg).unwrap();
        assert_eq!(p.manufacturer(), "gcp-kms");
    }
}
