//! AWS KMS provider stub.
//!
//! No `aws-sdk-kms` / `aws-config` dependency yet. Every operation returns
//! [`Error::NotImplemented`] so application and config plumbing for this
//! provider can be written and tested ahead of a real integration.

use std::sync::Arc;
use trusty_cryptoprov_core::{
    Error, KeyGenerator, KeyPurpose, NamedCurve, Provider, ProviderLoader, Result, Signer,
    TokenConfig,
};

/// Placeholder for AWS KMS-specific config (region, key ARN, IAM role, ...).
///
/// Not wired into [`TokenConfig`] yet — `TokenConfig`'s free-form
/// `attributes()` bag is the escape hatch until a real implementation
/// clarifies whether `TokenConfig` needs a per-provider extension point.
/// The type exists so provider-specific fields are visible in the API
/// before they are filled in.
#[derive(Debug, Clone, Default)]
pub struct AwsKmsConfig {
    /// AWS region.
    pub region: String,
    /// KMS key ID or ARN.
    pub key_id: String,
}

/// AWS KMS signing provider. Every [`KeyGenerator`] method currently returns
/// [`Error::NotImplemented`].
#[derive(Debug, Clone, Default)]
pub struct AwsKmsProvider;

impl AwsKmsProvider {
    /// Build a stub provider. Config is accepted (and ignored) so the
    /// constructor matches real providers; there is nothing to configure yet.
    #[must_use]
    pub fn from_config(_cfg: &dyn TokenConfig) -> Self {
        Self
    }
}

impl KeyGenerator for AwsKmsProvider {
    fn generate_rsa_key(
        &self,
        _label: &str,
        _bits: usize,
        _purpose: KeyPurpose,
    ) -> Result<Arc<dyn Signer>> {
        Err(Error::NotImplemented("aws-kms: generate_rsa_key"))
    }

    fn generate_ecdsa_key(&self, _label: &str, _curve: NamedCurve) -> Result<Arc<dyn Signer>> {
        Err(Error::NotImplemented("aws-kms: generate_ecdsa_key"))
    }

    fn export_key(&self, _key_id: &str) -> Result<(String, Vec<u8>)> {
        Err(Error::NotImplemented("aws-kms: export_key"))
    }

    fn get_key(&self, _key_id: &str) -> Result<Arc<dyn Signer>> {
        Err(Error::NotImplemented("aws-kms: get_key"))
    }
}

impl Provider for AwsKmsProvider {
    fn manufacturer(&self) -> &str {
        "aws-kms"
    }

    fn model(&self) -> &str {
        ""
    }
}

/// A [`ProviderLoader`] that builds an [`AwsKmsProvider`].
///
/// Ready to register with a [`trusty_cryptoprov_core::ProviderRegistry`]
/// under `kind = "aws-kms"`.
#[must_use]
pub fn loader() -> ProviderLoader {
    Arc::new(|cfg: &dyn TokenConfig| {
        Ok(Arc::new(AwsKmsProvider::from_config(cfg)) as Arc<dyn Provider>)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusty_cryptoprov_core::FileTokenConfig;

    #[test]
    fn every_key_operation_is_not_implemented() {
        let p = AwsKmsProvider;
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
        assert_eq!(p.manufacturer(), "aws-kms");
    }
}
