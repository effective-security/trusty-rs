//! AWS KMS provider (`Manufacturer` / `Model` come from token config).
//!
//! Ported from `go-source/cryptoprov/awskmscrypto`. The AWS SDK is
//! async/tokio-based while [`trusty_cryptoprov_core::Provider`] is
//! synchronous, so [`AwsKmsProvider`] owns a small internal [`Runtime`] and
//! bridges every call with [`Runtime::block_on`].
//!
//! Deliberate deviations from the Go implementation:
//! - `generate_rsa_key`/`generate_ecdsa_key`/`get_key` don't call
//!   `GetPublicKey`: the [`Signer`] trait splits `sign_rsa`/`sign_ecdsa` into
//!   separate methods rather than dispatching on the public key's type, so
//!   the key kind only needs to come from `KeySpec` (already known at
//!   generation time, or read from `DescribeKey` for lookups).
//! - `key_info(..., include_public: true)` PEM-wraps the DER bytes
//!   `GetPublicKey` returns directly (they're already SPKI DER) instead of
//!   parsing and re-serializing them.
//! - `enum_keys`'s `prefix` parameter is accepted for trait parity but,
//!   matching the Go provider, is not applied as a filter.

use crate::signer::{AwsKeyKind, AwsKmsSigner};
use aws_sdk_kms::types::{KeySpec, KeyUsageType};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::runtime::Runtime;
use tracing::{debug, info, warn};
use trusty_cryptoprov_core::{
    Error, KeyGenerator, KeyInfo, KeyManager, KeyPurpose, NamedCurve, Provider, ProviderLoader,
    Result, Signer, TokenConfig, TokenInfo,
};

/// AWS KMS signing provider.
pub struct AwsKmsProvider {
    client: aws_sdk_kms::Client,
    rt: Arc<Runtime>,
    manufacturer: String,
    model: String,
}

impl AwsKmsProvider {
    /// Build a provider from token config, loading AWS credentials/region
    /// via the standard SDK default chain, optionally overridden by the
    /// `Region`/`Endpoint` `key=value` entries in
    /// [`TokenConfig::attributes`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the async runtime or AWS config fails to
    /// initialize.
    pub fn from_config(cfg: &dyn TokenConfig) -> Result<Self> {
        let attrs = parse_kms_attributes(cfg.attributes());
        let region = attrs.get("Region").cloned().unwrap_or_default();
        let endpoint = attrs.get("Endpoint").cloned().unwrap_or_default();

        let rt = Runtime::new()
            .map_err(|e| Error::Config(format!("failed to start async runtime: {e}")))?;
        let client = rt.block_on(build_client(&region, &endpoint))?;

        Ok(Self {
            client,
            rt: Arc::new(rt),
            manufacturer: cfg.manufacturer().to_string(),
            model: cfg.model().to_string(),
        })
    }

    fn signer(&self, key_id: String, label: String, kind: AwsKeyKind) -> Arc<dyn Signer> {
        Arc::new(AwsKmsSigner::new(key_id, label, kind, self.client.clone(), Arc::clone(&self.rt)))
    }

    async fn create_key(
        &self,
        key_spec: KeySpec,
        usage: KeyUsageType,
        label: &str,
    ) -> Result<(String, String)> {
        let resp = self
            .client
            .create_key()
            .key_spec(key_spec)
            .key_usage(usage)
            .description(label)
            .send()
            .await
            .map_err(|e| {
                Error::Provider(format!("failed to create key with label {label:?}: {e}"))
            })?;

        let metadata = resp.key_metadata.ok_or_else(|| {
            Error::Provider("CreateKey response missing key metadata".to_string())
        })?;
        let key_id = metadata.key_id;
        info!(id = %key_id, arn = %metadata.arn.unwrap_or_default(), label = %label, "created AWS KMS key");

        if !label.is_empty()
            && let Err(e) = self.create_alias(&key_id, label).await
        {
            warn!(reason = "CreateAlias", id = %key_id, error = %e, "failed to create alias");
        }

        Ok((key_id, label.to_string()))
    }

    async fn create_alias(&self, key_id: &str, label: &str) -> Result<String> {
        let alias = alias_from_label(label);
        if alias == "alias/" {
            return Err(Error::Provider("alias is empty".to_string()));
        }
        self.client.create_alias().alias_name(&alias).target_key_id(key_id).send().await.map_err(
            |e| Error::Provider(format!("failed to create alias, id={key_id}, alias={alias}: {e}")),
        )?;
        info!(id = %key_id, label = %label, alias = %alias, "created AWS KMS alias");
        Ok(alias)
    }
}

async fn build_client(region: &str, endpoint: &str) -> Result<aws_sdk_kms::Client> {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if !region.is_empty() {
        loader = loader.region(aws_sdk_kms::config::Region::new(region.to_string()));
    }
    if let (Ok(id), Ok(secret)) =
        (std::env::var("AWS_ACCESS_KEY_ID"), std::env::var("AWS_SECRET_ACCESS_KEY"))
    {
        let token = std::env::var("AWS_SESSION_TOKEN").ok();
        loader = loader.credentials_provider(aws_sdk_kms::config::Credentials::new(
            id,
            secret,
            token,
            None,
            "trusty-cryptoprov-aws-kms-env",
        ));
    }
    let sdk_config = loader.load().await;

    let mut kms_builder = aws_sdk_kms::config::Builder::from(&sdk_config);
    if !endpoint.is_empty() {
        kms_builder = kms_builder.endpoint_url(endpoint);
    }
    Ok(aws_sdk_kms::Client::from_conf(kms_builder.build()))
}

/// Parse comma-separated `key=value` attributes (e.g. `"Region=us-east-1"`).
///
/// Unlike the Go original, a malformed entry (missing `=`) is skipped rather
/// than causing an index-out-of-range panic.
fn parse_kms_attributes(attributes: &str) -> HashMap<String, String> {
    attributes
        .split(',')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Build a KMS-valid alias name (`"alias/<sanitized-label>"`) from `label`.
/// KMS aliases only allow `[a-zA-Z0-9:/_-]`; any other character is replaced
/// with `_`. The reserved `"alias/aws/"` prefix is avoided.
fn alias_from_label(label: &str) -> String {
    let sanitized: String =
        label
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | ':') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
    let name = sanitized.strip_prefix("aws/").unwrap_or(&sanitized);
    format!("alias/{name}")
}

fn key_meta(metadata: &aws_sdk_kms::types::KeyMetadata) -> HashMap<String, String> {
    HashMap::from([
        ("description".to_string(), metadata.description.clone().unwrap_or_default()),
        (
            "usage".to_string(),
            metadata.key_usage.as_ref().map(ToString::to_string).unwrap_or_default(),
        ),
        (
            "origin".to_string(),
            metadata.origin.as_ref().map(ToString::to_string).unwrap_or_default(),
        ),
        (
            "state".to_string(),
            metadata.key_state.as_ref().map(ToString::to_string).unwrap_or_default(),
        ),
        ("enabled".to_string(), metadata.enabled.to_string()),
        ("algo".to_string(), format!("{:?}", metadata.signing_algorithms())),
    ])
}

impl KeyGenerator for AwsKmsProvider {
    fn generate_rsa_key(
        &self,
        label: &str,
        bits: usize,
        purpose: KeyPurpose,
    ) -> Result<Arc<dyn Signer>> {
        let key_spec = match bits {
            2048 => KeySpec::Rsa2048,
            3072 => KeySpec::Rsa3072,
            4096 => KeySpec::Rsa4096,
            _ => return Err(Error::Config(format!("unsupported RSA key size: {bits}"))),
        };
        let usage = match purpose {
            KeyPurpose::Encryption => KeyUsageType::EncryptDecrypt,
            _ => KeyUsageType::SignVerify,
        };
        let (key_id, label) = self.rt.block_on(self.create_key(key_spec, usage, label))?;
        Ok(self.signer(key_id, label, AwsKeyKind::Rsa))
    }

    fn generate_ecdsa_key(&self, label: &str, curve: NamedCurve) -> Result<Arc<dyn Signer>> {
        let key_spec = match curve {
            NamedCurve::P256 => KeySpec::EccNistP256,
            NamedCurve::P384 => KeySpec::EccNistP384,
            NamedCurve::P521 => KeySpec::EccNistP521,
            NamedCurve::P224 => {
                return Err(Error::UnsupportedCurve("P-224 is not supported by AWS KMS".into()));
            }
        };
        let (key_id, label) =
            self.rt.block_on(self.create_key(key_spec, KeyUsageType::SignVerify, label))?;
        Ok(self.signer(key_id, label, AwsKeyKind::Ecdsa))
    }

    fn export_key(&self, key_id: &str) -> Result<(String, Vec<u8>)> {
        let metadata = self.rt.block_on(describe_key(&self.client, key_id))?;
        let uri = format!(
            "pkcs11:manufacturer={};model={};id={};serial={};type=private",
            self.manufacturer,
            self.model,
            key_id,
            metadata.arn.unwrap_or_default(),
        );
        Ok((uri.clone(), uri.into_bytes()))
    }

    fn get_key(&self, key_id: &str) -> Result<Arc<dyn Signer>> {
        debug!(api = "get_key", key_id = %key_id);
        let metadata = self.rt.block_on(describe_key(&self.client, key_id))?;
        let kind = key_kind(metadata.key_spec.as_ref())?;
        let label = metadata.description.unwrap_or_default();
        Ok(self.signer(key_id.to_string(), label, kind))
    }
}

impl KeyManager for AwsKmsProvider {
    fn current_slot_id(&self) -> u64 {
        0
    }

    fn enum_tokens(&self, _current_slot_only: bool) -> Result<Vec<TokenInfo>> {
        Ok(vec![TokenInfo {
            slot_id: 0,
            manufacturer: self.manufacturer.clone(),
            model: self.model.clone(),
            ..Default::default()
        }])
    }

    fn enum_keys(&self, slot_id: u64, prefix: &str) -> Result<Vec<KeyInfo>> {
        debug!(slot_id, prefix, "enum_keys");
        self.rt.block_on(async {
            let mut list = Vec::new();
            let mut marker: Option<String> = None;
            loop {
                let mut req = self.client.list_keys().limit(100);
                if let Some(m) = &marker {
                    req = req.marker(m);
                }
                let resp = req.send().await.map_err(|e| Error::Provider(e.to_string()))?;

                for k in resp.keys() {
                    let Some(key_id) = &k.key_id else { continue };
                    let metadata = match self.client.describe_key().key_id(key_id).send().await {
                        Ok(r) => match r.key_metadata {
                            Some(m) => m,
                            None => continue,
                        },
                        Err(e) => {
                            warn!(reason = "DescribeKey", id = %key_id, error = %e, "failed to describe key");
                            continue;
                        }
                    };
                    if matches!(metadata.key_state, Some(aws_sdk_kms::types::KeyState::PendingDeletion))
                    {
                        continue;
                    }
                    if metadata.key_usage != Some(KeyUsageType::SignVerify) {
                        continue;
                    }
                    list.push(KeyInfo {
                        id: key_id.clone(),
                        creation_time: metadata.creation_date.and_then(system_time_from_aws),
                        meta: key_meta(&metadata),
                        ..Default::default()
                    });
                }

                if !resp.truncated {
                    break;
                }
                marker = resp.next_marker;
            }
            Ok(list)
        })
    }

    fn destroy_key_pair_on_slot(&self, _slot_id: u64, key_id: &str) -> Result<()> {
        self.rt.block_on(async {
            let resp = self
                .client
                .schedule_key_deletion()
                .key_id(key_id)
                .send()
                .await
                .map_err(|e| Error::Provider(format!("failed to schedule key deletion: {key_id}: {e}")))?;
            info!(id = %key_id, deletion_date = ?resp.deletion_date, "scheduled AWS KMS key deletion");
            Ok(())
        })
    }

    fn find_key_pair_on_slot(
        &self,
        _slot_id: u64,
        _key_id: &str,
        _label: &str,
    ) -> Result<Arc<dyn Signer>> {
        Err(Error::NotImplemented("aws-kms: find_key_pair_on_slot is not supported by AWS KMS"))
    }

    fn key_info(&self, _slot_id: u64, key_id: &str, include_public: bool) -> Result<KeyInfo> {
        self.rt.block_on(async {
            let metadata = describe_key(&self.client, key_id).await?;
            let public_key = if include_public {
                let resp =
                    self.client.get_public_key().key_id(key_id).send().await.map_err(|e| {
                        Error::Provider(format!("failed to get public key, id={key_id}: {e}"))
                    })?;
                let der = resp
                    .public_key
                    .map(aws_sdk_kms::primitives::Blob::into_inner)
                    .unwrap_or_default();
                pem::encode_config(
                    &pem::Pem::new("PUBLIC KEY", der),
                    pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
                )
            } else {
                String::new()
            };

            Ok(KeyInfo {
                id: key_id.to_string(),
                public_key,
                creation_time: metadata.creation_date.and_then(system_time_from_aws),
                meta: key_meta(&metadata),
                ..Default::default()
            })
        })
    }
}

async fn describe_key(
    client: &aws_sdk_kms::Client,
    key_id: &str,
) -> Result<aws_sdk_kms::types::KeyMetadata> {
    let resp = client
        .describe_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|e| Error::Provider(format!("failed to describe key, id={key_id}: {e}")))?;
    resp.key_metadata.ok_or_else(|| Error::KeyNotFound(key_id.to_string()))
}

fn key_kind(key_spec: Option<&KeySpec>) -> Result<AwsKeyKind> {
    match key_spec {
        Some(KeySpec::Rsa2048 | KeySpec::Rsa3072 | KeySpec::Rsa4096) => Ok(AwsKeyKind::Rsa),
        Some(KeySpec::EccNistP256 | KeySpec::EccNistP384 | KeySpec::EccNistP521) => {
            Ok(AwsKeyKind::Ecdsa)
        }
        other => Err(Error::UnsupportedKeyType).inspect_err(|_| {
            warn!(key_spec = ?other, "unsupported AWS KMS key spec for signing");
        }),
    }
}

fn system_time_from_aws(t: aws_sdk_kms::primitives::DateTime) -> Option<SystemTime> {
    t.try_into().ok()
}

impl Provider for AwsKmsProvider {
    fn manufacturer(&self) -> &str {
        &self.manufacturer
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn as_key_manager(&self) -> Option<&dyn KeyManager> {
        Some(self)
    }
}

/// A [`ProviderLoader`] that builds an [`AwsKmsProvider`].
///
/// Register with [`trusty_cryptoprov_core::ProviderRegistry`] under kind
/// `"aws-kms"`.
#[must_use]
pub fn loader() -> ProviderLoader {
    Arc::new(|cfg: &dyn TokenConfig| {
        Ok(Arc::new(AwsKmsProvider::from_config(cfg)?) as Arc<dyn Provider>)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kms_attributes_ok() {
        let attrs = parse_kms_attributes("Region=us-east-1, Endpoint=http://localhost:4566");
        assert_eq!(attrs.get("Region").unwrap(), "us-east-1");
        assert_eq!(attrs.get("Endpoint").unwrap(), "http://localhost:4566");
    }

    #[test]
    fn parse_kms_attributes_skips_malformed() {
        let attrs = parse_kms_attributes("Region=us-east-1,garbage,");
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs.get("Region").unwrap(), "us-east-1");
    }

    #[test]
    fn parse_kms_attributes_empty() {
        assert!(parse_kms_attributes("").is_empty());
    }

    #[test]
    fn alias_from_label_sanitizes() {
        assert_eq!(alias_from_label("my key!"), "alias/my_key_");
        assert_eq!(alias_from_label("aws/reserved"), "alias/reserved");
        assert_eq!(alias_from_label(""), "alias/");
    }

    #[test]
    fn key_kind_maps_rsa_and_ecdsa() {
        assert_eq!(key_kind(Some(&KeySpec::Rsa2048)).unwrap(), AwsKeyKind::Rsa);
        assert_eq!(key_kind(Some(&KeySpec::EccNistP256)).unwrap(), AwsKeyKind::Ecdsa);
        assert!(matches!(
            key_kind(Some(&KeySpec::SymmetricDefault)),
            Err(Error::UnsupportedKeyType)
        ));
        assert!(matches!(key_kind(None), Err(Error::UnsupportedKeyType)));
    }
}
