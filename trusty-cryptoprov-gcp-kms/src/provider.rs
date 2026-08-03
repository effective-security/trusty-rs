//! GCP Cloud KMS provider (`Manufacturer` / `Model` come from token config).
//!
//! Ported from `go-source/cryptoprov/gcpkmscrypto`. `google-cloud-kms-v1` is
//! async/tokio-based while [`trusty_cryptoprov_core::Provider`] is
//! synchronous, so [`GcpKmsProvider`] owns a small internal [`Runtime`] and
//! bridges every call with [`Runtime::block_on`].
//!
//! Deliberate deviations from the Go implementation:
//! - Key generation doesn't fetch the public key: the [`Signer`] trait
//!   splits `sign_rsa`/`sign_ecdsa` into separate methods rather than
//!   dispatching on the public key's type, so the key kind only needs the
//!   crypto key version's `algorithm` (see [`crate::signer::GcpKeyKind`]).
//!   Instead of polling `GetPublicKey` until the version leaves
//!   `PENDING_GENERATION` (the Go provider's proxy for "is it ready to
//!   sign"), this polls `GetCryptoKeyVersion`'s `state` directly.
//! - `key_info(..., include_public: true)` uses `GetPublicKey`'s `pem` field
//!   as-is (GCP already returns PEM, unlike AWS).
//! - `enum_keys`'s `prefix` parameter is accepted for trait parity but,
//!   matching the Go provider, is not applied as a filter.

use crate::signer::{GcpKeyKind, GcpKmsSigner};
use google_cloud_gax::paginator::ItemPaginator as _;
use google_cloud_kms_v1::client::KeyManagementService;
use google_cloud_kms_v1::model::crypto_key::CryptoKeyPurpose;
use google_cloud_kms_v1::model::crypto_key_version::{
    CryptoKeyVersionAlgorithm, CryptoKeyVersionState,
};
use google_cloud_kms_v1::model::{
    CreateCryptoKeyRequest, CryptoKey, CryptoKeyVersionTemplate, ProtectionLevel,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::runtime::Runtime;
use tracing::{debug, info, warn};
use trusty_cryptoprov_core::{
    DigestAlgorithm, Error, KeyGenerator, KeyInfo, KeyManager, KeyPurpose, NamedCurve, Provider,
    ProviderLoader, Result, Signer, TokenConfig, TokenInfo,
};

/// GCP Cloud KMS signing provider.
pub struct GcpKmsProvider {
    client: KeyManagementService,
    rt: Arc<Runtime>,
    keyring: String,
    manufacturer: String,
    model: String,
}

impl GcpKmsProvider {
    /// Build a provider from token config, using Application Default
    /// Credentials, optionally overridden by the `Endpoint`/`Keyring`
    /// `key=value` entries in [`TokenConfig::attributes`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the async runtime or KMS client fails to
    /// initialize.
    pub fn from_config(cfg: &dyn TokenConfig) -> Result<Self> {
        let attrs = parse_kms_attributes(cfg.attributes());
        let endpoint = attrs.get("Endpoint").cloned().unwrap_or_default();
        let keyring = attrs.get("Keyring").cloned().unwrap_or_default();

        let rt = Runtime::new()
            .map_err(|e| Error::Config(format!("failed to start async runtime: {e}")))?;
        let client = rt.block_on(build_client(&endpoint))?;

        Ok(Self {
            client,
            rt: Arc::new(rt),
            keyring,
            manufacturer: cfg.manufacturer().to_string(),
            model: cfg.model().to_string(),
        })
    }

    fn key_name(&self, key_id: &str) -> String {
        format!("{}/cryptoKeys/{key_id}", self.keyring)
    }

    fn key_version_name(&self, key_id: &str) -> String {
        format!("{}/cryptoKeyVersions/1", self.key_name(key_id))
    }

    fn signer(&self, key_id: String, label: String, kind: GcpKeyKind) -> Arc<dyn Signer> {
        let version_name = self.key_version_name(&key_id);
        Arc::new(GcpKmsSigner::new(
            key_id,
            label,
            kind,
            version_name,
            self.client.clone(),
            Arc::clone(&self.rt),
        ))
    }

    async fn generate_key(
        &self,
        algorithm: CryptoKeyVersionAlgorithm,
        purpose: KeyPurpose,
        label: &str,
        kind: GcpKeyKind,
    ) -> Result<Arc<dyn Signer>> {
        let crypto_key_purpose = match purpose {
            KeyPurpose::Encryption => CryptoKeyPurpose::AsymmetricDecrypt,
            _ => CryptoKeyPurpose::AsymmetricSign,
        };
        let (label, key_id) = key_label_and_id(label);

        let crypto_key = CryptoKey::new()
            .set_purpose(crypto_key_purpose)
            .set_version_template(
                CryptoKeyVersionTemplate::new()
                    .set_algorithm(algorithm)
                    .set_protection_level(ProtectionLevel::Hsm),
            )
            .set_labels([("label".to_string(), label.clone())]);

        let req = CreateCryptoKeyRequest::new()
            .set_parent(&self.keyring)
            .set_crypto_key_id(&key_id)
            .set_crypto_key(crypto_key);

        let resp = self
            .client
            .create_crypto_key()
            .with_request(req)
            .send()
            .await
            .map_err(|e| Error::Provider(format!("failed to create key: {e}")))?;
        info!(key_id = %resp.name, label = %label, "created GCP KMS key");

        let version_name = format!("{}/cryptoKeyVersions/1", resp.name);
        self.wait_until_enabled(&version_name).await?;

        Ok(self.signer(key_id, label, kind))
    }

    /// Poll `GetCryptoKeyVersion` until `state` leaves `PENDING_GENERATION`
    /// (up to 60s), matching the Go provider's wait for key material to
    /// become available before returning a usable signer.
    async fn wait_until_enabled(&self, version_name: &str) -> Result<()> {
        for _ in 0..60 {
            let version =
                self.client.get_crypto_key_version().set_name(version_name).send().await.map_err(
                    |e| Error::Provider(format!("failed to get crypto key version: {e}")),
                )?;
            match version.state {
                CryptoKeyVersionState::Enabled => return Ok(()),
                CryptoKeyVersionState::PendingGeneration => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                other => {
                    return Err(Error::Provider(format!(
                        "crypto key version {version_name} entered unexpected state: {other:?}"
                    )));
                }
            }
        }
        Err(Error::Provider(format!("timed out waiting for {version_name} to become enabled")))
    }
}

async fn build_client(endpoint: &str) -> Result<KeyManagementService> {
    let mut builder = KeyManagementService::builder();
    if !endpoint.is_empty() {
        builder = builder.with_endpoint(endpoint);
    }
    builder.build().await.map_err(|e| Error::Config(format!("failed to create KMS client: {e}")))
}

/// Parse comma-separated `key=value` attributes (e.g. `"Keyring=projects/.../keyRings/..."`).
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

/// Derive a KMS-valid `crypto_key_id` from a label: lowercase, strip a
/// trailing `*`, append 4 lowercase hex characters for uniqueness, and cap
/// at 63 characters (the `CryptoKeyId` length limit).
fn key_label_and_id(val: &str) -> (String, String) {
    let label = val.trim_end_matches('*').to_lowercase();
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let mut id = format!("{label}{}", &suffix[..4]);
    id.truncate(63);
    (label, id)
}

fn key_kind_from_algorithm(algorithm: &CryptoKeyVersionAlgorithm) -> Result<GcpKeyKind> {
    match algorithm {
        CryptoKeyVersionAlgorithm::RsaSignPkcs12048Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPkcs13072Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPkcs14096Sha256 => {
            Ok(GcpKeyKind::RsaPkcs1(DigestAlgorithm::Sha256))
        }
        CryptoKeyVersionAlgorithm::RsaSignPkcs14096Sha512 => {
            Ok(GcpKeyKind::RsaPkcs1(DigestAlgorithm::Sha512))
        }
        CryptoKeyVersionAlgorithm::RsaSignPss2048Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPss3072Sha256
        | CryptoKeyVersionAlgorithm::RsaSignPss4096Sha256 => {
            Ok(GcpKeyKind::RsaPss(DigestAlgorithm::Sha256))
        }
        CryptoKeyVersionAlgorithm::RsaSignPss4096Sha512 => {
            Ok(GcpKeyKind::RsaPss(DigestAlgorithm::Sha512))
        }
        CryptoKeyVersionAlgorithm::EcSignP256Sha256 => Ok(GcpKeyKind::Ecdsa),
        CryptoKeyVersionAlgorithm::EcSignP384Sha384 => Ok(GcpKeyKind::Ecdsa),
        other => {
            warn!(algorithm = ?other, "unsupported GCP KMS algorithm for signing");
            Err(Error::UnsupportedKeyType)
        }
    }
}

fn key_label_info(key: &CryptoKey) -> String {
    let mut parts = vec![format!(
        "protection={}",
        key.version_template
            .as_ref()
            .map(|t| format!("{:?}", t.protection_level))
            .unwrap_or_default()
    )];
    for (k, v) in &key.labels {
        parts.push(format!("{k}={v}"));
    }
    parts.join(",")
}

fn key_info(key: &CryptoKey) -> KeyInfo {
    let id = key.name.rsplit('/').next().unwrap_or(&key.name).to_string();
    let mut meta = HashMap::from([
        (
            "protection".to_string(),
            key.version_template
                .as_ref()
                .map(|t| format!("{:?}", t.protection_level))
                .unwrap_or_default(),
        ),
        (
            "algo".to_string(),
            key.version_template.as_ref().map(|t| format!("{:?}", t.algorithm)).unwrap_or_default(),
        ),
        ("purpose".to_string(), format!("{:?}", key.purpose)),
    ]);
    if let Some(primary) = &key.primary {
        meta.insert("state".to_string(), format!("{:?}", primary.state));
    }
    KeyInfo {
        id,
        label: key_label_info(key),
        current_version_id: "1".to_string(),
        creation_time: key.create_time.and_then(|t| SystemTime::try_from(t).ok()),
        meta,
        ..Default::default()
    }
}

impl KeyGenerator for GcpKmsProvider {
    fn generate_rsa_key(
        &self,
        label: &str,
        bits: usize,
        purpose: KeyPurpose,
    ) -> Result<Arc<dyn Signer>> {
        let (algorithm, hash) = match bits {
            2048 => (CryptoKeyVersionAlgorithm::RsaSignPkcs12048Sha256, DigestAlgorithm::Sha256),
            3072 => (CryptoKeyVersionAlgorithm::RsaSignPkcs13072Sha256, DigestAlgorithm::Sha256),
            4096 => (CryptoKeyVersionAlgorithm::RsaSignPkcs14096Sha512, DigestAlgorithm::Sha512),
            _ => return Err(Error::Config(format!("unsupported RSA key size: {bits}"))),
        };
        self.rt.block_on(self.generate_key(algorithm, purpose, label, GcpKeyKind::RsaPkcs1(hash)))
    }

    fn generate_ecdsa_key(&self, label: &str, curve: NamedCurve) -> Result<Arc<dyn Signer>> {
        let algorithm = match curve {
            NamedCurve::P256 => CryptoKeyVersionAlgorithm::EcSignP256Sha256,
            NamedCurve::P384 => CryptoKeyVersionAlgorithm::EcSignP384Sha384,
            NamedCurve::P224 | NamedCurve::P521 => {
                return Err(Error::UnsupportedCurve(format!(
                    "{} is not supported by GCP KMS asymmetric signing",
                    curve.name()
                )));
            }
        };
        self.rt.block_on(self.generate_key(
            algorithm,
            KeyPurpose::Signing,
            label,
            GcpKeyKind::Ecdsa,
        ))
    }

    fn export_key(&self, key_id: &str) -> Result<(String, Vec<u8>)> {
        let uri = format!(
            "pkcs11:manufacturer={};model={};id={key_id};serial=1;type=private",
            self.manufacturer, self.model,
        );
        Ok((uri.clone(), uri.into_bytes()))
    }

    fn get_key(&self, key_id: &str) -> Result<Arc<dyn Signer>> {
        debug!(api = "get_key", key_id = %key_id);
        self.rt.block_on(async {
            let name = self.key_name(key_id);
            let key = self
                .client
                .get_crypto_key()
                .set_name(&name)
                .send()
                .await
                .map_err(|e| Error::Provider(format!("failed to get key: {e}")))?;
            let version = self
                .client
                .get_crypto_key_version()
                .set_name(self.key_version_name(key_id))
                .send()
                .await
                .map_err(|e| Error::Provider(format!("failed to get crypto key version: {e}")))?;
            let kind = key_kind_from_algorithm(&version.algorithm)?;
            let label = key.labels.get("label").cloned().unwrap_or_default();
            Ok(self.signer(key_id.to_string(), label, kind))
        })
    }
}

impl KeyManager for GcpKmsProvider {
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
            let mut pager = self.client.list_crypto_keys().set_parent(&self.keyring).by_item();
            while let Some(key) =
                pager.next().await.transpose().map_err(|e| Error::Provider(e.to_string()))?
            {
                if let Some(primary) = &key.primary
                    && primary.state != CryptoKeyVersionState::Enabled
                {
                    debug!(key = %key.name, state = ?primary.state, "skip key");
                    continue;
                }
                list.push(key_info(&key));
            }
            Ok(list)
        })
    }

    fn destroy_key_pair_on_slot(&self, slot_id: u64, key_id: &str) -> Result<()> {
        info!(slot_id, key_id, "destroy_key_pair_on_slot");
        self.rt.block_on(async {
            let resp = self
                .client
                .destroy_crypto_key_version()
                .set_name(self.key_version_name(key_id))
                .send()
                .await
                .map_err(|e| Error::Provider(format!("failed to schedule key deletion: {key_id}: {e}")))?;
            info!(id = %key_id, destroy_time = ?resp.destroy_time, "scheduled GCP KMS key deletion");
            Ok(())
        })
    }

    fn find_key_pair_on_slot(
        &self,
        _slot_id: u64,
        _key_id: &str,
        _label: &str,
    ) -> Result<Arc<dyn Signer>> {
        Err(Error::NotImplemented("gcp-kms: find_key_pair_on_slot is not supported by GCP KMS"))
    }

    fn key_info(&self, _slot_id: u64, key_id: &str, include_public: bool) -> Result<KeyInfo> {
        self.rt.block_on(async {
            let name = self.key_name(key_id);
            let key = self.client.get_crypto_key().set_name(&name).send().await.map_err(|e| {
                Error::Provider(format!("failed to describe key, id={key_id}: {e}"))
            })?;
            let mut info = key_info(&key);
            if include_public {
                let resp = self
                    .client
                    .get_public_key()
                    .set_name(self.key_version_name(key_id))
                    .send()
                    .await
                    .map_err(|e| {
                        Error::Provider(format!("failed to get public key, id={key_id}: {e}"))
                    })?;
                info.public_key = resp.pem;
            }
            Ok(info)
        })
    }
}

impl Provider for GcpKmsProvider {
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

/// A [`ProviderLoader`] that builds a [`GcpKmsProvider`].
///
/// Register with [`trusty_cryptoprov_core::ProviderRegistry`] under kind
/// `"gcp-kms"`.
#[must_use]
pub fn loader() -> ProviderLoader {
    Arc::new(|cfg: &dyn TokenConfig| {
        Ok(Arc::new(GcpKmsProvider::from_config(cfg)?) as Arc<dyn Provider>)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kms_attributes_ok() {
        let attrs =
            parse_kms_attributes("Keyring=projects/p/locations/l/keyRings/r, Endpoint=host:443");
        assert_eq!(attrs.get("Keyring").unwrap(), "projects/p/locations/l/keyRings/r");
        assert_eq!(attrs.get("Endpoint").unwrap(), "host:443");
    }

    #[test]
    fn parse_kms_attributes_skips_malformed() {
        let attrs = parse_kms_attributes("Keyring=r,garbage,");
        assert_eq!(attrs.len(), 1);
    }

    #[test]
    fn key_label_and_id_strips_trailing_star_and_lowercases() {
        let (label, id) = key_label_and_id("MyKey*");
        assert_eq!(label, "mykey");
        assert!(id.starts_with("mykey"));
        assert_eq!(id.len(), "mykey".len() + 4);
    }

    #[test]
    fn key_label_and_id_caps_length() {
        let long = "a".repeat(100);
        let (_, id) = key_label_and_id(&long);
        assert_eq!(id.len(), 63);
    }

    #[test]
    fn key_kind_from_algorithm_mapping() {
        assert_eq!(
            key_kind_from_algorithm(&CryptoKeyVersionAlgorithm::RsaSignPkcs12048Sha256).unwrap(),
            GcpKeyKind::RsaPkcs1(DigestAlgorithm::Sha256)
        );
        assert_eq!(
            key_kind_from_algorithm(&CryptoKeyVersionAlgorithm::RsaSignPss4096Sha512).unwrap(),
            GcpKeyKind::RsaPss(DigestAlgorithm::Sha512)
        );
        assert_eq!(
            key_kind_from_algorithm(&CryptoKeyVersionAlgorithm::EcSignP256Sha256).unwrap(),
            GcpKeyKind::Ecdsa
        );
        assert!(matches!(
            key_kind_from_algorithm(&CryptoKeyVersionAlgorithm::HmacSha256),
            Err(Error::UnsupportedKeyType)
        ));
    }
}
