//! Minimal in-memory crypto provider (`Manufacturer: "inmem"`).

use crate::keys::{EcdsaSoftwareKey, SoftwareEcdsaKey, SoftwareKey, SoftwareRsaKey};
use pem::{EncodeConfig, LineEnding, encode_config};
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::rand_core::OsRng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::trace;
use trusty_cryptoprov_core::{
    Error, KeyGenerator, KeyPurpose, NamedCurve, Provider, ProviderLoader, Result, Signer,
    TokenConfig,
};
use uuid::Uuid;

/// Provider manufacturer / default model name.
pub const PROVIDER_NAME: &str = "inmem";

struct StoredKey {
    key: SoftwareKey,
}

/// In-memory provider for exportable RSA/ECDSA keys (not a
/// [`KeyManager`](trusty_cryptoprov_core::KeyManager)).
pub struct InmemProvider {
    keys: Mutex<HashMap<String, StoredKey>>,
    manufacturer: String,
    model: String,
}

impl InmemProvider {
    /// Create a provider with default manufacturer/model `"inmem"`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
            manufacturer: PROVIDER_NAME.to_string(),
            model: PROVIDER_NAME.to_string(),
        }
    }

    /// Create from token config (model may be empty).
    #[must_use]
    pub fn from_config(cfg: &dyn TokenConfig) -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
            manufacturer: if cfg.manufacturer().is_empty() {
                PROVIDER_NAME.to_string()
            } else {
                cfg.manufacturer().to_string()
            },
            model: cfg.model().to_string(),
        }
    }

    fn next_id() -> String {
        Uuid::new_v4().to_string()
    }

    fn default_label() -> String {
        // Uses hex of a GUID when label empty.
        Uuid::new_v4().simple().to_string()
    }

    fn store(&self, id: String, key: SoftwareKey) {
        trace!(id = %id, "register inmem key");
        let mut map = trusty_cryptoprov_core::sync::lock(&self.keys);
        map.insert(id, StoredKey { key });
    }
}

impl Default for InmemProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyGenerator for InmemProvider {
    fn generate_rsa_key(
        &self,
        label: &str,
        bits: usize,
        _purpose: KeyPurpose,
    ) -> Result<Arc<dyn Signer>> {
        let key = RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|e| Error::Config(format!("unable to generate key, bit size: {bits}: {e}")))?;
        let label = if label.is_empty() { Self::default_label() } else { label.to_string() };
        let id = Self::next_id();
        let software =
            SoftwareKey::Rsa(SoftwareRsaKey { key, id: id.clone(), label: label.clone() });
        self.store(id, software.clone());
        Ok(Arc::new(software))
    }

    fn generate_ecdsa_key(&self, label: &str, curve: NamedCurve) -> Result<Arc<dyn Signer>> {
        // `Generate::generate` uses the OS CSPRNG (p256/p384/p521 enable `getrandom`).
        use p256::elliptic_curve::Generate as _;
        let ecdsa = match curve {
            NamedCurve::P224 => {
                return Err(Error::UnsupportedCurve(
                    "P-224 is not supported by the inmem provider (use PKCS#11)".into(),
                ));
            }
            NamedCurve::P256 => EcdsaSoftwareKey::P256(p256::ecdsa::SigningKey::generate()),
            NamedCurve::P384 => {
                use p384::elliptic_curve::Generate as _;
                EcdsaSoftwareKey::P384(p384::ecdsa::SigningKey::generate())
            }
            NamedCurve::P521 => {
                use p521::elliptic_curve::Generate as _;
                EcdsaSoftwareKey::P521(p521::ecdsa::SigningKey::generate())
            }
        };
        let label = if label.is_empty() { Self::default_label() } else { label.to_string() };
        let id = Self::next_id();
        let software = SoftwareKey::Ecdsa(SoftwareEcdsaKey {
            key: ecdsa,
            id: id.clone(),
            label: label.clone(),
        });
        self.store(id, software.clone());
        Ok(Arc::new(software))
    }

    fn export_key(&self, key_id: &str) -> Result<(String, Vec<u8>)> {
        let map = trusty_cryptoprov_core::sync::lock(&self.keys);
        let stored = map.get(key_id).ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;
        let pem_bytes = match &stored.key {
            SoftwareKey::Rsa(k) => {
                let der = k
                    .key
                    .to_pkcs1_der()
                    .map_err(|e| Error::Config(format!("export RSA key: {e}")))?;
                encode_config(
                    &pem::Pem::new("RSA PRIVATE KEY", der.as_bytes()),
                    EncodeConfig::new().set_line_ending(LineEnding::LF),
                )
                .into_bytes()
            }
            SoftwareKey::Ecdsa(k) => {
                macro_rules! sec1_der {
                    ($mod:ident, $sk:expr) => {{
                        let secret = $mod::SecretKey::from($sk);
                        secret
                            .to_sec1_der()
                            .map_err(|e| Error::Config(format!("export EC key: {e}")))?
                            .to_vec()
                    }};
                }
                let der = match &k.key {
                    EcdsaSoftwareKey::P256(sk) => sec1_der!(p256, sk),
                    EcdsaSoftwareKey::P384(sk) => sec1_der!(p384, sk),
                    EcdsaSoftwareKey::P521(sk) => sec1_der!(p521, sk),
                };
                encode_config(
                    &pem::Pem::new("EC PRIVATE KEY", der),
                    EncodeConfig::new().set_line_ending(LineEnding::LF),
                )
                .into_bytes()
            }
        };
        Ok((String::new(), pem_bytes))
    }

    fn get_key(&self, key_id: &str) -> Result<Arc<dyn Signer>> {
        let map = trusty_cryptoprov_core::sync::lock(&self.keys);
        map.get(key_id)
            .map(|s| Arc::new(s.key.clone()) as Arc<dyn Signer>)
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))
    }
}

impl Provider for InmemProvider {
    fn manufacturer(&self) -> &str {
        &self.manufacturer
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn as_key_manager(&self) -> Option<&dyn trusty_cryptoprov_core::KeyManager> {
        None
    }
}

/// A [`ProviderLoader`] that builds an [`InmemProvider`] from token config.
///
/// Register with [`trusty_cryptoprov_core::ProviderRegistry`] under kind
/// `"inmem"` (see [`PROVIDER_NAME`]).
#[must_use]
pub fn loader() -> ProviderLoader {
    Arc::new(|cfg: &dyn TokenConfig| {
        Ok(Arc::new(InmemProvider::from_config(cfg)) as Arc<dyn Provider>)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_get_export_rsa_ecdsa() {
        let p = InmemProvider::new();
        assert_eq!(p.manufacturer(), "inmem");
        assert!(p.as_key_manager().is_none());

        let rsa = p.generate_rsa_key("rsa-label", 2048, KeyPurpose::Signing).unwrap();
        assert_eq!(rsa.label(), Some("rsa-label"));
        let id = rsa.key_id().unwrap().to_string();
        let got = p.get_key(&id).unwrap();
        assert_eq!(got.label(), Some("rsa-label"));
        let (uri, pem) = p.export_key(&id).unwrap();
        assert!(uri.is_empty());
        assert!(String::from_utf8_lossy(&pem).contains("PRIVATE KEY"));

        let ec = p.generate_ecdsa_key("ec-label", NamedCurve::P256).unwrap();
        assert_eq!(ec.label(), Some("ec-label"));
        let (_uri, pem) = p.export_key(ec.key_id().unwrap()).unwrap();
        assert!(String::from_utf8_lossy(&pem).contains("EC PRIVATE KEY"));

        let err = p.generate_ecdsa_key("x", NamedCurve::P224).unwrap_err();
        assert!(matches!(err, Error::UnsupportedCurve(_)));
    }

    #[test]
    fn from_config_uses_manufacturer_and_model() {
        let cfg =
            trusty_cryptoprov_core::FileTokenConfig { model: "v1".into(), ..Default::default() };
        let p = InmemProvider::from_config(&cfg);
        assert_eq!(p.manufacturer(), "inmem");
        assert_eq!(p.model(), "v1");
    }
}
