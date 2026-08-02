//! SoftHSM-friendly loader and enumeration APIs (no cryptoprov dependency).

use crate::Pkcs11Lib;
use crate::common::{key_type_name, object_class_name};
use crate::config::{OwnedTokenConfig, init};
use crate::error::{Error, Result};
use crate::pem::encode_public_key_pem;
use crate::types::SlotTokenInfo;
use crate::util::{extract_id_label_type_class, find_key_handle, slot_from_id};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use tracing::warn;

/// Token information for enumeration (mirrors Go cryptoprov.TokenInfo shape).
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl From<&SlotTokenInfo> for TokenInfo {
    fn from(s: &SlotTokenInfo) -> Self {
        Self {
            slot_id: s.id,
            description: s.description.clone(),
            label: s.label.clone(),
            manufacturer: s.manufacturer.clone(),
            model: s.model.clone(),
            serial: s.serial.clone(),
        }
    }
}

/// Key information for enumeration (mirrors Go cryptoprov.KeyInfo shape).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyInfo {
    /// CKA_ID.
    pub id: String,
    /// CKA_LABEL.
    pub label: String,
    /// Key type name (e.g. `"RSA"`).
    pub key_type: String,
    /// Object class name (e.g. `"Private key"`).
    pub class: String,
    /// Optional PEM-encoded public key.
    pub public_key: String,
}

/// Load a PKCS#11 provider from token config (Go `LoadProvider` without registry).
///
/// # Errors
///
/// See [`Pkcs11Lib::init`].
pub fn load_provider(cfg: impl Into<OwnedTokenConfig>) -> Result<Pkcs11Lib> {
    init(cfg)
}

impl Pkcs11Lib {
    /// Manufacturer from config.
    #[must_use]
    pub fn manufacturer(&self) -> &str {
        &self.inner.config.manufacturer
    }

    /// Model from config.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.inner.config.model
    }

    /// Enumerate tokens; if `current_slot_only`, return only the selected slot.
    ///
    /// # Errors
    ///
    /// See [`Pkcs11Lib::tokens_info`] (not called when `current_slot_only`
    /// is `true`).
    pub fn enum_tokens(&self, current_slot_only: bool) -> Result<Vec<TokenInfo>> {
        if current_slot_only {
            return Ok(vec![TokenInfo::from(&self.inner.slot)]);
        }
        let list = self.tokens_info()?;
        Ok(list.iter().map(TokenInfo::from).collect())
    }

    /// Enumerate private keys on `slot_id`, optionally filtering label prefix.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the library has been closed, or
    /// [`Error::Pkcs11`] if `slot_id` is invalid or the search fails.
    pub fn enum_keys(&self, slot_id: u64, prefix: &str) -> Result<Vec<KeyInfo>> {
        let ctx = self.ctx()?;
        let slot = slot_from_id(slot_id)?;
        let session = ctx
            .open_ro_session(slot)
            .map_err(|e| Error::from(e).context(format!("OpenSession on slot {slot_id}")))?;

        let keys = session
            .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])
            .map_err(Error::from)?;

        let mut res = Vec::with_capacity(keys.len());
        for obj in keys {
            let attrs = session
                .get_attributes(
                    obj,
                    &[
                        AttributeType::Id,
                        AttributeType::Label,
                        AttributeType::KeyType,
                        AttributeType::Class,
                    ],
                )
                .map_err(|e| Error::from(e).context("GetAttributeValue on key"))?;
            let (id, label, kt, class) = extract_id_label_type_class(attrs);
            let key_label = String::from_utf8_lossy(&label).into_owned();
            if !prefix.is_empty() && !key_label.starts_with(prefix) {
                continue;
            }
            res.push(KeyInfo {
                id: String::from_utf8_lossy(&id).into_owned(),
                label: key_label,
                key_type: kt.map(key_type_name).unwrap_or("").to_string(),
                class: class.map(object_class_name).unwrap_or("").to_string(),
                public_key: String::new(),
            });
        }
        Ok(res)
    }

    /// Retrieve key info; optionally include PEM public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the library has been closed,
    /// [`Error::KeyNotFound`] if `key_id` does not match a private key, or
    /// [`Error::Pkcs11`] for other PKCS#11 failures. When `include_public`
    /// is `true`, also propagates PEM-encoding failures from the exported
    /// public key.
    pub fn key_info(&self, slot_id: u64, key_id: &str, include_public: bool) -> Result<KeyInfo> {
        let ctx = self.ctx()?;
        let slot = slot_from_id(slot_id)?;
        let session = ctx
            .open_rw_session(slot)
            .map_err(|e| Error::from(e).context(format!("OpenSession on slot {slot_id}")))?;

        let priv_handle = match find_key_handle(
            &session,
            Some(key_id),
            None,
            Some(ObjectClass::PRIVATE_KEY),
            None,
        ) {
            Ok(h) => h,
            Err(e) => {
                warn!(reason = "not_found", r#type = %ObjectClass::PRIVATE_KEY, err = %e);
                return Err(e);
            }
        };

        let attrs = session
            .get_attributes(
                priv_handle,
                &[
                    AttributeType::Id,
                    AttributeType::Label,
                    AttributeType::KeyType,
                    AttributeType::Class,
                ],
            )
            .map_err(|e| Error::from(e).context("GetAttributeValue on key"))?;

        let (id, label, kt, class) = extract_id_label_type_class(attrs);
        let key_id_str = String::from_utf8_lossy(&id).into_owned();
        let mut public_key = String::new();
        if include_public {
            public_key = self.get_public_key_pem(slot_id, &key_id_str).map_err(|e| {
                e.context(format!(
                    "reason='failed on GetPublicKey', slotID={slot_id}, keyID={key_id_str:?}"
                ))
            })?;
        }

        Ok(KeyInfo {
            id: key_id_str,
            label: String::from_utf8_lossy(&label).into_owned(),
            key_type: kt.map(key_type_name).unwrap_or("").to_string(),
            class: class.map(object_class_name).unwrap_or("").to_string(),
            public_key,
        })
    }

    fn get_public_key_pem(&self, slot_id: u64, key_id: &str) -> Result<String> {
        let priv_key = self
            .find_key_pair(key_id, "", Some(slot_id))
            .map_err(|e| e.context(format!("unable to find key: slot={slot_id}, key={key_id}")))?;
        let pub_key = crate::keys::convert_to_public(&priv_key)?;
        encode_public_key_pem(&pub_key)
    }
}
