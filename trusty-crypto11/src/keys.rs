//! Find / list / identify / export key APIs.

use crate::Pkcs11Lib;
use crate::common::format_pkcs11_uri;
use crate::ecdsa::{EcdsaPrivateKey, ecdsa_to_public, export_ecdsa_public_key};
use crate::error::{Error, Result};
use crate::rsa::{RsaPrivateKey, export_rsa_public_key, rsa_to_public};
use crate::types::{Pkcs11Object, PublicKey};
use crate::util::{extract_id_label_type_class, find_key_handle, slot_from_id};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use std::sync::Arc;

/// Asymmetric private key hosted on the token (no DSA).
#[derive(Debug, Clone)]
pub enum PrivateKey {
    /// RSA private key.
    Rsa(RsaPrivateKey),
    /// ECDSA private key.
    Ecdsa(EcdsaPrivateKey),
}

impl PrivateKey {
    /// Underlying PKCS#11 object.
    #[must_use]
    pub fn object(&self) -> Pkcs11Object {
        match self {
            Self::Rsa(k) => k.object(),
            Self::Ecdsa(k) => k.object(),
        }
    }

    /// Cached public half.
    #[must_use]
    pub fn public(&self) -> PublicKey {
        match self {
            Self::Rsa(k) => rsa_to_public(k.public()),
            Self::Ecdsa(k) => ecdsa_to_public(k.public()),
        }
    }
}

/// Key identifier accessors (Go `KeyIdentifier`).
pub trait KeyIdentifier {
    /// CKA_ID as UTF-8 (lossy) string.
    fn key_id(&self) -> &str;
    /// CKA_LABEL as UTF-8 (lossy) string.
    fn label(&self) -> &str;
}

/// `CKA_ID`/`CKA_LABEL` pair identifying a PKCS#11 object (see
/// [`Pkcs11Lib::identify`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyIdentity {
    /// CKA_ID as UTF-8 (lossy) string.
    pub id: String,
    /// CKA_LABEL as UTF-8 (lossy) string.
    pub label: String,
}

/// Key returned from generate helpers, carrying id/label.
#[derive(Debug, Clone)]
pub struct GeneratedKey {
    /// Key ID string.
    pub id: String,
    /// Key label string.
    pub label: String,
    /// Private key handle.
    pub key: PrivateKey,
}

impl KeyIdentifier for GeneratedKey {
    fn key_id(&self) -> &str {
        &self.id
    }
    fn label(&self) -> &str {
        &self.label
    }
}

impl Pkcs11Lib {
    /// Read CKA_ID and CKA_LABEL for an object.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the library has been closed, or
    /// [`Error::Pkcs11`] if `object`'s slot is invalid or the attributes
    /// cannot be read.
    pub fn identify(&self, object: &Pkcs11Object) -> Result<KeyIdentity> {
        let slot = slot_from_id(object.slot)?;
        self.with_session(slot, |session| {
            let attrs = session
                .get_attributes(object.handle, &[AttributeType::Id, AttributeType::Label])
                .map_err(Error::from)?;
            let (id, label, _, _) = extract_id_label_type_class(attrs);
            Ok(KeyIdentity {
                id: String::from_utf8_lossy(&id).into_owned(),
                label: String::from_utf8_lossy(&label).into_owned(),
            })
        })
    }

    /// Identify a private key (GeneratedKey shortcut or PKCS#11 object).
    ///
    /// # Errors
    ///
    /// See [`Self::identify`].
    pub fn identify_key(&self, key: &PrivateKey) -> Result<KeyIdentity> {
        self.identify(&key.object())
    }

    /// Find asymmetric key pair by id/label, optionally on a specific slot
    /// (defaults to the token's current slot).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the library has been closed,
    /// [`Error::KeyNotFound`] if no key matches `key_id`/`label`,
    /// [`Error::UnsupportedKeyType`] if the found key is neither RSA nor
    /// EC, or [`Error::Pkcs11`] for other PKCS#11 failures.
    pub fn find_key_pair(
        &self,
        key_id: &str,
        label: &str,
        slot_id: Option<u64>,
    ) -> Result<PrivateKey> {
        let slot_id = slot_id.unwrap_or_else(|| self.current_slot_id());
        self.inner.pools.setup(slot_id);
        let slot = slot_from_id(slot_id)?;
        self.with_session(slot, |session| {
            self.find_key_pair_on_session(session, slot_id, key_id, label)
        })
    }

    /// Find asymmetric key pair using an existing session.
    ///
    /// # Errors
    ///
    /// See [`Self::find_key_pair`] (this is its session-level implementation).
    pub fn find_key_pair_on_session(
        &self,
        session: &Session,
        slot_id: u64,
        key_id: &str,
        label: &str,
    ) -> Result<PrivateKey> {
        let id = if key_id.is_empty() { None } else { Some(key_id) };
        let lbl = if label.is_empty() { None } else { Some(label) };
        let priv_handle = find_key_handle(session, id, lbl, Some(ObjectClass::PRIVATE_KEY), None)?;
        let key_type = read_key_type(session, priv_handle)?;
        let pub_handle =
            find_key_handle(session, id, lbl, Some(ObjectClass::PUBLIC_KEY), Some(key_type))?;
        match key_type {
            KeyType::RSA => {
                let pub_key = export_rsa_public_key(session, pub_handle)
                    .map_err(|e| e.context("exportRSAPublicKey"))?;
                Ok(PrivateKey::Rsa(RsaPrivateKey {
                    lib: Arc::clone(&self.inner),
                    object: Pkcs11Object { handle: priv_handle, slot: slot_id },
                    public_key: pub_key,
                }))
            }
            KeyType::EC => {
                let pub_key = export_ecdsa_public_key(session, pub_handle)
                    .map_err(|e| e.context("exportECDSAPublicKey"))?;
                Ok(PrivateKey::Ecdsa(EcdsaPrivateKey {
                    lib: Arc::clone(&self.inner),
                    object: Pkcs11Object { handle: priv_handle, slot: slot_id },
                    public_key: pub_key,
                }))
            }
            _ => Err(Error::UnsupportedKeyType),
        }
    }

    /// List object handles matching class/type on the current slot (pooled session).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the library has been closed, or
    /// [`Error::Pkcs11`] if the search fails.
    pub fn list_keys(
        &self,
        class: Option<ObjectClass>,
        key_type: Option<KeyType>,
    ) -> Result<Vec<ObjectHandle>> {
        let slot = self.inner.slot.slot()?;
        self.with_session(slot, |session| list_keys_on_session(session, class, key_type))
    }

    /// Find handles by label (+ optional class/type) on the current slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the library has been closed, or
    /// [`Error::Pkcs11`] if the search fails.
    pub fn find_keys(
        &self,
        key_label: &str,
        class: Option<ObjectClass>,
        key_type: Option<KeyType>,
    ) -> Result<Vec<ObjectHandle>> {
        let slot = self.inner.slot.slot()?;
        self.with_session(slot, |session| {
            let mut template = vec![Attribute::Label(key_label.as_bytes().to_vec())];
            if let Some(c) = class {
                template.push(Attribute::Class(c));
            }
            if let Some(kt) = key_type {
                template.push(Attribute::KeyType(kt));
            }
            session.find_objects(&template).map_err(Error::from)
        })
    }

    /// Get private key by ID on the current slot.
    ///
    /// # Errors
    ///
    /// See [`Self::find_key_pair`]; errors are wrapped with the searched
    /// `key_id` as context.
    pub fn get_key(&self, key_id: &str) -> Result<PrivateKey> {
        self.find_key_pair(key_id, "", None)
            .map_err(|e| e.context(format!("unable to find key {key_id:?}")))
    }

    /// Export the PKCS#11 URI for a key ID.
    ///
    /// Private keys generated by this crate are never extractable from the
    /// token, so there is no raw key material to return alongside the URI
    /// (unlike Go `crypto11`, whose equivalent signature carried a
    /// perpetually-`nil` key-bytes result).
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if `key_id` does not match a key
    /// (see [`Self::find_key_pair`]), [`Error::Closed`] if the library has
    /// been closed, or [`Error::Pkcs11`] if token info cannot be read.
    pub fn export_key(&self, key_id: &str) -> Result<String> {
        let _ = self
            .find_key_pair(key_id, "", None)
            .map_err(|e| e.context(format!("unable to find key {key_id:?}")))?;
        let ctx = self.ctx()?;
        let slot = self.inner.slot.slot()?;
        let ti = ctx.get_token_info(slot).map_err(|e| Error::from(e).context("token info"))?;
        Ok(format_pkcs11_uri(
            &self.inner.config.manufacturer,
            &self.inner.config.model,
            ti.serial_number(),
            ti.label(),
            key_id,
        ))
    }
}

/// Convert private key to public (software or PKCS#11-backed).
pub fn convert_to_public(priv_key: &PrivateKey) -> Result<PublicKey> {
    Ok(priv_key.public())
}

fn read_key_type(session: &Session, handle: ObjectHandle) -> Result<KeyType> {
    let attrs = session.get_attributes(handle, &[AttributeType::KeyType]).map_err(Error::from)?;
    for a in attrs {
        if let Attribute::KeyType(kt) = a {
            return Ok(kt);
        }
    }
    Err(Error::UnsupportedKeyType)
}

fn list_keys_on_session(
    session: &Session,
    class: Option<ObjectClass>,
    key_type: Option<KeyType>,
) -> Result<Vec<ObjectHandle>> {
    let mut template = Vec::new();
    if let Some(c) = class {
        template.push(Attribute::Class(c));
    }
    if let Some(kt) = key_type {
        template.push(Attribute::KeyType(kt));
    }
    session.find_objects(&template).map_err(Error::from)
}
