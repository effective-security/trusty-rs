//! Token enumeration and key destruction helpers.

use crate::Pkcs11Lib;
use crate::error::{Error, Result};
use crate::types::SlotTokenInfo;
use cryptoki::context::Pkcs11;
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::slot::Slot;
use std::convert::TryFrom;
use tracing::{debug, error, warn};

/// Convert a raw slot id to a [`Slot`] (Go `crypto11` slots are always in range).
pub(crate) fn slot_from_id(id: u64) -> Result<Slot> {
    Slot::try_from(id).map_err(Error::from)
}

/// Pull `CKA_ID`/`CKA_LABEL`/`CKA_KEY_TYPE`/`CKA_CLASS` out of a PKCS#11
/// attribute list (the shape returned by `get_attributes` when requesting
/// those four types; callers that only requested a subset simply get
/// `None`/empty back for the rest).
pub(crate) fn extract_id_label_type_class(
    attrs: Vec<Attribute>,
) -> (Vec<u8>, Vec<u8>, Option<KeyType>, Option<ObjectClass>) {
    let mut id = Vec::new();
    let mut label = Vec::new();
    let mut key_type = None;
    let mut class = None;
    for a in attrs {
        match a {
            Attribute::Id(v) => id = v,
            Attribute::Label(v) => label = v,
            Attribute::KeyType(v) => key_type = Some(v),
            Attribute::Class(v) => class = Some(v),
            _ => {}
        }
    }
    (id, label, key_type, class)
}

/// Enumerate tokens with a raw [`Pkcs11`] context (used during init).
pub(crate) fn tokens_info_with_ctx(ctx: &Pkcs11) -> Result<Vec<SlotTokenInfo>> {
    let slots = ctx.get_slots_with_token().map_err(Error::from)?;
    debug!(slots = slots.len());
    let mut list = Vec::new();
    for slot in slots {
        let si = ctx
            .get_slot_info(slot)
            .map_err(|e| Error::from(e).context(format!("GetSlotInfo: {}", slot.id())))?;
        match ctx.get_token_info(slot) {
            Ok(ti) => {
                if !ti.serial_number().is_empty() || !ti.label().is_empty() {
                    list.push(SlotTokenInfo {
                        id: slot.id(),
                        description: si.slot_description().to_string(),
                        label: ti.label().to_string(),
                        manufacturer: ti.manufacturer_id().trim().to_string(),
                        model: ti.model().trim().to_string(),
                        serial: ti.serial_number().to_string(),
                        login_required: ti.login_required(),
                    });
                }
            }
            Err(e) => {
                error!(
                    reason = "GetTokenInfo",
                    slot_id = slot.id(),
                    manufacturer_id = si.manufacturer_id(),
                    slot_description = si.slot_description(),
                    err = %e
                );
            }
        }
    }
    Ok(list)
}

impl Pkcs11Lib {
    /// Current slot ID selected at init.
    #[must_use]
    pub fn current_slot_id(&self) -> u64 {
        self.inner.slot.id
    }

    /// List tokens visible through this library context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the library has been closed, or
    /// [`Error::Pkcs11`] if slot/token enumeration fails.
    pub fn tokens_info(&self) -> Result<Vec<SlotTokenInfo>> {
        let ctx = self.ctx()?;
        tokens_info_with_ctx(&ctx)
    }

    /// Destroy public and private key objects with the given CKA_ID on `slot_id`.
    ///
    /// Best-effort: if no object of a given class matches `key_id`, that
    /// half is skipped (logged, not an error); only a mid-destroy PKCS#11
    /// failure is returned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the library has been closed, or
    /// [`Error::Pkcs11`] if `slot_id` is invalid, the session cannot be
    /// opened, or `C_DestroyObject` fails on a found object.
    pub fn destroy_key_pair_on_slot(&self, slot_id: u64, key_id: &str) -> Result<()> {
        let ctx = self.ctx()?;
        let slot = slot_from_id(slot_id)?;
        let session = ctx
            .open_rw_session(slot)
            .map_err(|e| Error::from(e).context(format!("OpenSession on slot {slot_id}")))?;

        let priv_handle =
            find_key_handle(&session, Some(key_id), None, Some(ObjectClass::PRIVATE_KEY), None);
        let pub_handle =
            find_key_handle(&session, Some(key_id), None, Some(ObjectClass::PUBLIC_KEY), None);

        if let Ok(h) = priv_handle {
            session.destroy_object(h).map_err(Error::from)?;
        } else if let Err(e) = &priv_handle {
            warn!(reason = "not_found", r#type = %ObjectClass::PRIVATE_KEY, err = %e);
        }

        if let Ok(h) = pub_handle {
            session.destroy_object(h).map_err(Error::from)?;
        } else if let Err(e) = &pub_handle {
            warn!(reason = "not_found", r#type = %ObjectClass::PUBLIC_KEY, err = %e);
        }

        Ok(())
    }
}

pub(crate) fn find_key_handle(
    session: &cryptoki::session::Session,
    key_id: Option<&str>,
    label: Option<&str>,
    class: Option<ObjectClass>,
    key_type: Option<KeyType>,
) -> Result<ObjectHandle> {
    let mut template = Vec::new();
    if let Some(c) = class {
        template.push(Attribute::Class(c));
    }
    if let Some(kt) = key_type {
        template.push(Attribute::KeyType(kt));
    }
    if let Some(id) = key_id.filter(|s| !s.is_empty()) {
        template.push(Attribute::Id(id.as_bytes().to_vec()));
    }
    if let Some(l) = label.filter(|s| !s.is_empty()) {
        template.push(Attribute::Label(l.as_bytes().to_vec()));
    }
    let handles = session.find_objects(&template).map_err(Error::from)?;
    handles.into_iter().next().ok_or(Error::KeyNotFound)
}
