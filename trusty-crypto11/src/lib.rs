#![doc = include_str!("../README.md")]

pub mod common;
pub mod config;
pub mod ecdsa;
pub mod error;
pub mod keys;
pub mod pem;
pub mod provider;
pub mod rand;
pub mod rsa;
pub mod sessions;
pub mod types;
pub mod util;

pub use common::{
    attribute_name, attribute_names, format_pkcs11_uri, key_id_from_random, key_label_from_random,
    key_type_name, key_type_names, object_class_name, object_class_names,
};
pub use config::{
    FileTokenConfig, OwnedTokenConfig, configure_from_file, init, load_token_config,
    resolve_pin_file_prefix,
};
pub use ecdsa::{EcdsaKeyPairOptions, EcdsaPrivateKey};
pub use error::{Error, Result};
pub use keys::{GeneratedKey, KeyIdentifier, KeyIdentity, PrivateKey, convert_to_public};
pub use pem::encode_public_key_pem;
pub use provider::{KeyInfo, TokenInfo, load_provider};
pub use rsa::{
    KeyPurpose, PssSaltLen, RsaDecryptScheme, RsaKeyPairOptions, RsaPrivateKey, RsaSignScheme,
};
pub use types::{
    DigestAlgorithm, EcdsaPublicKey, NamedCurve, Pkcs11Object, PublicKey, SlotTokenInfo,
};

use crate::sessions::SessionPools;
use cryptoki::context::Pkcs11;
use cryptoki::session::Session;
use cryptoki::slot::Slot;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// Shared library state (sessions, config, PKCS#11 context).
#[derive(Debug)]
pub(crate) struct Pkcs11LibInner {
    pub(crate) ctx: Mutex<Option<Pkcs11>>,
    pub(crate) config: OwnedTokenConfig,
    pub(crate) slot: SlotTokenInfo,
    pub(crate) pools: SessionPools,
    pub(crate) closed: AtomicBool,
}

/// Open PKCS#11 library handle with pooled sessions for the selected token.
#[derive(Debug, Clone)]
pub struct Pkcs11Lib {
    pub(crate) inner: Arc<Pkcs11LibInner>,
}

impl Pkcs11Lib {
    /// Initialize from token config (same as [`init`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CannotOpenPkcs11`] if the shared library at
    /// `cfg.path` cannot be loaded, [`Error::TokenNotFound`] if no slot's
    /// serial or label matches `cfg`, or [`Error::Pkcs11`] for any other
    /// PKCS#11 initialize/login failure.
    pub fn init(cfg: impl Into<OwnedTokenConfig>) -> Result<Self> {
        config::init(cfg)
    }

    /// Initialize from a config file path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be read, [`Error::Config`]
    /// if it cannot be parsed, or any error from [`Self::init`] once the
    /// config is loaded.
    pub fn from_config_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        configure_from_file(path)
    }

    /// Access the underlying cryptoki context (cloned Arc handle).
    pub(crate) fn ctx(&self) -> Result<Pkcs11> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        self.inner.ctx.lock().unwrap_or_else(PoisonError::into_inner).clone().ok_or(Error::Closed)
    }

    /// Run `f` with an exclusive RW session for `slot`.
    pub(crate) fn with_session<T, F>(&self, slot: Slot, f: F) -> Result<T>
    where
        F: FnOnce(&Session) -> Result<T>,
    {
        let ctx = self.ctx()?;
        self.inner.pools.with_session(&ctx, slot, f)
    }

    /// Open a new RW session on `slot_id` (low-level; prefer pooled ops).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the library has been closed, or
    /// [`Error::Pkcs11`] if `slot_id` is invalid or the session cannot be
    /// opened.
    pub fn new_session(&self, slot_id: u64) -> Result<Session> {
        let ctx = self.ctx()?;
        let slot = util::slot_from_id(slot_id)?;
        sessions::open_rw_session(&ctx, slot)
    }

    /// Release pooled sessions and finalize the PKCS#11 library.
    ///
    /// `Pkcs11Lib` is `Clone`, and PKCS#11's `C_Finalize` is process-wide with
    /// no refcount of its own — calling it while another clone is mid-session
    /// (e.g. inside `Self::with_session`) is undefined behavior at the FFI
    /// boundary. To avoid that race, this only finalizes when `self` is the
    /// last live handle (`Arc::strong_count(&self.inner) == 1`); otherwise it
    /// hands the handle back unchanged via `Err` and does nothing. Either
    /// way, cleanup still happens automatically and race-free via `Drop`
    /// once the last clone is dropped, so calling `close()` is optional.
    ///
    /// # Errors
    ///
    /// Returns `Err(self)` if other clones of this `Pkcs11Lib` are still alive.
    pub fn close(self) -> std::result::Result<(), Self> {
        match Arc::try_unwrap(self.inner) {
            Ok(inner) => {
                drop(inner);
                Ok(())
            }
            Err(inner) => Err(Self { inner }),
        }
    }
}

impl Drop for Pkcs11LibInner {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.pools.clear_all();
        if let Some(ctx) = self.ctx.get_mut().unwrap_or_else(PoisonError::into_inner).take() {
            // SoftHSM is process-global: only the last live handle may finalize.
            // Concurrent C_Initialize/C_Finalize also needs the module lock.
            let _guard = crate::config::pkcs11_module_lock();
            if crate::config::pkcs11_refcount_release() {
                let _ = ctx.finalize();
            }
            // else: drop `ctx` without C_Finalize — other handles still need the module.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No real PKCS#11 module needed: `ctx: None` alone exercises the
    /// refcount gating in `close()` without touching FFI.
    fn fake_lib() -> Pkcs11Lib {
        Pkcs11Lib {
            inner: Arc::new(Pkcs11LibInner {
                ctx: Mutex::new(None),
                config: OwnedTokenConfig {
                    manufacturer: String::new(),
                    model: String::new(),
                    path: String::new(),
                    token_serial: String::new(),
                    token_label: String::new(),
                    pin: secrecy::SecretString::from(""),
                    attributes: String::new(),
                },
                slot: SlotTokenInfo {
                    id: 0,
                    description: String::new(),
                    label: String::new(),
                    manufacturer: String::new(),
                    model: String::new(),
                    serial: String::new(),
                    login_required: false,
                },
                pools: SessionPools::new(),
                closed: AtomicBool::new(false),
            }),
        }
    }

    #[test]
    fn close_refuses_while_other_clones_are_alive() {
        let lib = fake_lib();
        let clone = lib.clone();
        let lib = lib.close().expect_err("a live clone must block close()");
        assert!(!lib.inner.closed.load(Ordering::Acquire));
        drop(clone);
        lib.close().expect("last handle must close successfully");
    }

    #[test]
    fn close_succeeds_as_last_handle() {
        let lib = fake_lib();
        lib.close().expect("sole handle must close successfully");
    }
}
