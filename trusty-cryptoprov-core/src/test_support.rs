//! Shared dummy [`Provider`] for unit tests across modules.

use crate::error::{Error, Result};
use crate::provider::{KeyGenerator, Provider};
use crate::signing::{KeyPurpose, NamedCurve, Signer};
use std::sync::Arc;

/// A [`Provider`] whose identity is configurable and whose key operations
/// always fail — enough to exercise registry/lookup logic without touching
/// real cryptography.
pub(crate) struct FakeProvider {
    pub(crate) manufacturer: &'static str,
    pub(crate) model: &'static str,
}

impl KeyGenerator for FakeProvider {
    fn generate_rsa_key(&self, _: &str, _: usize, _: KeyPurpose) -> Result<Arc<dyn Signer>> {
        Err(Error::Config("unused".into()))
    }
    fn generate_ecdsa_key(&self, _: &str, _: NamedCurve) -> Result<Arc<dyn Signer>> {
        Err(Error::Config("unused".into()))
    }
    fn export_key(&self, _: &str) -> Result<(String, Vec<u8>)> {
        Err(Error::KeyNotFound("x".into()))
    }
    fn get_key(&self, _: &str) -> Result<Arc<dyn Signer>> {
        Err(Error::KeyNotFound("x".into()))
    }
}

impl Provider for FakeProvider {
    fn manufacturer(&self) -> &str {
        self.manufacturer
    }
    fn model(&self) -> &str {
        self.model
    }
}
