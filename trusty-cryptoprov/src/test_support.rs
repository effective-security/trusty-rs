//! Shared test helper: a [`Crypto`] backed by the inmem provider.
//!
//! Each test builds its own [`ProviderRegistry`]; there is no process-global
//! provider state.

use trusty_cryptoprov_core::{Crypto, ProviderRegistry};

pub(crate) fn inmem_crypto() -> Crypto {
    let mut registry = ProviderRegistry::new();
    registry.register("inmem", trusty_cryptoprov_inmem::loader()).unwrap();
    registry.load("", &[]).unwrap()
}
