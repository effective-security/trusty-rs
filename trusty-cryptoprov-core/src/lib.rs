#![doc = include_str!("../README.md")]

pub mod config;
pub mod error;
pub mod provider;
pub mod registry;
pub mod signing;
pub mod sync;
#[cfg(test)]
mod test_support;

pub use config::{FileTokenConfig, TokenConfig, load_token_config};
pub use error::{Error, Result};
pub use provider::{Crypto, KeyGenerator, KeyInfo, KeyManager, Provider, TokenInfo};
pub use registry::{ProviderLoader, ProviderRegistry};
pub use signing::{DigestAlgorithm, KeyPurpose, NamedCurve, PssSaltLen, RsaSignScheme, Signer};
