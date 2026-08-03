#![doc = include_str!("../README.md")]

mod provider;
mod signer;

pub use provider::{AwsKmsProvider, loader};
pub use signer::{AwsKeyKind, AwsKmsSigner};
