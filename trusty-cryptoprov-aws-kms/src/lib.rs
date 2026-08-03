#![doc = include_str!("../README.md")]

mod provider;

pub use provider::{AwsKmsConfig, AwsKmsProvider, loader};
