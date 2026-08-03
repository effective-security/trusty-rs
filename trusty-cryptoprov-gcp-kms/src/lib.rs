#![doc = include_str!("../README.md")]

mod provider;

pub use provider::{GcpKmsConfig, GcpKmsProvider, loader};
