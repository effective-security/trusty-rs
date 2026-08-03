#![doc = include_str!("../README.md")]

pub mod ext;
pub mod gcm;
pub mod keys;
pub mod signer;
pub mod tls;

#[cfg(all(test, feature = "inmem"))]
mod test_support;

pub use ext::CryptoExt;
pub use gcm::{gcm_decrypt, gcm_encrypt};
#[cfg(feature = "inmem")]
pub use keys::{
    SoftwareEcdsaKey, SoftwareKey, SoftwareRsaKey, get_private_key_der_from_pem,
    key_purpose_from_int, parse_private_key_der, parse_private_key_pem,
    parse_private_key_pem_with_password,
};
pub use tls::TlsKeyMaterial;
#[cfg(feature = "aws-kms")]
pub use trusty_cryptoprov_aws_kms::{AwsKmsConfig, AwsKmsProvider};
pub use trusty_cryptoprov_core::{
    Crypto, DigestAlgorithm, Error, FileTokenConfig, KeyGenerator, KeyInfo, KeyManager, KeyPurpose,
    NamedCurve, Provider, ProviderLoader, ProviderRegistry, PssSaltLen, Result, RsaSignScheme,
    Signer, TokenConfig, TokenInfo, load_token_config,
};
#[cfg(feature = "gcp-kms")]
pub use trusty_cryptoprov_gcp_kms::{GcpKmsConfig, GcpKmsProvider};
#[cfg(feature = "inmem")]
pub use trusty_cryptoprov_inmem::{InmemProvider, PROVIDER_NAME as INMEM_PROVIDER_NAME};
#[cfg(feature = "pkcs11")]
pub use trusty_cryptoprov_pkcs11::{
    Pkcs11Provider, Pkcs11Signer, PrivateKeyUri, parse_private_key_uri, parse_token_uri,
};
