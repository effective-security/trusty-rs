//! Algorithm identifiers and the [`Signer`] trait.
//!
//! These enums mirror shapes used by `trusty-crypto11`, but are defined
//! natively here rather than re-exported from it, so this crate never
//! depends on a PKCS#11 (or any other provider) SDK. Provider crates convert
//! between their SDK's types and these at their own boundary (see
//! `trusty-cryptoprov-pkcs11`'s scheme-conversion helpers).

use crate::error::Result;

/// Key purpose for RSA generation (maps to PKCS#11 `CKA_SIGN` / `CKA_ENCRYPT`,
/// or the equivalent concept in other backends).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyPurpose {
    /// No purpose attributes beyond defaults.
    #[default]
    Undefined,
    /// Signing / verification.
    Signing,
    /// Encryption / decryption.
    Encryption,
}

impl KeyPurpose {
    /// Map integer purpose codes: `1` = signing, `2` = encryption, otherwise
    /// [`KeyPurpose::Undefined`].
    ///
    /// Prefer constructing [`KeyPurpose`] variants directly in new code.
    #[must_use]
    pub const fn from_int(purpose: i32) -> Self {
        match purpose {
            1 => Self::Signing,
            2 => Self::Encryption,
            _ => Self::Undefined,
        }
    }
}

/// Named NIST curves for ECDSA key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedCurve {
    /// NIST P-224
    P224,
    /// NIST P-256
    P256,
    /// NIST P-384
    P384,
    /// NIST P-521
    P521,
}

impl NamedCurve {
    /// Curve name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::P224 => "P-224",
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
        }
    }
}

/// Digest algorithm identifier for a pre-computed hash to be signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// SHA-1
    Sha1,
    /// SHA-224
    Sha224,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

impl DigestAlgorithm {
    /// Digest output length in bytes.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// RSA PSS salt length policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PssSaltLen {
    /// Salt length equals hash length.
    EqualsHash,
    /// Explicit salt length in bytes.
    Explicit(usize),
}

/// RSA signature scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsaSignScheme {
    /// PKCS#1 v1.5 with DigestInfo prefix for `hash`.
    Pkcs1v15 {
        /// Hash algorithm of the pre-computed digest.
        hash: DigestAlgorithm,
    },
    /// RSASSA-PSS; salt Auto is rejected.
    Pss {
        /// Hash / MGF1 hash.
        hash: DigestAlgorithm,
        /// Salt length policy.
        salt_len: PssSaltLen,
    },
}

/// A signing key handle, owned by whichever provider produced it.
///
/// Replaces a closed "one enum variant per provider" key type: every
/// provider crate defines its own concrete type implementing `Signer`
/// (`Pkcs11Signer`, a software RSA/ECDSA signer, ...) without any of them
/// needing to be known to this crate or to each other.
pub trait Signer: Send + Sync + std::fmt::Debug {
    /// Sign a precomputed `digest` with RSA (PKCS#1 v1.5 or PSS).
    ///
    /// # Errors
    ///
    /// [`crate::error::Error::UnsupportedKeyType`] if this signer is not an
    /// RSA key, or a provider-specific signing failure.
    fn sign_rsa(&self, digest: &[u8], scheme: &RsaSignScheme) -> Result<Vec<u8>>;

    /// Sign a precomputed `digest` with ECDSA; returns DER-encoded `R|S`.
    ///
    /// # Errors
    ///
    /// [`crate::error::Error::UnsupportedKeyType`] if this signer is not an
    /// ECDSA key, or a provider-specific signing failure.
    fn sign_ecdsa(&self, digest: &[u8]) -> Result<Vec<u8>>;

    /// Provider key ID, when this signer is backed by a provider key store.
    fn key_id(&self) -> Option<&str> {
        None
    }

    /// Provider key label, when known.
    fn label(&self) -> Option<&str> {
        None
    }
}
