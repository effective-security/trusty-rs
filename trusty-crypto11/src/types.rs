//! Core PKCS#11 object and slot types.

use crate::error::Result;
use crate::util::slot_from_id;
use cryptoki::object::ObjectHandle;
use cryptoki::slot::Slot;

/// Information about a token present on a slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotTokenInfo {
    /// Slot identifier (`CK_SLOT_ID` as `u64`).
    pub id: u64,
    /// Slot description from `C_GetSlotInfo`.
    pub description: String,
    /// Token label.
    pub label: String,
    /// Token manufacturer.
    pub manufacturer: String,
    /// Token model.
    pub model: String,
    /// Token serial number.
    pub serial: String,
    /// Whether login is required for private objects / crypto ops.
    pub login_required: bool,
}

impl SlotTokenInfo {
    /// Convert to cryptoki [`Slot`].
    pub(crate) fn slot(&self) -> Result<Slot> {
        slot_from_id(self.id)
    }
}

/// Reference to a PKCS#11 object on a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pkcs11Object {
    /// Object handle.
    pub handle: ObjectHandle,
    /// Slot that owns the object.
    pub slot: u64,
}

/// Digest algorithms used by RSA sign/decrypt scheme enums.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// Named NIST curves supported for ECDSA key generation / export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// Curve name
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

/// Software public key material exported from the token.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PublicKey {
    /// RSA public key.
    Rsa(rsa::RsaPublicKey),
    /// ECDSA public key on a named curve.
    Ecdsa(EcdsaPublicKey),
}

/// ECDSA public key variants.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum EcdsaPublicKey {
    /// P-256
    P256(p256::PublicKey),
    /// P-384
    P384(p384::PublicKey),
    /// P-521
    P521(p521::PublicKey),
    /// P-224 encoded as uncompressed SEC1 bytes (no dedicated crate type).
    P224 {
        /// Uncompressed SEC1 point (`0x04 || X || Y`).
        sec1: Vec<u8>,
    },
}
