//! RSA key generation, signing, and decryption.

use crate::Pkcs11Lib;
use crate::common::{key_id_from_random, key_label_from_random, utc_now_parts};
use crate::error::{Error, Result};
use crate::types::{DigestAlgorithm, Pkcs11Object, PublicKey};
use crate::util::slot_from_id;
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::AttributeType;
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use cryptoki::types::Ulong;
use num_integer::Integer;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};
use std::sync::Arc;
use tracing::{debug, error};

/// RSA public exponent 65537 (F4) as big-endian PKCS#11 `CKA_PUBLIC_EXPONENT` bytes.
const RSA_PUBLIC_EXPONENT_F4: &[u8] = &[0x01, 0x00, 0x01];

/// DigestInfo DER prefix for SHA-1 (RFC 8017).
const DIGEST_INFO_SHA1: &[u8] =
    &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
/// DigestInfo DER prefix for SHA-224 (RFC 8017).
const DIGEST_INFO_SHA224: &[u8] = &[
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
    0x00, 0x04, 0x1c,
];
/// DigestInfo DER prefix for SHA-256 (RFC 8017).
const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
/// DigestInfo DER prefix for SHA-384 (RFC 8017).
const DIGEST_INFO_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
/// DigestInfo DER prefix for SHA-512 (RFC 8017).
const DIGEST_INFO_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// Key purpose controlling CKA_SIGN/VERIFY vs CKA_ENCRYPT/DECRYPT.
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

/// PSS salt length.
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

/// RSA decryption scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsaDecryptScheme {
    /// PKCS#1 v1.5 (no SessionKeyLen).
    Pkcs1v15,
    /// RSAES-OAEP.
    Oaep {
        /// OAEP hash / MGF1.
        hash: DigestAlgorithm,
        /// OAEP label (empty for SoftHSM SHA-1 path).
        label: Vec<u8>,
    },
}

/// PKCS#11 RSA private key handle with cached public key.
#[derive(Debug, Clone)]
pub struct RsaPrivateKey {
    pub(crate) lib: Arc<crate::Pkcs11LibInner>,
    pub(crate) object: Pkcs11Object,
    pub(crate) public_key: RsaPublicKey,
}

impl RsaPrivateKey {
    /// Object handle / slot.
    #[must_use]
    pub fn object(&self) -> Pkcs11Object {
        self.object
    }

    /// Cached public key.
    #[must_use]
    pub fn public(&self) -> &RsaPublicKey {
        &self.public_key
    }

    /// Limited validation (exponent ≥ 2 and odd).
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedRsaKey`] if the public exponent is invalid.
    pub fn validate(&self) -> Result<()> {
        if !is_valid_rsa_exponent(self.public_key.e()) {
            return Err(Error::MalformedRsaKey);
        }
        Ok(())
    }

    /// Sign `digest` using the given scheme.
    ///
    /// `digest` must already be the raw hash bytes matching `scheme`'s hash
    /// algorithm (this method does not hash the message).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the library has been closed,
    /// [`Error::UnsupportedRsaOptions`] for unsupported scheme options, or
    /// [`Error::Pkcs11`] for token failures.
    pub fn sign(&self, digest: &[u8], scheme: &RsaSignScheme) -> Result<Vec<u8>> {
        let slot = slot_from_id(self.object.slot)?;
        let lib = Pkcs11Lib { inner: Arc::clone(&self.lib) };
        lib.with_session(slot, |session| match scheme {
            RsaSignScheme::Pkcs1v15 { hash } => {
                sign_pkcs1v15(session, self.object.handle, digest, *hash)
            }
            RsaSignScheme::Pss { hash, salt_len } => {
                sign_pss(session, self.object.handle, digest, *hash, *salt_len)
            }
        })
    }

    /// Decrypt `ciphertext` using the given scheme.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the library has been closed, or
    /// [`Error::Pkcs11`] if decryption fails on the token.
    pub fn decrypt(&self, ciphertext: &[u8], scheme: &RsaDecryptScheme) -> Result<Vec<u8>> {
        let slot = slot_from_id(self.object.slot)?;
        let lib = Pkcs11Lib { inner: Arc::clone(&self.lib) };
        lib.with_session(slot, |session| match scheme {
            RsaDecryptScheme::Pkcs1v15 => decrypt_pkcs1v15(session, self.object.handle, ciphertext),
            RsaDecryptScheme::Oaep { hash, label } => {
                decrypt_oaep(session, self.object.handle, ciphertext, *hash, label)
            }
        })
    }
}

/// Optional id/label/purpose for [`Pkcs11Lib::generate_rsa_key_pair`] (random
/// id/label are generated when left `None`/empty).
#[derive(Debug, Clone, Copy, Default)]
pub struct RsaKeyPairOptions<'a> {
    /// `CKA_ID`; random if `None` or empty.
    pub id: Option<&'a [u8]>,
    /// `CKA_LABEL`; random if `None` or empty.
    pub label: Option<&'a str>,
    /// Sign/verify vs. encrypt/decrypt attributes.
    pub purpose: KeyPurpose,
}

impl Pkcs11Lib {
    /// Generate an RSA key pair, optionally on a specific slot (defaults to
    /// the token's current slot).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the library has been closed,
    /// [`Error::CannotGetRandomData`] if a random id/label could not be
    /// generated, or [`Error::Pkcs11`] if key generation fails.
    pub fn generate_rsa_key_pair(
        &self,
        bits: usize,
        slot_id: Option<u64>,
        opts: RsaKeyPairOptions<'_>,
    ) -> Result<RsaPrivateKey> {
        let slot_id = slot_id.unwrap_or_else(|| self.current_slot_id());
        self.inner.pools.setup(slot_id);
        let slot = slot_from_id(slot_id)?;
        self.with_session(slot, |session| {
            self.generate_rsa_key_pair_on_session(session, slot_id, bits, opts)
        })
    }

    /// Generate an RSA key pair on an already-open `session` (low-level;
    /// prefer [`Self::generate_rsa_key_pair`]).
    ///
    /// # Errors
    ///
    /// See [`Self::generate_rsa_key_pair`].
    pub fn generate_rsa_key_pair_on_session(
        &self,
        session: &Session,
        slot_id: u64,
        bits: usize,
        opts: RsaKeyPairOptions<'_>,
    ) -> Result<RsaPrivateKey> {
        let purpose = opts.purpose;
        let label = match opts.label {
            Some(l) if !l.is_empty() => l.as_bytes().to_vec(),
            _ => self.generate_key_label()?,
        };
        let id = match opts.id {
            Some(i) if !i.is_empty() => i.to_vec(),
            _ => self.generate_key_id()?,
        };

        let mut public_template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Token(true),
            Attribute::PublicExponent(RSA_PUBLIC_EXPONENT_F4.to_vec()),
            Attribute::ModulusBits(Ulong::new(bits as u64)),
            Attribute::Label(label.clone()),
            Attribute::Id(id.clone()),
        ];
        let mut private_template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Label(label),
            Attribute::Id(id),
        ];

        match purpose {
            KeyPurpose::Signing => {
                public_template.push(Attribute::Verify(true));
                private_template.push(Attribute::Sign(true));
            }
            KeyPurpose::Encryption => {
                public_template.push(Attribute::Encrypt(true));
                private_template.push(Attribute::Decrypt(true));
            }
            KeyPurpose::Undefined => {}
        }

        let (pub_handle, priv_handle) = session
            .generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &public_template, &private_template)
            .map_err(|e| {
                error!(reason = "generate_key_pair", err = %e);
                Error::from(e)
            })?;

        let pub_key = export_rsa_public_key(session, pub_handle).map_err(|e| {
            error!(reason = "export_rsa_public_key", err = %e);
            e
        })?;

        Ok(RsaPrivateKey {
            lib: Arc::clone(&self.inner),
            object: Pkcs11Object { handle: priv_handle, slot: slot_id },
            public_key: pub_key,
        })
    }

    /// High-level generate returning [`crate::keys::GeneratedKey`] with id/label.
    ///
    /// # Errors
    ///
    /// See [`Self::generate_rsa_key_pair`].
    pub fn generate_rsa_key(
        &self,
        label: &str,
        bits: usize,
        purpose: KeyPurpose,
    ) -> Result<crate::keys::GeneratedKey> {
        let opts = RsaKeyPairOptions { label: Some(label), purpose, ..Default::default() };
        let priv_key = self.generate_rsa_key_pair(bits, None, opts)?;
        let identity = self.identify(&priv_key.object)?;
        Ok(crate::keys::GeneratedKey {
            id: identity.id,
            label: identity.label,
            key: crate::keys::PrivateKey::Rsa(priv_key),
        })
    }

    pub(crate) fn generate_key_label(&self) -> Result<Vec<u8>> {
        let mut raw = [0u8; 32];
        let n = self.gen_random(&mut raw)?;
        if n < raw.len() {
            return Err(Error::CannotGetRandomData);
        }
        let (y, m, d, hh, mm, ss) = utc_now_parts();
        key_label_from_random(&raw, y, m, d, hh, mm, ss)
    }

    pub(crate) fn generate_key_id(&self) -> Result<Vec<u8>> {
        let mut raw = [0u8; 32];
        let n = self.gen_random(&mut raw)?;
        if n < raw.len() {
            return Err(Error::CannotGetRandomData);
        }
        key_id_from_random(&raw)
    }
}

/// A valid RSA public exponent is `>= 2` and odd (an even `e` can't be
/// coprime with `phi(n)`).
fn is_valid_rsa_exponent(e: &BigUint) -> bool {
    e >= &BigUint::from(2u32) && e.is_odd()
}

pub(crate) fn export_rsa_public_key(
    session: &Session,
    pub_handle: ObjectHandle,
) -> Result<RsaPublicKey> {
    debug!(obj = %pub_handle, "export_rsa_public_key");
    let attrs = session
        .get_attributes(pub_handle, &[AttributeType::Modulus, AttributeType::PublicExponent])
        .map_err(Error::from)?;
    let mut modulus = None;
    let mut exponent = None;
    for a in attrs {
        match a {
            Attribute::Modulus(v) => modulus = Some(v),
            Attribute::PublicExponent(v) => exponent = Some(v),
            _ => {}
        }
    }
    let modulus = modulus.ok_or(Error::MalformedRsaKey)?;
    let exponent = exponent.ok_or(Error::MalformedRsaKey)?;
    let n = BigUint::from_bytes_be(&modulus);
    let e = BigUint::from_bytes_be(&exponent);
    if e.bits() > 32 || e < BigUint::from(2u32) {
        return Err(Error::MalformedRsaKey);
    }
    RsaPublicKey::new(n, e).map_err(|_| Error::MalformedRsaKey)
}

fn hash_to_pkcs11(hash: DigestAlgorithm) -> Result<(MechanismType, PkcsMgfType, u64)> {
    Ok(match hash {
        DigestAlgorithm::Sha1 => (MechanismType::SHA1, PkcsMgfType::MGF1_SHA1, 20),
        DigestAlgorithm::Sha224 => (MechanismType::SHA224, PkcsMgfType::MGF1_SHA224, 28),
        DigestAlgorithm::Sha256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256, 32),
        DigestAlgorithm::Sha384 => (MechanismType::SHA384, PkcsMgfType::MGF1_SHA384, 48),
        DigestAlgorithm::Sha512 => (MechanismType::SHA512, PkcsMgfType::MGF1_SHA512, 64),
    })
}

fn pkcs1_digest_info_prefix(hash: DigestAlgorithm) -> &'static [u8] {
    match hash {
        DigestAlgorithm::Sha1 => DIGEST_INFO_SHA1,
        DigestAlgorithm::Sha224 => DIGEST_INFO_SHA224,
        DigestAlgorithm::Sha256 => DIGEST_INFO_SHA256,
        DigestAlgorithm::Sha384 => DIGEST_INFO_SHA384,
        DigestAlgorithm::Sha512 => DIGEST_INFO_SHA512,
    }
}

fn sign_pkcs1v15(
    session: &Session,
    key: ObjectHandle,
    digest: &[u8],
    hash: DigestAlgorithm,
) -> Result<Vec<u8>> {
    let prefix = pkcs1_digest_info_prefix(hash);
    let mut t = Vec::with_capacity(prefix.len() + digest.len());
    t.extend_from_slice(prefix);
    t.extend_from_slice(digest);
    session.sign(&Mechanism::RsaPkcs, key, &t).map_err(Error::from)
}

fn sign_pss(
    session: &Session,
    key: ObjectHandle,
    digest: &[u8],
    hash: DigestAlgorithm,
    salt_len: PssSaltLen,
) -> Result<Vec<u8>> {
    let (h_mech, mgf, h_len) = hash_to_pkcs11(hash)?;
    let s_len = match salt_len {
        PssSaltLen::EqualsHash => h_len,
        PssSaltLen::Explicit(n) => n as u64,
    };
    let params = PkcsPssParams { hash_alg: h_mech, mgf, s_len: Ulong::new(s_len) };
    let mech = Mechanism::RsaPkcsPss(params);
    session.sign(&mech, key, digest).map_err(Error::from)
}

fn decrypt_pkcs1v15(session: &Session, key: ObjectHandle, ciphertext: &[u8]) -> Result<Vec<u8>> {
    session.decrypt(&Mechanism::RsaPkcs, key, ciphertext).map_err(Error::from)
}

fn decrypt_oaep(
    session: &Session,
    key: ObjectHandle,
    ciphertext: &[u8],
    hash: DigestAlgorithm,
    label: &[u8],
) -> Result<Vec<u8>> {
    let (h_mech, mgf, _) = hash_to_pkcs11(hash)?;
    let source = if label.is_empty() {
        PkcsOaepSource::empty()
    } else {
        PkcsOaepSource::data_specified(label)
    };
    let params = PkcsOaepParams::new(h_mech, mgf, source);
    let mech = Mechanism::from(params);
    session.decrypt(&mech, key, ciphertext).map_err(Error::from)
}

/// Convert RSA public key into [`PublicKey`].
pub(crate) fn rsa_to_public(pk: &RsaPublicKey) -> PublicKey {
    PublicKey::Rsa(pk.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_exponent_f4_is_valid() {
        assert!(is_valid_rsa_exponent(&BigUint::from(65537u32)));
    }

    #[test]
    fn rsa_exponent_rejects_even() {
        assert!(!is_valid_rsa_exponent(&BigUint::from(65536u32)));
        assert!(!is_valid_rsa_exponent(&BigUint::from(2u32)));
    }

    #[test]
    fn rsa_exponent_rejects_below_two() {
        assert!(!is_valid_rsa_exponent(&BigUint::from(0u32)));
        assert!(!is_valid_rsa_exponent(&BigUint::from(1u32)));
    }
}
