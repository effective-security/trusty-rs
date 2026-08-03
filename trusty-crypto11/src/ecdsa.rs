//! ECDSA key generation and signing (DER-encoded R\|S).

use crate::Pkcs11Lib;
use crate::error::{Error, Result};
use crate::types::{EcdsaPublicKey, NamedCurve, Pkcs11Object, PublicKey};
use crate::util::slot_from_id;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use der::asn1::{OctetStringRef, UintRef};
use der::{Decode, Encode, Sequence};
use std::sync::Arc;
use tracing::error;

/// PKCS#11 ECDSA private key with cached public key.
#[derive(Debug, Clone)]
pub struct EcdsaPrivateKey {
    pub(crate) lib: Arc<crate::Pkcs11LibInner>,
    pub(crate) object: Pkcs11Object,
    pub(crate) public_key: EcdsaPublicKey,
}

impl EcdsaPrivateKey {
    /// Object handle / slot.
    #[must_use]
    pub fn object(&self) -> Pkcs11Object {
        self.object
    }

    /// Cached public key.
    #[must_use]
    pub fn public(&self) -> &EcdsaPublicKey {
        &self.public_key
    }

    /// Sign `digest`; returns a DER-encoded ECDSA signature (ASN.1 `R`/`S`).
    ///
    /// `digest` must already be the raw hash bytes (this method does not
    /// hash the message).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the library has been closed, or
    /// [`Error::Pkcs11`] / encoding errors if signing or DER marshalling fails.
    pub fn sign(&self, digest: &[u8]) -> Result<Vec<u8>> {
        let slot = slot_from_id(self.object.slot)?;
        let lib = Pkcs11Lib { inner: Arc::clone(&self.lib) };
        lib.with_session(slot, |session| {
            let sig =
                session.sign(&Mechanism::Ecdsa, self.object.handle, digest).map_err(Error::from)?;
            marshal_ecdsa_der(&sig)
        })
    }
}

/// Optional id/label for [`Pkcs11Lib::generate_ecdsa_key_pair`] (random
/// id/label are generated when left `None`/empty).
#[derive(Debug, Clone, Copy, Default)]
pub struct EcdsaKeyPairOptions<'a> {
    /// `CKA_ID`; random if `None` or empty.
    pub id: Option<&'a [u8]>,
    /// `CKA_LABEL`; random if `None` or empty.
    pub label: Option<&'a str>,
}

impl Pkcs11Lib {
    /// Generate an ECDSA key pair, optionally on a specific slot (defaults
    /// to the token's current slot).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the library has been closed,
    /// [`Error::CannotGetRandomData`] if a random id/label could not be
    /// generated, or [`Error::Pkcs11`] if key generation fails.
    pub fn generate_ecdsa_key_pair(
        &self,
        curve: NamedCurve,
        slot_id: Option<u64>,
        opts: EcdsaKeyPairOptions<'_>,
    ) -> Result<EcdsaPrivateKey> {
        let slot_id = slot_id.unwrap_or_else(|| self.current_slot_id());
        self.inner.pools.setup(slot_id);
        let slot = slot_from_id(slot_id)?;
        self.with_session(slot, |session| {
            self.generate_ecdsa_key_pair_on_session(session, slot_id, curve, opts)
        })
    }

    /// Generate an ECDSA key pair on an already-open `session` (low-level;
    /// prefer [`Self::generate_ecdsa_key_pair`]).
    ///
    /// # Errors
    ///
    /// See [`Self::generate_ecdsa_key_pair`].
    pub fn generate_ecdsa_key_pair_on_session(
        &self,
        session: &Session,
        slot_id: u64,
        curve: NamedCurve,
        opts: EcdsaKeyPairOptions<'_>,
    ) -> Result<EcdsaPrivateKey> {
        let label = match opts.label {
            Some(l) if !l.is_empty() => l.as_bytes().to_vec(),
            _ => self.generate_key_label()?,
        };
        let id = match opts.id {
            Some(i) if !i.is_empty() => i.to_vec(),
            _ => self.generate_key_id()?,
        };
        let parameters = curve_oid_der(curve)?;

        let public_template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::EC),
            Attribute::Token(true),
            Attribute::Verify(true),
            Attribute::Label(label.clone()),
            Attribute::Id(id.clone()),
            Attribute::EcParams(parameters),
        ];
        let private_template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Token(true),
            Attribute::Sign(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Label(label),
            Attribute::Id(id),
        ];

        let (pub_handle, priv_handle) = session
            .generate_key_pair(&Mechanism::EccKeyPairGen, &public_template, &private_template)
            .map_err(|e| {
                error!(reason = "generate_key_pair", err = %e);
                Error::from(e)
            })?;

        let pub_key = export_ecdsa_public_key(session, pub_handle).map_err(|e| {
            error!(reason = "export_ecdsa_public_key", err = %e);
            e
        })?;

        Ok(EcdsaPrivateKey {
            lib: Arc::clone(&self.inner),
            object: Pkcs11Object { handle: priv_handle, slot: slot_id },
            public_key: pub_key,
        })
    }

    /// High-level ECDSA generate returning [`crate::keys::GeneratedKey`].
    ///
    /// # Errors
    ///
    /// See [`Self::generate_ecdsa_key_pair`].
    pub fn generate_ecdsa_key(
        &self,
        label: &str,
        curve: NamedCurve,
    ) -> Result<crate::keys::GeneratedKey> {
        let opts = EcdsaKeyPairOptions { label: Some(label), ..Default::default() };
        let priv_key = self.generate_ecdsa_key_pair(curve, None, opts)?;
        let identity = self.identify(&priv_key.object)?;
        Ok(crate::keys::GeneratedKey {
            id: identity.id,
            label: identity.label,
            key: crate::keys::PrivateKey::Ecdsa(priv_key),
        })
    }
}

/// Uncompressed SEC1 EC point prefix (`0x04 || X || Y`).
pub(crate) const SEC1_UNCOMPRESSED_PREFIX: u8 = 0x04;

/// DER-encoded `secp224r1` OID (1.3.132.0.33) for `CKA_EC_PARAMS`.
pub(crate) const OID_SECP224R1_DER: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21];
/// DER-encoded `prime256v1` OID (1.2.840.10045.3.1.7) for `CKA_EC_PARAMS`.
const OID_PRIME256V1_DER: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// DER-encoded `secp384r1` OID (1.3.132.0.34) for `CKA_EC_PARAMS`.
const OID_SECP384R1_DER: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
/// DER-encoded `secp521r1` OID (1.3.132.0.35) for `CKA_EC_PARAMS`.
const OID_SECP521R1_DER: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

/// DER-encoded named curve OID.
pub(crate) fn curve_oid_der(curve: NamedCurve) -> Result<Vec<u8>> {
    Ok(match curve {
        NamedCurve::P224 => OID_SECP224R1_DER.to_vec(),
        NamedCurve::P256 => OID_PRIME256V1_DER.to_vec(),
        NamedCurve::P384 => OID_SECP384R1_DER.to_vec(),
        NamedCurve::P521 => OID_SECP521R1_DER.to_vec(),
    })
}

pub(crate) fn curve_from_oid(oid: &[u8]) -> Result<NamedCurve> {
    for curve in [NamedCurve::P224, NamedCurve::P256, NamedCurve::P384, NamedCurve::P521] {
        if curve_oid_der(curve)? == oid {
            return Ok(curve);
        }
    }
    Err(Error::UnsupportedEllipticCurve)
}

pub(crate) fn export_ecdsa_public_key(
    session: &Session,
    pub_handle: ObjectHandle,
) -> Result<EcdsaPublicKey> {
    let attrs = session
        .get_attributes(pub_handle, &[AttributeType::EcParams, AttributeType::EcPoint])
        .map_err(Error::from)?;
    let mut params = None;
    let mut point = None;
    for a in attrs {
        match a {
            Attribute::EcParams(v) => params = Some(v),
            Attribute::EcPoint(v) => point = Some(v),
            _ => {}
        }
    }
    let params = params.ok_or(Error::UnsupportedEllipticCurve)?;
    let point = point.ok_or(Error::MalformedPoint)?;
    let curve = curve_from_oid(&params)?;
    let sec1 = parse_ec_point_der(&point)?;
    match curve {
        NamedCurve::P256 => {
            let pk = p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| Error::MalformedPoint)?;
            Ok(EcdsaPublicKey::P256(pk))
        }
        NamedCurve::P384 => {
            let pk = p384::PublicKey::from_sec1_bytes(&sec1).map_err(|_| Error::MalformedPoint)?;
            Ok(EcdsaPublicKey::P384(pk))
        }
        NamedCurve::P521 => {
            let pk = p521::PublicKey::from_sec1_bytes(&sec1).map_err(|_| Error::MalformedPoint)?;
            Ok(EcdsaPublicKey::P521(pk))
        }
        NamedCurve::P224 => Ok(EcdsaPublicKey::P224 { sec1 }),
    }
}

/// Parse PKCS#11 `CKA_EC_POINT` (DER OCTET STRING wrapping uncompressed SEC1).
///
/// Also accepts raw uncompressed SEC1 when the DER parse does not fit (some tokens).
pub(crate) fn parse_ec_point_der(b: &[u8]) -> Result<Vec<u8>> {
    if let Ok(point) = try_parse_der_octet_string(b) {
        if point.first() == Some(&SEC1_UNCOMPRESSED_PREFIX) {
            return Ok(point);
        }
        return Err(Error::MalformedPoint);
    }
    // Raw SEC1: uncompressed || X || Y (odd total length)
    if b.first() == Some(&SEC1_UNCOMPRESSED_PREFIX) && b.len() >= 3 && !b.len().is_multiple_of(2) {
        return Ok(b.to_vec());
    }
    Err(Error::MalformedDer)
}

fn try_parse_der_octet_string(b: &[u8]) -> Result<Vec<u8>> {
    // `from_der` requires the input be exactly one DER TLV (errors on
    // trailing bytes), so raw SEC1 input is never mis-parsed as DER.
    // der 0.8 models OCTET STRING as a DST (`OctetStringRef`), so decoding
    // yields `&OctetStringRef` rather than an owned/lifetime-parameterized value.
    let octet_string = <&OctetStringRef>::from_der(b).map_err(|_| Error::MalformedDer)?;
    Ok(octet_string.as_bytes().to_vec())
}

#[derive(Sequence)]
struct EcdsaSig<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

/// Convert raw PKCS#11 R\|S to DER.
pub(crate) fn marshal_ecdsa_der(sig_bytes: &[u8]) -> Result<Vec<u8>> {
    if sig_bytes.is_empty() || !sig_bytes.len().is_multiple_of(2) {
        return Err(Error::MalformedSignature);
    }
    let n = sig_bytes.len() / 2;
    let r = strip_leading_zeros(&sig_bytes[..n]);
    let s = strip_leading_zeros(&sig_bytes[n..]);
    let sig = EcdsaSig {
        r: UintRef::new(r).map_err(|_| Error::MalformedSignature)?,
        s: UintRef::new(s).map_err(|_| Error::MalformedSignature)?,
    };
    sig.to_der().map_err(|_| Error::MalformedSignature)
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + 1 < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    &bytes[i..]
}

pub(crate) fn ecdsa_to_public(pk: &EcdsaPublicKey) -> PublicKey {
    PublicKey::Ecdsa(pk.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec1_point(body_len: usize) -> Vec<u8> {
        let mut p = vec![SEC1_UNCOMPRESSED_PREFIX];
        p.extend(std::iter::repeat_n(0xAB, body_len));
        p
    }

    /// Round-trip check for the `der`-crate OCTET STRING parser: short-form
    /// length (P-256-shaped).
    #[test]
    fn parse_ec_point_der_short_form_octet_string() {
        let point = sec1_point(64); // 65 bytes, DER length fits in one byte
        let mut wrapped = vec![0x04, point.len() as u8];
        wrapped.extend_from_slice(&point);
        assert_eq!(parse_ec_point_der(&wrapped).unwrap(), point);
    }

    /// Long-form DER length (P-521-shaped point forces a length > 127).
    #[test]
    fn parse_ec_point_der_long_form_octet_string() {
        let point = sec1_point(132); // 133 bytes, needs a long-form length
        let mut wrapped = vec![0x04, 0x81, point.len() as u8];
        wrapped.extend_from_slice(&point);
        assert_eq!(parse_ec_point_der(&wrapped).unwrap(), point);
    }

    #[test]
    fn parse_ec_point_der_raw_sec1_fallback() {
        let point = sec1_point(64);
        assert_eq!(parse_ec_point_der(&point).unwrap(), point);
    }

    #[test]
    fn parse_ec_point_der_rejects_trailing_bytes() {
        let point = sec1_point(64);
        let mut wrapped = vec![0x04, point.len() as u8];
        wrapped.extend_from_slice(&point);
        wrapped.push(0xFF);
        assert!(parse_ec_point_der(&wrapped).is_err());
    }

    #[test]
    fn parse_ec_point_der_rejects_wrong_tag() {
        // BIT STRING tag, not OCTET STRING; also not shaped like raw SEC1.
        let bytes = [0x03, 0x05, 0, 0, 0, 0, 0];
        assert!(parse_ec_point_der(&bytes).is_err());
    }
}
