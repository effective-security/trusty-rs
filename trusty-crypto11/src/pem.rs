//! Temporary SPKI/PEM encode for public keys (until `trusty-certutil`).

use crate::error::{Error, Result};
use crate::types::{EcdsaPublicKey, PublicKey};
use der::Encode;
use der::asn1::{AnyRef, BitStringRef, ObjectIdentifier};
use pem_rfc7468::{LineEnding, encode_string};
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

/// OID for `id-ecPublicKey` (1.2.840.10045.2.1).
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// OID for `secp224r1` (1.3.132.0.33).
const OID_SECP224R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.33");

/// Encode a public key as PEM (`PUBLIC KEY` / SPKI), matching Go certutil usage.
pub fn encode_public_key_pem(pub_key: &PublicKey) -> Result<String> {
    let der = match pub_key {
        PublicKey::Rsa(rsa) => encode_rsa_spki(rsa)?,
        PublicKey::Ecdsa(ec) => encode_ecdsa_spki(ec)?,
    };
    encode_string("PUBLIC KEY", LineEnding::LF, &der).map_err(Error::from)
}

fn encode_rsa_spki(rsa: &rsa::RsaPublicKey) -> Result<Vec<u8>> {
    // `rsa` 0.9 still depends on `spki` 0.7 / `pkcs8` 0.10, so its
    // `EncodePublicKey` is a different trait than the crate-root `pkcs8` 0.11.
    use rsa::pkcs8::EncodePublicKey;

    Ok(rsa.to_public_key_der().map_err(map_legacy_spki_err)?.as_bytes().to_vec())
}

fn encode_ecdsa_spki(ec: &EcdsaPublicKey) -> Result<Vec<u8>> {
    use pkcs8::EncodePublicKey;

    match ec {
        EcdsaPublicKey::P256(pk) => Ok(pk.to_public_key_der()?.as_bytes().to_vec()),
        EcdsaPublicKey::P384(pk) => Ok(pk.to_public_key_der()?.as_bytes().to_vec()),
        EcdsaPublicKey::P521(pk) => Ok(pk.to_public_key_der()?.as_bytes().to_vec()),
        EcdsaPublicKey::P224 { sec1 } => encode_p224_spki(sec1),
    }
}

fn map_legacy_spki_err(err: impl std::fmt::Display) -> Error {
    Error::Config(format!("spki: {err}"))
}

/// SPKI for id-ecPublicKey + secp224r1 + uncompressed point.
///
/// No `p224` crate exists to build this via `to_public_key_der()` like the
/// other curves, so the SPKI is assembled directly from `der`/`spki`'s typed
/// encoders instead.
fn encode_p224_spki(sec1: &[u8]) -> Result<Vec<u8>> {
    let spki = SubjectPublicKeyInfoRef {
        algorithm: AlgorithmIdentifierRef {
            oid: OID_EC_PUBLIC_KEY,
            parameters: Some(AnyRef::from(&OID_SECP224R1)),
        },
        subject_public_key: BitStringRef::new(0, sec1).map_err(|_| Error::MalformedPoint)?,
    };
    spki.to_der().map_err(|_| Error::MalformedPoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdsa::SEC1_UNCOMPRESSED_PREFIX;
    use rsa::RsaPublicKey;
    use rsa::pkcs8::DecodePublicKey;

    const RSA_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9NYz2LMdLIantfZAL/cLDKJL/\n\
/n1J3vd4F7Rv92dX8TaRWRBwA9f/qCtu8pOoA7pTLPV0TDtiRwrxtnH0YTe+HRa7\n\
duDn+Z+y6dr3FAMVaby70kpukJVVxCK8+VqbpGAztq3aCxhsl8om7StJh9qHXlKk\n\
OMybCsCasio7tDpy3QIDAQAB\n\
-----END PUBLIC KEY-----\n";

    #[test]
    fn encode_rsa_pem_roundtrip() {
        let pk = RsaPublicKey::from_public_key_pem(RSA_PEM).unwrap();
        let pem = encode_public_key_pem(&PublicKey::Rsa(pk)).unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.contains("-----END PUBLIC KEY-----"));
    }

    #[test]
    fn encode_p256_pem_has_headers() {
        let sec1 = p256_generator_sec1();
        let pk = p256::PublicKey::from_sec1_bytes(&sec1).unwrap();
        let pem = encode_public_key_pem(&PublicKey::Ecdsa(EcdsaPublicKey::P256(pk))).unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.contains("-----END PUBLIC KEY-----"));
    }

    #[test]
    fn encode_p224_spki_pem() {
        // Minimal-looking uncompressed P-224 point (57 bytes: prefix + 28 + 28)
        let mut sec1 = vec![SEC1_UNCOMPRESSED_PREFIX];
        sec1.extend(std::iter::repeat_n(0x02u8, 56));
        let pem = encode_public_key_pem(&PublicKey::Ecdsa(EcdsaPublicKey::P224 { sec1 })).unwrap();
        assert!(pem.contains("BEGIN PUBLIC KEY"));
    }

    fn p256_generator_sec1() -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = SEC1_UNCOMPRESSED_PREFIX;
        out[1..33].copy_from_slice(&[
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
        ]);
        out[33..65].copy_from_slice(&[
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
            0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5,
        ]);
        out
    }
}
