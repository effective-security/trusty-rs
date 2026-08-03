//! Software (in-process) signing keys and PEM/DER private-key parsing.

use pem::parse_many;
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey as DecodeRsaPkcs8;
use rsa::rand_core::OsRng;
use rsa::{Pkcs1v15Sign, Pss};
// rsa 0.9 is on digest 0.10; use its re-exported sha2 types for PKCS#1/PSS
// scheme construction. A caller hashing digests itself uses sha2 0.11.
use rsa::sha2::{Sha224, Sha256, Sha384, Sha512};
use sha1_legacy::Sha1;
use std::sync::Arc;
use trusty_cryptoprov_core::{DigestAlgorithm, Error, PssSaltLen, Result, RsaSignScheme, Signer};

/// Software ECDSA private key (one of P-256 / P-384 / P-521).
#[derive(Clone)]
pub enum EcdsaSoftwareKey {
    /// P-256 signing key.
    P256(p256::ecdsa::SigningKey),
    /// P-384 signing key.
    P384(p384::ecdsa::SigningKey),
    /// P-521 signing key.
    P521(p521::ecdsa::SigningKey),
}

impl std::fmt::Debug for EcdsaSoftwareKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P256(_) => f.write_str("EcdsaSoftwareKey::P256"),
            Self::P384(_) => f.write_str("EcdsaSoftwareKey::P384"),
            Self::P521(_) => f.write_str("EcdsaSoftwareKey::P521"),
        }
    }
}

/// In-process RSA private key with optional provider identity metadata.
#[derive(Clone)]
pub struct SoftwareRsaKey {
    /// RSA private key material.
    pub key: RsaPrivateKey,
    /// Provider key ID (empty for PEM-parsed keys).
    pub id: String,
    /// Provider key label (empty for PEM-parsed keys).
    pub label: String,
}

impl std::fmt::Debug for SoftwareRsaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareRsaKey")
            .field("id", &self.id)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// In-process ECDSA private key with optional provider identity metadata.
#[derive(Clone, Debug)]
pub struct SoftwareEcdsaKey {
    /// Curve-specific key material.
    pub key: EcdsaSoftwareKey,
    /// Provider key ID (empty for PEM-parsed keys).
    pub id: String,
    /// Provider key label (empty for PEM-parsed keys).
    pub label: String,
}

/// A software (in-process) signing key: RSA or ECDSA.
///
/// This crate's only `Signer` implementation — `trusty-cryptoprov-pkcs11`
/// defines its own separate `Pkcs11Signer`, with no shared type between them.
#[derive(Clone, Debug)]
pub enum SoftwareKey {
    /// Software RSA key.
    Rsa(SoftwareRsaKey),
    /// Software ECDSA key.
    Ecdsa(SoftwareEcdsaKey),
}

impl Signer for SoftwareKey {
    fn sign_rsa(&self, digest: &[u8], scheme: &RsaSignScheme) -> Result<Vec<u8>> {
        match self {
            Self::Rsa(k) => sign_software_rsa(&k.key, digest, scheme),
            Self::Ecdsa(_) => Err(Error::UnsupportedKeyType),
        }
    }

    fn sign_ecdsa(&self, digest: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Ecdsa(k) => sign_software_ecdsa(&k.key, digest),
            Self::Rsa(_) => Err(Error::UnsupportedKeyType),
        }
    }

    fn key_id(&self) -> Option<&str> {
        match self {
            Self::Rsa(k) if !k.id.is_empty() => Some(&k.id),
            Self::Ecdsa(k) if !k.id.is_empty() => Some(&k.id),
            _ => None,
        }
    }

    fn label(&self) -> Option<&str> {
        match self {
            Self::Rsa(k) if !k.label.is_empty() => Some(&k.label),
            Self::Ecdsa(k) if !k.label.is_empty() => Some(&k.label),
            _ => None,
        }
    }
}

fn sign_software_rsa(
    key: &RsaPrivateKey,
    digest: &[u8],
    scheme: &RsaSignScheme,
) -> Result<Vec<u8>> {
    match scheme {
        RsaSignScheme::Pkcs1v15 { hash } => {
            let padding = pkcs1v15_padding(*hash)?;
            key.sign(padding, digest).map_err(|e| Error::SignFailure(e.to_string()))
        }
        RsaSignScheme::Pss { hash, salt_len } => {
            let padding = pss_padding(*hash, *salt_len)?;
            key.sign_with_rng(&mut OsRng, padding, digest)
                .map_err(|e| Error::SignFailure(e.to_string()))
        }
    }
}

fn pkcs1v15_padding(hash: DigestAlgorithm) -> Result<Pkcs1v15Sign> {
    Ok(match hash {
        DigestAlgorithm::Sha1 => Pkcs1v15Sign::new::<Sha1>(),
        DigestAlgorithm::Sha224 => Pkcs1v15Sign::new::<Sha224>(),
        DigestAlgorithm::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
        DigestAlgorithm::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
        DigestAlgorithm::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
    })
}

fn pss_padding(hash: DigestAlgorithm, salt_len: PssSaltLen) -> Result<Pss> {
    let salt = match salt_len {
        PssSaltLen::EqualsHash => hash.digest_len(),
        PssSaltLen::Explicit(n) => n,
    };
    Ok(match hash {
        DigestAlgorithm::Sha1 => Pss::new_with_salt::<Sha1>(salt),
        DigestAlgorithm::Sha224 => Pss::new_with_salt::<Sha224>(salt),
        DigestAlgorithm::Sha256 => Pss::new_with_salt::<Sha256>(salt),
        DigestAlgorithm::Sha384 => Pss::new_with_salt::<Sha384>(salt),
        DigestAlgorithm::Sha512 => Pss::new_with_salt::<Sha512>(salt),
    })
}

fn sign_software_ecdsa(key: &EcdsaSoftwareKey, digest: &[u8]) -> Result<Vec<u8>> {
    // p256/p384/p521 use `signature` v3; use each crate's re-export so traits resolve.
    // `to_der` encodes the ECDSA signature as ASN.1 SEQUENCE of integers R and S.
    macro_rules! sign_with {
        ($mod:ident, $sk:expr) => {{
            use $mod::ecdsa::signature::hazmat::PrehashSigner;
            let sig: $mod::ecdsa::Signature =
                $sk.sign_prehash(digest).map_err(|e| Error::SignFailure(e.to_string()))?;
            Ok(sig.to_der().as_bytes().to_vec())
        }};
    }
    match key {
        EcdsaSoftwareKey::P256(sk) => sign_with!(p256, sk),
        EcdsaSoftwareKey::P384(sk) => sign_with!(p384, sk),
        EcdsaSoftwareKey::P521(sk) => sign_with!(p521, sk),
    }
}

/// Parse an unencrypted PEM private key (PKCS#8 / PKCS#1 / SEC1).
///
/// # Errors
///
/// See [`parse_private_key_pem_with_password`].
pub fn parse_private_key_pem(key_pem: &[u8]) -> Result<Arc<dyn Signer>> {
    parse_private_key_pem_with_password(key_pem, None)
}

/// Parse a PEM private key.
///
/// `password` is accepted for API completeness, but encrypted-PEM decryption
/// is not implemented in v1 — encrypted blocks return
/// [`Error::EncryptedPemUnsupported`].
///
/// # Errors
///
/// [`Error::EncryptedPemUnsupported`], [`Error::UnableToDecodePrivateKey`],
/// or [`Error::FailedToParseKey`].
pub fn parse_private_key_pem_with_password(
    key_pem: &[u8],
    password: Option<&[u8]>,
) -> Result<Arc<dyn Signer>> {
    let der = get_private_key_der_from_pem(key_pem, password)?;
    parse_private_key_der(&der)
}

/// Extract DER bytes from PEM, skipping `EC PARAMETERS` blocks.
///
/// If a block has `Proc-Type` containing `ENCRYPTED`, returns
/// [`Error::EncryptedPemUnsupported`] (password decrypt deferred).
///
/// # Errors
///
/// Decode / encrypted / missing-key failures.
pub fn get_private_key_der_from_pem(in_pem: &[u8], _password: Option<&[u8]>) -> Result<Vec<u8>> {
    let blocks = parse_many(in_pem).map_err(|_| Error::UnableToDecodePrivateKey)?;
    for block in blocks {
        if block.tag() == "EC PARAMETERS" {
            continue;
        }
        if let Some(proc_type) = block.headers().get("Proc-Type")
            && proc_type.contains("ENCRYPTED")
        {
            return Err(Error::EncryptedPemUnsupported);
        }
        return Ok(block.contents().to_vec());
    }
    Err(Error::UnableToDecodePrivateKey)
}

/// Parse PKCS#8, PKCS#1 RSA, or SEC1 EC DER private key.
///
/// # Errors
///
/// Returns [`Error::FailedToParseKey`] if none of the formats match.
pub fn parse_private_key_der(key_der: &[u8]) -> Result<Arc<dyn Signer>> {
    // Each `if let Ok(...) = ...` below is one "try this format, keep going on
    // failure" attempt; macros collapse the per-curve repetition so the three
    // curve arms can't silently drift from each other.
    macro_rules! try_rsa {
        ($decode:ident) => {
            if let Ok(key) = RsaPrivateKey::$decode(key_der) {
                return Ok(Arc::new(SoftwareKey::Rsa(SoftwareRsaKey {
                    key,
                    id: String::new(),
                    label: String::new(),
                })));
            }
        };
    }
    macro_rules! try_ecdsa_pkcs8 {
        ($mod:ident, $curve:ident) => {{
            // Each curve crate's pkcs8 0.11 re-export.
            use $mod::pkcs8::DecodePrivateKey;
            if let Ok(key) = $mod::ecdsa::SigningKey::from_pkcs8_der(key_der) {
                return Ok(Arc::new(SoftwareKey::Ecdsa(SoftwareEcdsaKey {
                    key: EcdsaSoftwareKey::$curve(key),
                    id: String::new(),
                    label: String::new(),
                })));
            }
        }};
    }
    macro_rules! try_ecdsa_sec1 {
        ($mod:ident, $curve:ident) => {
            // SEC1 EC PRIVATE KEY (inherent methods on elliptic_curve::SecretKey).
            if let Ok(secret) = $mod::SecretKey::from_sec1_der(key_der) {
                let key = $mod::ecdsa::SigningKey::from(secret);
                return Ok(Arc::new(SoftwareKey::Ecdsa(SoftwareEcdsaKey {
                    key: EcdsaSoftwareKey::$curve(key),
                    id: String::new(),
                    label: String::new(),
                })));
            }
        };
    }

    // RSA PKCS#8 / PKCS#1 (rsa crate → pkcs8 0.10).
    try_rsa!(from_pkcs8_der);
    try_rsa!(from_pkcs1_der);

    try_ecdsa_pkcs8!(p256, P256);
    try_ecdsa_pkcs8!(p384, P384);
    try_ecdsa_pkcs8!(p521, P521);

    try_ecdsa_sec1!(p256, P256);
    try_ecdsa_sec1!(p384, P384);
    try_ecdsa_sec1!(p521, P521);

    Err(Error::FailedToParseKey)
}

/// Map integer purpose codes to [`trusty_cryptoprov_core::KeyPurpose`].
///
/// `1` = signing, `2` = encryption, otherwise undefined. Prefer constructing
/// [`trusty_cryptoprov_core::KeyPurpose`] directly in new code.
#[must_use]
pub fn key_purpose_from_int(purpose: i32) -> trusty_cryptoprov_core::KeyPurpose {
    trusty_cryptoprov_core::KeyPurpose::from_int(purpose)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPublicKey;
    use sha2::{Digest, Sha256 as Sha256Hash};
    use trusty_cryptoprov_core::KeyPurpose;

    #[test]
    fn key_purpose_from_int_mapping() {
        assert_eq!(KeyPurpose::from_int(1), KeyPurpose::Signing);
        assert_eq!(KeyPurpose::from_int(2), KeyPurpose::Encryption);
        assert_eq!(KeyPurpose::from_int(0), KeyPurpose::Undefined);
        assert_eq!(key_purpose_from_int(1), KeyPurpose::Signing);
    }

    #[test]
    fn encrypted_pem_rejected() {
        let pem = b"-----BEGIN RSA PRIVATE KEY-----\n\
Proc-Type: 4,ENCRYPTED\n\
DEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF\n\
\n\
AAAA\n\
-----END RSA PRIVATE KEY-----\n";
        let err = parse_private_key_pem(pem).unwrap_err();
        assert!(matches!(err, Error::EncryptedPemUnsupported));
    }

    #[test]
    fn skip_ec_parameters_block() {
        let pem = b"-----BEGIN EC PARAMETERS-----\n\
BggqhkjOPQMBBw==\n\
-----END EC PARAMETERS-----\n\
-----BEGIN EC PRIVATE KEY-----\n\
not-valid\n\
-----END EC PRIVATE KEY-----\n";
        let err = parse_private_key_pem(pem).unwrap_err();
        assert!(matches!(err, Error::FailedToParseKey | Error::UnableToDecodePrivateKey));
    }

    #[test]
    fn software_rsa_sign_pkcs1v15_sha256_verify() {
        let rsa_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pub_key = RsaPublicKey::from(&rsa_key);
        let key = SoftwareKey::Rsa(SoftwareRsaKey {
            key: rsa_key,
            id: "id-1".into(),
            label: "sign-rsa".into(),
        });
        assert_eq!(key.key_id(), Some("id-1"));
        assert_eq!(key.label(), Some("sign-rsa"));

        let digest = Sha256Hash::digest(b"hello cryptoprov");
        let scheme = RsaSignScheme::Pkcs1v15 { hash: DigestAlgorithm::Sha256 };
        let sig = key.sign_rsa(&digest, &scheme).unwrap();
        pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &sig).unwrap();

        let err = key.sign_ecdsa(&digest).unwrap_err();
        assert!(matches!(err, Error::UnsupportedKeyType));
    }

    #[test]
    fn software_ecdsa_p256_sign_verify() {
        use p256::elliptic_curve::Generate as _;
        let sk = p256::ecdsa::SigningKey::generate();
        let vk = *sk.verifying_key();
        let key = SoftwareKey::Ecdsa(SoftwareEcdsaKey {
            key: EcdsaSoftwareKey::P256(sk),
            id: String::new(),
            label: String::new(),
        });

        let digest = Sha256Hash::digest(b"hello ecdsa");
        let sig_der = key.sign_ecdsa(&digest).unwrap();
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        let sig = p256::ecdsa::Signature::from_der(&sig_der).unwrap();
        vk.verify_prehash(&digest, &sig).unwrap();

        let err = key
            .sign_rsa(&digest, &RsaSignScheme::Pkcs1v15 { hash: DigestAlgorithm::Sha256 })
            .unwrap_err();
        assert!(matches!(err, Error::UnsupportedKeyType));
    }
}
