//! [`Signer`] implementation backed by an AWS KMS key.

use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use std::sync::Arc;
use tokio::runtime::Runtime;
use trusty_cryptoprov_core::{DigestAlgorithm, Error, PssSaltLen, Result, RsaSignScheme, Signer};

/// Key type recorded at generation/lookup time so [`AwsKmsSigner`] knows
/// which trait method (`sign_rsa` vs `sign_ecdsa`) is valid, without needing
/// to parse the key's public key material (AWS KMS's `DescribeKey` already
/// reports `KeySpec`, which is all that's needed to classify the key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwsKeyKind {
    /// RSA key (2048 / 3072 / 4096).
    Rsa,
    /// ECDSA key (P-256 / P-384 / P-521).
    Ecdsa,
}

/// A KMS-backed [`Signer`]. Every signing call round-trips to AWS KMS.
pub struct AwsKmsSigner {
    key_id: String,
    label: String,
    kind: AwsKeyKind,
    client: aws_sdk_kms::Client,
    rt: Arc<Runtime>,
}

impl AwsKmsSigner {
    pub(crate) fn new(
        key_id: String,
        label: String,
        kind: AwsKeyKind,
        client: aws_sdk_kms::Client,
        rt: Arc<Runtime>,
    ) -> Self {
        Self { key_id, label, kind, client, rt }
    }

    async fn sign(&self, digest: &[u8], algorithm: SigningAlgorithmSpec) -> Result<Vec<u8>> {
        let resp = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(digest.to_vec()))
            .message_type(MessageType::Digest)
            .signing_algorithm(algorithm)
            .send()
            .await
            .map_err(|e| Error::SignFailure(e.to_string()))?;
        Ok(resp.signature.map(Blob::into_inner).unwrap_or_default())
    }
}

impl std::fmt::Debug for AwsKmsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsSigner")
            .field("key_id", &self.key_id)
            .field("label", &self.label)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Signer for AwsKmsSigner {
    fn sign_rsa(&self, digest: &[u8], scheme: &RsaSignScheme) -> Result<Vec<u8>> {
        if self.kind != AwsKeyKind::Rsa {
            return Err(Error::UnsupportedKeyType);
        }
        let algorithm = rsa_signing_algorithm(scheme)?;
        self.rt.block_on(self.sign(digest, algorithm))
    }

    fn sign_ecdsa(&self, digest: &[u8]) -> Result<Vec<u8>> {
        if self.kind != AwsKeyKind::Ecdsa {
            return Err(Error::UnsupportedKeyType);
        }
        // AWS KMS's ECDSA algorithms are hash-size-specific and `sign_ecdsa`
        // receives no explicit hash, so the digest length is the only
        // available signal (32/48/64 bytes -> SHA-256/384/512).
        let algorithm = match digest.len() {
            32 => SigningAlgorithmSpec::EcdsaSha256,
            48 => SigningAlgorithmSpec::EcdsaSha384,
            64 => SigningAlgorithmSpec::EcdsaSha512,
            n => return Err(Error::SignFailure(format!("unsupported ECDSA digest length: {n}"))),
        };
        self.rt.block_on(self.sign(digest, algorithm))
    }

    fn key_id(&self) -> Option<&str> {
        if self.key_id.is_empty() { None } else { Some(&self.key_id) }
    }

    fn label(&self) -> Option<&str> {
        if self.label.is_empty() { None } else { Some(&self.label) }
    }
}

fn rsa_signing_algorithm(scheme: &RsaSignScheme) -> Result<SigningAlgorithmSpec> {
    let hash = match scheme {
        RsaSignScheme::Pkcs1v15 { hash } => *hash,
        RsaSignScheme::Pss { hash, .. } => *hash,
    };
    let is_pss = matches!(scheme, RsaSignScheme::Pss { .. });
    // AWS KMS only defines RSA signing algorithms for SHA-256/384/512; PSS
    // salt length is fixed to the hash length server-side, so an explicit
    // `PssSaltLen::Explicit` that disagrees can't be honored.
    if let RsaSignScheme::Pss { hash, salt_len: PssSaltLen::Explicit(n) } = scheme
        && *n != hash.digest_len()
    {
        return Err(Error::SignFailure(
            "AWS KMS RSA-PSS salt length is fixed to the hash length".to_string(),
        ));
    }
    match (hash, is_pss) {
        (DigestAlgorithm::Sha256, false) => Ok(SigningAlgorithmSpec::RsassaPkcs1V15Sha256),
        (DigestAlgorithm::Sha384, false) => Ok(SigningAlgorithmSpec::RsassaPkcs1V15Sha384),
        (DigestAlgorithm::Sha512, false) => Ok(SigningAlgorithmSpec::RsassaPkcs1V15Sha512),
        (DigestAlgorithm::Sha256, true) => Ok(SigningAlgorithmSpec::RsassaPssSha256),
        (DigestAlgorithm::Sha384, true) => Ok(SigningAlgorithmSpec::RsassaPssSha384),
        (DigestAlgorithm::Sha512, true) => Ok(SigningAlgorithmSpec::RsassaPssSha512),
        (hash, _) => Err(Error::SignFailure(format!("unsupported hash for AWS KMS: {hash:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_signing_algorithm_mapping() {
        assert_eq!(
            rsa_signing_algorithm(&RsaSignScheme::Pkcs1v15 { hash: DigestAlgorithm::Sha256 })
                .unwrap(),
            SigningAlgorithmSpec::RsassaPkcs1V15Sha256
        );
        assert_eq!(
            rsa_signing_algorithm(&RsaSignScheme::Pss {
                hash: DigestAlgorithm::Sha384,
                salt_len: PssSaltLen::EqualsHash
            })
            .unwrap(),
            SigningAlgorithmSpec::RsassaPssSha384
        );
        assert!(
            rsa_signing_algorithm(&RsaSignScheme::Pkcs1v15 { hash: DigestAlgorithm::Sha1 })
                .is_err()
        );
        assert!(
            rsa_signing_algorithm(&RsaSignScheme::Pss {
                hash: DigestAlgorithm::Sha256,
                salt_len: PssSaltLen::Explicit(16)
            })
            .is_err()
        );
    }
}
