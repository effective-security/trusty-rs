//! [`Signer`] implementation backed by a GCP Cloud KMS crypto key version.

use google_cloud_kms_v1::client::KeyManagementService;
use google_cloud_kms_v1::model::digest::Digest as DigestOneOf;
use google_cloud_kms_v1::model::{AsymmetricSignRequest, Digest};
use std::sync::Arc;
use tokio::runtime::Runtime;
use trusty_cryptoprov_core::{DigestAlgorithm, Error, PssSaltLen, Result, RsaSignScheme, Signer};

/// Key type + fixed signing algorithm, read from the crypto key version's
/// `algorithm` at generation/lookup time (GCP KMS binds the padding scheme
/// and hash to the key version itself — the caller's [`RsaSignScheme`] at
/// sign time is only validated against it, never used to pick an algorithm
/// for the wire request the way AWS KMS's `SigningAlgorithmSpec` is).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcpKeyKind {
    /// RSASSA-PKCS1-v1_5 with the given digest hash.
    RsaPkcs1(DigestAlgorithm),
    /// RSASSA-PSS with the given digest hash (salt length fixed to hash length by GCP).
    RsaPss(DigestAlgorithm),
    /// ECDSA (P-256 or P-384; GCP KMS has no P-521 asymmetric-sign algorithm).
    Ecdsa,
}

/// A GCP Cloud KMS-backed [`Signer`]. Every signing call round-trips to KMS.
pub struct GcpKmsSigner {
    key_id: String,
    label: String,
    kind: GcpKeyKind,
    version_name: String,
    client: KeyManagementService,
    rt: Arc<Runtime>,
}

impl GcpKmsSigner {
    pub(crate) fn new(
        key_id: String,
        label: String,
        kind: GcpKeyKind,
        version_name: String,
        client: KeyManagementService,
        rt: Arc<Runtime>,
    ) -> Self {
        Self { key_id, label, kind, version_name, client, rt }
    }

    async fn sign(&self, digest: &[u8]) -> Result<Vec<u8>> {
        let digest_oneof = match digest.len() {
            32 => DigestOneOf::Sha256(digest.to_vec().into()),
            48 => DigestOneOf::Sha384(digest.to_vec().into()),
            64 => DigestOneOf::Sha512(digest.to_vec().into()),
            n => return Err(Error::SignFailure(format!("unsupported digest length: {n}"))),
        };
        let digest_crc32c = i64::from(crc32c::crc32c(digest));

        let req = AsymmetricSignRequest::new()
            .set_name(&self.version_name)
            .set_digest(Digest::new().set_digest(Some(digest_oneof)))
            .set_digest_crc32c(digest_crc32c);

        let resp = self
            .client
            .asymmetric_sign()
            .with_request(req)
            .send()
            .await
            .map_err(|e| Error::SignFailure(e.to_string()))?;

        if !resp.verified_digest_crc32c {
            return Err(Error::SignFailure("request corrupted in-transit".to_string()));
        }
        let signature_crc32c =
            resp.signature_crc32c.as_ref().map(|v| *v).ok_or_else(|| {
                Error::SignFailure("response missing signature_crc32c".to_string())
            })?;
        if i64::from(crc32c::crc32c(&resp.signature)) != signature_crc32c {
            return Err(Error::SignFailure("response corrupted in-transit".to_string()));
        }

        Ok(resp.signature.to_vec())
    }
}

impl std::fmt::Debug for GcpKmsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpKmsSigner")
            .field("key_id", &self.key_id)
            .field("label", &self.label)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Signer for GcpKmsSigner {
    fn sign_rsa(&self, digest: &[u8], scheme: &RsaSignScheme) -> Result<Vec<u8>> {
        let hash = match scheme {
            RsaSignScheme::Pkcs1v15 { hash } => {
                if self.kind != GcpKeyKind::RsaPkcs1(*hash) {
                    return Err(Error::UnsupportedKeyType);
                }
                *hash
            }
            RsaSignScheme::Pss { hash, salt_len } => {
                if self.kind != GcpKeyKind::RsaPss(*hash) {
                    return Err(Error::UnsupportedKeyType);
                }
                if let PssSaltLen::Explicit(n) = salt_len
                    && *n != hash.digest_len()
                {
                    return Err(Error::SignFailure(
                        "GCP KMS RSA-PSS salt length is fixed to the hash length".to_string(),
                    ));
                }
                *hash
            }
        };
        if digest.len() != hash.digest_len() {
            return Err(Error::SignFailure(format!(
                "digest length {} does not match {hash:?}",
                digest.len()
            )));
        }
        self.rt.block_on(self.sign(digest))
    }

    fn sign_ecdsa(&self, digest: &[u8]) -> Result<Vec<u8>> {
        if self.kind != GcpKeyKind::Ecdsa {
            return Err(Error::UnsupportedKeyType);
        }
        self.rt.block_on(self.sign(digest))
    }

    fn key_id(&self) -> Option<&str> {
        if self.key_id.is_empty() { None } else { Some(&self.key_id) }
    }

    fn label(&self) -> Option<&str> {
        if self.label.is_empty() { None } else { Some(&self.label) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_len_validation_is_deterministic() {
        // Pure sanity check on the constants used above; the real
        // request/response path needs a live KMS client.
        assert_eq!(DigestAlgorithm::Sha256.digest_len(), 32);
        assert_eq!(DigestAlgorithm::Sha384.digest_len(), 48);
        assert_eq!(DigestAlgorithm::Sha512.digest_len(), 64);
    }
}
