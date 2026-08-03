//! AES-GCM encrypt/decrypt with nonce prepended.

use aes::Aes192;
use aes_gcm::aead::{Aead, KeyInit, consts::U12};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use trusty_cryptoprov_core::{Error, Result};

/// AES-192-GCM (same nonce size as AES-128/256-GCM).
type Aes192Gcm = AesGcm<Aes192, U12>;

/// Encrypt `plaintext` with AES-GCM; returns `nonce || ciphertext+tag`.
///
/// Key must be 16, 24, or 32 bytes. Nonce is 12 random bytes from the OS CSPRNG.
///
/// # Errors
///
/// [`Error::InvalidAesKeyLength`] or encryption failures.
pub fn gcm_encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    match key.len() {
        16 => seal::<Aes128Gcm>(plaintext, key),
        24 => seal::<Aes192Gcm>(plaintext, key),
        32 => seal::<Aes256Gcm>(plaintext, key),
        n => Err(Error::InvalidAesKeyLength(n)),
    }
}

/// Decrypt ciphertext produced by [`gcm_encrypt`].
///
/// # Errors
///
/// [`Error::InvalidAesKeyLength`], [`Error::CiphertextTooShort`], or
/// [`Error::GcmAuthFailure`].
pub fn gcm_decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    match key.len() {
        16 => open::<Aes128Gcm>(ciphertext, key),
        24 => open::<Aes192Gcm>(ciphertext, key),
        32 => open::<Aes256Gcm>(ciphertext, key),
        n => Err(Error::InvalidAesKeyLength(n)),
    }
}

fn seal<A>(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>>
where
    A: KeyInit + Aead,
{
    use aes::cipher::typenum::Unsigned;
    use aes_gcm::aead::Generate;

    let cipher = A::new_from_slice(key).map_err(|_| Error::InvalidAesKeyLength(key.len()))?;
    // aead 0.6: `Nonce<A>` is `Array<u8, A::NonceSize>`; `Generate` fills it from OS CSPRNG.
    let nonce = aes_gcm::aead::Nonce::<A>::generate();
    let mut out = nonce.to_vec();
    debug_assert_eq!(out.len(), A::NonceSize::to_usize());
    let ct = cipher.encrypt(&nonce, plaintext).map_err(|_| Error::GcmEncryptFailure)?;
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open<A>(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>>
where
    A: KeyInit + Aead,
{
    use aes::cipher::typenum::Unsigned;

    let cipher = A::new_from_slice(key).map_err(|_| Error::InvalidAesKeyLength(key.len()))?;
    let nonce_size = A::NonceSize::to_usize();
    if ciphertext.len() < nonce_size {
        return Err(Error::CiphertextTooShort);
    }
    let (nonce_bytes, ct) = ciphertext.split_at(nonce_size);
    let nonce =
        aes_gcm::aead::Nonce::<A>::try_from(nonce_bytes).map_err(|_| Error::GcmAuthFailure)?;
    cipher.decrypt(&nonce, ct).map_err(|_| Error::GcmAuthFailure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_key_fails() {
        let err = gcm_encrypt(b"data to protect", &[0u8; 15]).unwrap_err();
        assert!(matches!(err, Error::InvalidAesKeyLength(15)));
    }

    #[test]
    fn round_trip_and_tamper() {
        let plain = b"data to protect";
        let mut key = [0u8; 32];
        // rand 0.10: `thread_rng()` renamed to `rng()`; `fill_bytes` lives on `Rng`.
        use rand::Rng;
        rand::rng().fill_bytes(&mut key);

        let encrypted = gcm_encrypt(plain, &key).unwrap();
        let decrypted = gcm_decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plain);

        assert!(gcm_decrypt(&encrypted[1..], &key).is_err());
        let mut wrong = key;
        wrong[0] ^= 1;
        assert!(gcm_decrypt(&encrypted, &wrong).is_err());
        assert!(matches!(
            gcm_decrypt(&encrypted[..2], &key).unwrap_err(),
            Error::CiphertextTooShort
        ));
    }
}
