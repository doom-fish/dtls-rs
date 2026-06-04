//! AES-128-GCM record protection over CryptoKit (RFC 5288 / RFC 5246 §6.2.3.3).
//!
//! TLS 1.2 GCM uses a 12-byte nonce formed from a 4-byte implicit salt (taken
//! from the key block) and an 8-byte explicit nonce carried in each record.
//! CryptoKit's AES-GCM seal returns a combined `nonce || ciphertext || tag`
//! box; we always pass an explicit 12-byte nonce and strip the nonce prefix so
//! the caller deals only with `ciphertext || tag`.

use cryptokit::aes_gcm::{AesGcm, AesGcmNonce, AesGcmSealedBox};
use cryptokit::SymmetricKey;

use crate::error::{Error, Result};

/// AES-GCM authentication tag length.
pub const TAG_LEN: usize = 16;
/// Length of the explicit per-record nonce.
pub const EXPLICIT_NONCE_LEN: usize = 8;
/// Length of the implicit per-key salt.
pub const SALT_LEN: usize = 4;

fn build_nonce(salt: &[u8; SALT_LEN], explicit: &[u8; EXPLICIT_NONCE_LEN]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..SALT_LEN].copy_from_slice(salt);
    nonce[SALT_LEN..].copy_from_slice(explicit);
    nonce
}

/// Seal `plaintext` and return `ciphertext || tag`.
///
/// # Errors
///
/// Returns an error if the CryptoKit bridge rejects the request.
pub fn seal(
    key: &[u8; 16],
    salt: &[u8; SALT_LEN],
    explicit_nonce: &[u8; EXPLICIT_NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let symmetric = SymmetricKey::from_bytes(key.to_vec());
    let nonce = build_nonce(salt, explicit_nonce);
    let sealed = AesGcm::seal_with_aad(plaintext, &symmetric, Some(&nonce), aad)?;
    let combined = sealed.into_combined();
    // Combined is nonce(12) || ciphertext || tag; drop the nonce prefix.
    Ok(combined[12..].to_vec())
}

/// Open `ciphertext || tag` and return the plaintext.
///
/// # Errors
///
/// Returns [`Error::BadRecordMac`] if authentication fails.
pub fn open(
    key: &[u8; 16],
    salt: &[u8; SALT_LEN],
    explicit_nonce: &[u8; EXPLICIT_NONCE_LEN],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext_and_tag.len() < TAG_LEN {
        return Err(Error::Truncated("AES-GCM ciphertext"));
    }
    let symmetric = SymmetricKey::from_bytes(key.to_vec());
    let nonce = build_nonce(salt, explicit_nonce);
    let nonce_value = AesGcmNonce::from_bytes(nonce.to_vec())?;
    let split = ciphertext_and_tag.len() - TAG_LEN;
    let (ciphertext, tag) = ciphertext_and_tag.split_at(split);
    let sealed = AesGcmSealedBox::from_parts(&nonce_value, ciphertext, tag)?;
    AesGcm::open_with_aad(&sealed, &symmetric, aad).map_err(|_| Error::BadRecordMac)
}
