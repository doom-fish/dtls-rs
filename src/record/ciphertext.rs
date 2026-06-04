//! AEAD record protection for `TLS_*_WITH_AES_128_GCM_SHA256`.
//!
//! The protected fragment is `explicit_nonce(8) || ciphertext || tag(16)`. The
//! GCM nonce is `salt(4) || explicit_nonce(8)`; we use the record's
//! `epoch || sequence` as the explicit nonce. The additional authenticated data
//! is the DTLS variant of RFC 5246 §6.2.3.3:
//! `seq_num(8) || type(1) || version(2) || length(2)` where `seq_num` is
//! `epoch(2) || sequence(6)` and `length` is the plaintext length.

use crate::crypto::aes_gcm;
use crate::error::{Error, Result};

/// One direction's AES-128-GCM key material.
#[derive(Debug, Clone)]
pub struct AeadKeys {
    /// 16-byte AES key.
    pub key: [u8; 16],
    /// 4-byte implicit nonce salt.
    pub salt: [u8; 4],
}

/// Encode `epoch || sequence` as the 8-byte AEAD sequence number / nonce.
#[must_use]
pub fn seq_num_bytes(epoch: u16, sequence: u64) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..2].copy_from_slice(&epoch.to_be_bytes());
    out[2..].copy_from_slice(&sequence.to_be_bytes()[2..]);
    out
}

fn aad(epoch: u16, sequence: u64, content_type: u8, version: u16, plaintext_len: usize) -> [u8; 13] {
    let seq = seq_num_bytes(epoch, sequence);
    let mut out = [0u8; 13];
    out[..8].copy_from_slice(&seq);
    out[8] = content_type;
    out[9..11].copy_from_slice(&version.to_be_bytes());
    out[11..13].copy_from_slice(&(plaintext_len as u16).to_be_bytes());
    out
}

/// Protect `plaintext`, returning the record fragment to put on the wire.
///
/// # Errors
///
/// Returns an error if the AEAD seal fails.
pub fn protect(
    keys: &AeadKeys,
    epoch: u16,
    sequence: u64,
    content_type: u8,
    version: u16,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let explicit = seq_num_bytes(epoch, sequence);
    let aad = aad(epoch, sequence, content_type, version, plaintext.len());
    let sealed = aes_gcm::seal(&keys.key, &keys.salt, &explicit, plaintext, &aad)?;
    let mut fragment = Vec::with_capacity(explicit.len() + sealed.len());
    fragment.extend_from_slice(&explicit);
    fragment.extend_from_slice(&sealed);
    Ok(fragment)
}

/// Unprotect a record fragment, returning the plaintext.
///
/// # Errors
///
/// Returns [`Error::BadRecordMac`] if authentication fails, or
/// [`Error::Truncated`] if the fragment is too short to hold a nonce and tag.
pub fn unprotect(
    keys: &AeadKeys,
    epoch: u16,
    sequence: u64,
    content_type: u8,
    version: u16,
    fragment: &[u8],
) -> Result<Vec<u8>> {
    if fragment.len() < aes_gcm::EXPLICIT_NONCE_LEN + aes_gcm::TAG_LEN {
        return Err(Error::Truncated("AEAD record fragment"));
    }
    let (explicit_slice, ciphertext_and_tag) = fragment.split_at(aes_gcm::EXPLICIT_NONCE_LEN);
    let mut explicit = [0u8; aes_gcm::EXPLICIT_NONCE_LEN];
    explicit.copy_from_slice(explicit_slice);
    let plaintext_len = ciphertext_and_tag.len() - aes_gcm::TAG_LEN;
    let aad = aad(epoch, sequence, content_type, version, plaintext_len);
    aes_gcm::open(&keys.key, &keys.salt, &explicit, ciphertext_and_tag, &aad)
}
