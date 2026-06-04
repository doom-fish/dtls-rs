//! The TLS 1.2 pseudo-random function (RFC 5246 §5).
//!
//! TLS 1.2 defines `PRF(secret, label, seed) = P_<hash>(secret, label || seed)`
//! and for every cipher suite in the WebRTC profile the hash is SHA-256, so we
//! only implement the SHA-256 variant.
//!
//! ```text
//! P_hash(secret, seed) = HMAC(secret, A(1) || seed) ||
//!                        HMAC(secret, A(2) || seed) || ...
//! A(0) = seed
//! A(i) = HMAC(secret, A(i-1))
//! ```

use crate::crypto::hmac::hmac_sha256;
use crate::error::Result;

/// Evaluate `P_SHA256(secret, seed)` and return `length` bytes.
fn p_sha256(secret: &[u8], seed: &[u8], length: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(length);
    // A(1) = HMAC(secret, seed)
    let mut a = hmac_sha256(secret, seed)?;
    while out.len() < length {
        // HMAC(secret, A(i) || seed)
        let mut input = Vec::with_capacity(a.len() + seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(seed);
        let block = hmac_sha256(secret, &input)?;
        out.extend_from_slice(&block);
        // A(i+1) = HMAC(secret, A(i))
        a = hmac_sha256(secret, &a)?;
    }
    out.truncate(length);
    Ok(out)
}

/// The TLS 1.2 PRF with SHA-256.
///
/// `seed` is the concatenation of any per-call seed material that follows the
/// label (for example the two `Hello.random` values).
///
/// # Errors
///
/// Returns [`crate::error::Error::Crypto`] if an underlying HMAC fails.
pub fn prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], length: usize) -> Result<Vec<u8>> {
    let mut label_and_seed = Vec::with_capacity(label.len() + seed.len());
    label_and_seed.extend_from_slice(label);
    label_and_seed.extend_from_slice(seed);
    p_sha256(secret, &label_and_seed, length)
}
