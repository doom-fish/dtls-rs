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

use zeroize::Zeroizing;

use crate::crypto::hmac::hmac_sha256;
use crate::error::{Error, Result};

#[allow(missing_docs)]
pub const MAX_OUTPUT_LEN: usize = 16 * 1024;

/// Evaluate `P_SHA256(secret, seed)` and return `length` bytes.
fn p_sha256(secret: &[u8], seed: &[u8], length: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(length));
    // A(1) = HMAC(secret, seed)
    let mut a = hmac_sha256(secret, seed)?;
    let mut input = Zeroizing::new(Vec::with_capacity(a.len() + seed.len()));
    while out.len() < length {
        // HMAC(secret, A(i) || seed)
        input.clear();
        input.extend_from_slice(a.as_slice());
        input.extend_from_slice(seed);
        let block = hmac_sha256(secret, &input)?;
        let take = block.len().min(length - out.len());
        out.extend_from_slice(&block[..take]);
        // A(i+1) = HMAC(secret, A(i))
        a = hmac_sha256(secret, a.as_slice())?;
    }
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
pub fn prf_sha256(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    if length > MAX_OUTPUT_LEN {
        return Err(Error::InvalidArgument("PRF output length exceeds MAX_OUTPUT_LEN"));
    }
    let mut label_and_seed = Zeroizing::new(Vec::with_capacity(label.len() + seed.len()));
    label_and_seed.extend_from_slice(label);
    label_and_seed.extend_from_slice(seed);
    p_sha256(secret, &label_and_seed, length)
}
