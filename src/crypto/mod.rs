//! Cryptographic primitives, all backed by Apple system frameworks.
//!
//! Symmetric and elliptic-curve operations come from CryptoKit through the
//! sibling `cryptokit-rs` crate; RSA verification and the CSPRNG come from
//! Security.framework through `security-rs`. No algorithm is implemented in
//! this crate from scratch except the TLS 1.2 PRF, which is a thin HMAC
//! construction.

pub mod aes_gcm;
pub mod ecdhe_p256;
pub mod ecdsa_sign;
pub mod ecdsa_verify;
pub mod hash;
pub mod hmac;
pub mod prf;
pub mod rsa_verify;

use crate::error::Result;

/// Fill `buf` with cryptographically secure random bytes (`SecRandomCopyBytes`).
///
/// # Errors
///
/// Returns [`crate::error::Error::Security`] if the system CSPRNG fails.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    security::SecureRandom::fill(buf)?;
    Ok(())
}

/// Return `len` cryptographically secure random bytes.
///
/// # Errors
///
/// Returns [`crate::error::Error::Security`] if the system CSPRNG fails.
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let bytes = security::SecureRandom::bytes(len)?;
    Ok(bytes)
}

#[allow(missing_docs)]
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    core::hint::black_box(diff) == 0
}
