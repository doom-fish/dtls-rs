//! SHA-256 over CryptoKit.

use crate::error::Result;

/// Compute the SHA-256 digest of `data`.
///
/// # Errors
///
/// Returns [`crate::error::Error::Crypto`] if the CryptoKit bridge rejects the
/// request.
pub fn sha256(data: &[u8]) -> Result<[u8; 32]> {
    let digest = cryptokit::sha256(data)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}
