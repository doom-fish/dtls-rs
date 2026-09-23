//! HMAC-SHA256 over CryptoKit.

use cryptokit::SymmetricKey;

use crate::error::Result;

/// Compute `HMAC-SHA256(key, message)`.
///
/// # Errors
///
/// Returns [`crate::error::Error::Crypto`] if the CryptoKit bridge rejects the
/// request.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; 32]> {
    let symmetric = SymmetricKey::from_bytes(key.to_vec());
    let mac = cryptokit::hmac_sha256(message, &symmetric)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(mac.as_bytes());
    Ok(out)
}
