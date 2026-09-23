//! HMAC-SHA256 over CryptoKit.

use cryptokit::SymmetricKey;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Compute `HMAC-SHA256(key, message)`.
///
/// # Errors
///
/// Returns [`crate::error::Error::Crypto`] if the CryptoKit bridge rejects the
/// request.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let symmetric = SymmetricKey::from_bytes(key.to_vec());
    let mac = cryptokit::hmac_sha256(message, &symmetric)?;
    let mut out = Zeroizing::new([0u8; 32]);
    if mac.as_bytes().len() != out.len() {
        return Err(Error::Crypto("unexpected HMAC-SHA256 length".to_owned()));
    }
    out.copy_from_slice(mac.as_bytes());
    Ok(out)
}
