//! SHA-256 over CryptoKit.

use crate::error::{Error, Result};

/// Compute the SHA-256 digest of `data`.
///
/// # Errors
///
/// Returns [`crate::error::Error::Crypto`] if the CryptoKit bridge rejects the
/// request.
pub fn sha256(data: &[u8]) -> Result<[u8; 32]> {
    let digest = cryptokit::sha256(data)?;
    digest
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("unexpected SHA-256 digest length".to_owned()))
}
