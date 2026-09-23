//! Ephemeral ECDHE on NIST P-256 via CryptoKit key agreement.
//!
//! The TLS wire format for an ECDHE public value is an uncompressed EC point
//! `0x04 || X || Y` (65 bytes for P-256). CryptoKit's *raw representation* for a
//! key-agreement public key is the bare `X || Y` (64 bytes), so we translate
//! between the two here. The agreed premaster secret is the 32-byte X
//! coordinate of the shared point.

use cryptokit::p256::{P256KeyAgreementPrivateKey, P256KeyAgreementPublicKey};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Length of an uncompressed P-256 point on the wire (`0x04 || X || Y`).
pub const UNCOMPRESSED_POINT_LEN: usize = 65;

/// An ephemeral P-256 key-agreement keypair.
pub struct EcdheKeyPair {
    private: P256KeyAgreementPrivateKey,
    public_point: [u8; UNCOMPRESSED_POINT_LEN],
}

impl EcdheKeyPair {
    /// Generate a fresh ephemeral keypair.
    ///
    /// # Errors
    ///
    /// Returns an error if CryptoKit key generation fails.
    pub fn generate() -> Result<Self> {
        let private = P256KeyAgreementPrivateKey::generate()?;
        let raw = private.public_key()?.into_raw_representation();
        if raw.len() != 64 {
            return Err(Error::Crypto(format!(
                "unexpected P-256 raw public key length {}",
                raw.len()
            )));
        }
        let mut point = [0u8; UNCOMPRESSED_POINT_LEN];
        point[0] = 0x04;
        point[1..].copy_from_slice(&raw);
        Ok(Self {
            private,
            public_point: point,
        })
    }

    /// The local public value in TLS uncompressed-point form.
    #[must_use]
    pub fn public_point(&self) -> &[u8; UNCOMPRESSED_POINT_LEN] {
        &self.public_point
    }

    /// Compute the premaster secret (the 32-byte X coordinate) against the
    /// peer's uncompressed-point public value.
    ///
    /// # Errors
    ///
    /// Returns an error if the point is malformed or key agreement fails.
    pub fn agree(&self, peer_point: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let raw = uncompressed_point_to_raw(peer_point)?;
        let peer = P256KeyAgreementPublicKey::from_raw_representation(raw)?;
        let secret = self.private.shared_secret(&peer)?;
        Ok(secret.hazmat_raw_bytes())
    }
}

/// Convert a TLS uncompressed point (`0x04 || X || Y`) into the CryptoKit raw
/// representation (`X || Y`).
fn uncompressed_point_to_raw(point: &[u8]) -> Result<Vec<u8>> {
    if point.len() != UNCOMPRESSED_POINT_LEN {
        return Err(Error::Decode(format!(
            "ECDHE point must be {UNCOMPRESSED_POINT_LEN} bytes, got {}",
            point.len()
        )));
    }
    if point[0] != 0x04 {
        return Err(Error::Decode(
            "ECDHE point is not in uncompressed form".to_owned(),
        ));
    }
    Ok(point[1..].to_vec())
}
