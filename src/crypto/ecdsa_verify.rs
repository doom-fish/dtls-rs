//! ECDSA-P256 signature verification over CryptoKit.

use cryptokit::p256::{P256EcdsaSignature, P256SigningPublicKey};

use crate::error::{Error, Result};

/// Verify a DER-encoded ECDSA-P256 signature over `message`.
///
/// `public_point` is the peer key as an uncompressed point (`0x04 || X || Y`,
/// 65 bytes). `signature_der` is the DER `SEQUENCE { r, s }` taken verbatim from
/// the wire. Verification (like signing) hashes `message` with SHA-256.
///
/// # Errors
///
/// Returns [`Error::BadSignature`] if the signature is invalid and
/// [`Error::Crypto`] if the inputs are malformed.
pub fn verify_ecdsa_p256(
    public_point: &[u8],
    message: &[u8],
    signature_der: &[u8],
) -> Result<()> {
    let public = P256SigningPublicKey::from_x963_representation(public_point.to_vec())?;
    let signature = P256EcdsaSignature::from_der_representation(signature_der.to_vec())?;
    let valid = public.verify_signature(message, &signature)?;
    if valid {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}
