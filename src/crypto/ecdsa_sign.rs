//! ECDSA-P256 signing over CryptoKit.
//!
//! CryptoKit's `P256.Signing` always hashes its input with SHA-256 before
//! signing, which is exactly the `ecdsa_secp256r1_sha256` scheme TLS 1.2 uses,
//! so we feed the to-be-signed bytes directly. CryptoKit returns the raw
//! `r || s` representation; TLS carries the DER `SEQUENCE { r, s }` form, so we
//! convert on the way out.

use cryptokit::p256::{P256EcdsaSignature, P256SigningPrivateKey};

use crate::error::{Error, Result};

/// An ECDSA-P256 signing key used both to self-sign our certificate and to sign
/// `ServerKeyExchange` / `CertificateVerify`.
pub struct EcdsaSigningKey {
    private: P256SigningPrivateKey,
    spki_point: Vec<u8>,
}

impl EcdsaSigningKey {
    /// Generate a fresh signing keypair.
    ///
    /// # Errors
    ///
    /// Returns an error if CryptoKit key generation fails.
    pub fn generate() -> Result<Self> {
        let private = P256SigningPrivateKey::generate()?;
        let spki_point = private.public_key()?.x963_representation()?;
        Ok(Self {
            private,
            spki_point,
        })
    }

    /// The public key as an uncompressed point (`0x04 || X || Y`, 65 bytes) for
    /// embedding in a `SubjectPublicKeyInfo`.
    #[must_use]
    pub fn public_point(&self) -> &[u8] {
        &self.spki_point
    }

    /// Sign `message` and return a DER-encoded ECDSA signature.
    ///
    /// # Errors
    ///
    /// Returns an error if signing or DER conversion fails.
    pub fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>> {
        let raw = self.private.sign(message)?;
        let signature = P256EcdsaSignature::from_raw_representation(raw)?;
        signature.der_representation().map_err(Error::from)
    }
}
