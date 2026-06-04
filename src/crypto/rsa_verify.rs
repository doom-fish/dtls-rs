//! RSA signature verification via Security.framework.
//!
//! CryptoKit has no RSA, but WebRTC peers that present RSA certificates (for
//! example Firefox's historical default) still need their `ServerKeyExchange`
//! or `CertificateVerify` signatures verified. We hand the peer's leaf
//! certificate DER to `SecCertificateCreateWithData`, copy out its public
//! `SecKey`, and call `SecKeyVerifySignature` through the `security-rs` wrapper.
//! The `…Message…` algorithm constants hash the input internally, matching the
//! TLS 1.2 "sign over the raw transcript" convention.

use security::key::SignatureAlgorithm;
use security::Certificate;

use crate::error::{Error, Result};

/// The RSA signature schemes the WebRTC profile accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaScheme {
    /// `rsa_pkcs1_sha256` (TLS `SignatureAndHashAlgorithm` 0x0401).
    Pkcs1Sha256,
    /// `rsa_pss_rsae_sha256` (TLS `SignatureScheme` 0x0804).
    PssSha256,
}

/// Verify an RSA signature made by the key inside `leaf_cert_der`.
///
/// # Errors
///
/// Returns [`Error::BadSignature`] if the signature is invalid, or
/// [`Error::Security`] if Security.framework rejects the inputs.
pub fn verify_rsa(
    leaf_cert_der: &[u8],
    scheme: RsaScheme,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let certificate = Certificate::from_der(leaf_cert_der)?;
    let public_key = certificate.public_key()?;
    let algorithm = match scheme {
        RsaScheme::Pkcs1Sha256 => SignatureAlgorithm::RsaSignatureMessagePkcs1v15Sha256,
        RsaScheme::PssSha256 => SignatureAlgorithm::RsaSignatureMessagePssSha256,
    };
    if public_key.verify_signature(algorithm, message, signature)? {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}
