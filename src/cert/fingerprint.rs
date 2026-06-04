//! Certificate fingerprints (the WebRTC trust anchor).
//!
//! WebRTC carries the SHA-256 hash of the peer certificate's DER in the SDP
//! `a=fingerprint` line. Both sides compute this hash over the leaf certificate
//! and compare it to the value exchanged out of band.

use crate::crypto::hash::sha256;
use crate::error::Result;

/// Compute the SHA-256 fingerprint over a certificate's DER encoding.
///
/// # Errors
///
/// Returns an error if the CryptoKit hash fails.
pub fn sha256_fingerprint(cert_der: &[u8]) -> Result<[u8; 32]> {
    sha256(cert_der)
}

/// Format a fingerprint as the colon-separated upper-case hex used in SDP.
#[must_use]
pub fn format_colon_hex(fingerprint: &[u8]) -> String {
    fingerprint
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}
