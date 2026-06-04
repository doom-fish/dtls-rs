//! RFC 5705 keying-material exporter, used by WebRTC to derive SRTP keys
//! (RFC 5764, label `EXTRACTOR-dtls_srtp`).

use crate::crypto::prf::prf_sha256;

/// The DTLS-SRTP exporter label.
pub const DTLS_SRTP_LABEL: &[u8] = b"EXTRACTOR-dtls_srtp";

/// Export `length` bytes of keying material per RFC 5705.
///
/// The seed is `client_random || server_random`, optionally followed by a
/// 16-bit length-prefixed `context`. DTLS-SRTP uses no context.
///
/// # Errors
///
/// Returns an error if the PRF fails.
pub fn export_keying_material(
    master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    label: &[u8],
    context: Option<&[u8]>,
    length: usize,
) -> crate::error::Result<Vec<u8>> {
    let mut seed = Vec::with_capacity(64 + context.map_or(0, |c| c.len() + 2));
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    if let Some(context) = context {
        seed.extend_from_slice(&(context.len() as u16).to_be_bytes());
        seed.extend_from_slice(context);
    }
    prf_sha256(master_secret, label, &seed, length)
}
