//! RFC 5705 keying-material exporter, used by WebRTC to derive SRTP keys
//! (RFC 5764, label `EXTRACTOR-dtls_srtp`).

use std::fmt;
use std::ops::Deref;

use zeroize::Zeroizing;

use crate::crypto::constant_time_eq;
use crate::crypto::prf::prf_sha256;
use crate::error::Error;

/// The DTLS-SRTP exporter label.
pub const DTLS_SRTP_LABEL: &[u8] = b"EXTRACTOR-dtls_srtp";

#[allow(missing_docs)]
pub struct ExportedKeyingMaterial(Zeroizing<Vec<u8>>);

impl Deref for ExportedKeyingMaterial {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for ExportedKeyingMaterial {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq for ExportedKeyingMaterial {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl Eq for ExportedKeyingMaterial {}

impl fmt::Debug for ExportedKeyingMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExportedKeyingMaterial([REDACTED; {} bytes])", self.0.len())
    }
}

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
) -> crate::error::Result<ExportedKeyingMaterial> {
    let mut seed = Vec::with_capacity(64 + context.map_or(0, |c| c.len() + 2));
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    if let Some(context) = context {
        let context_len = u16::try_from(context.len())
            .map_err(|_| Error::InvalidArgument("exporter context longer than 65535 bytes"))?;
        seed.extend_from_slice(&context_len.to_be_bytes());
        seed.extend_from_slice(context);
    }
    prf_sha256(master_secret, label, &seed, length).map(ExportedKeyingMaterial)
}
