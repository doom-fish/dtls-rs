//! `supported_groups` extension (RFC 8422 §5.1.1).

use crate::error::{Error, Result};

use super::{ext_type, Extension};

/// NIST P-256 (`secp256r1`).
pub const SECP256R1: u16 = 0x0017;

/// Build a `supported_groups` extension listing `groups`.
#[must_use]
pub fn build(groups: &[u16]) -> Extension {
    let mut data = Vec::new();
    data.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for group in groups {
        data.extend_from_slice(&group.to_be_bytes());
    }
    Extension::new(ext_type::SUPPORTED_GROUPS, data)
}

/// Parse the list of named groups.
///
/// # Errors
///
/// Returns an error if the extension data is malformed.
pub fn parse(data: &[u8]) -> Result<Vec<u16>> {
    if data.len() < 2 {
        return Err(Error::Truncated("supported_groups length"));
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let body = data
        .get(2..2 + len)
        .ok_or(Error::Truncated("supported_groups list"))?;
    if len % 2 != 0 || data.len() != 2 + len {
        return Err(Error::Decode("malformed supported_groups list".to_owned()));
    }
    Ok(body
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect())
}
