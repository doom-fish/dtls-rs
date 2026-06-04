//! `use_srtp` extension (RFC 5764 §4.1.1).

use crate::error::{Error, Result};

use super::{ext_type, Extension};

/// `SRTP_AEAD_AES_128_GCM`.
pub const SRTP_AEAD_AES_128_GCM: u16 = 0x0007;
/// `SRTP_AEAD_AES_256_GCM`.
pub const SRTP_AEAD_AES_256_GCM: u16 = 0x0008;

/// Build a `use_srtp` extension offering `profiles` with an empty MKI.
#[must_use]
pub fn build(profiles: &[u16]) -> Extension {
    let mut data = Vec::new();
    data.extend_from_slice(&((profiles.len() * 2) as u16).to_be_bytes());
    for profile in profiles {
        data.extend_from_slice(&profile.to_be_bytes());
    }
    data.push(0); // empty srtp_mki
    Extension::new(ext_type::USE_SRTP, data)
}

/// Parse the list of offered SRTP protection profiles.
///
/// # Errors
///
/// Returns an error if the extension data is malformed.
pub fn parse_profiles(data: &[u8]) -> Result<Vec<u16>> {
    if data.len() < 2 {
        return Err(Error::Truncated("use_srtp profiles length"));
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if len % 2 != 0 {
        return Err(Error::Decode("use_srtp profiles length not even".to_owned()));
    }
    let body = data
        .get(2..2 + len)
        .ok_or(Error::Truncated("use_srtp profiles"))?;
    let mut profiles = Vec::with_capacity(len / 2);
    for chunk in body.chunks_exact(2) {
        profiles.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    Ok(profiles)
}
