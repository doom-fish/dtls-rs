//! `signature_algorithms` extension (RFC 5246 §7.4.1.4.1 / RFC 8446 codepoints).

use crate::error::{Error, Result};

use super::{ext_type, Extension};

/// `ecdsa_secp256r1_sha256`.
pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
/// `rsa_pss_rsae_sha256`.
pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
/// `rsa_pkcs1_sha256`.
pub const RSA_PKCS1_SHA256: u16 = 0x0401;

/// Build a `signature_algorithms` extension listing `schemes`.
#[must_use]
pub fn build(schemes: &[u16]) -> Extension {
    let mut data = Vec::new();
    data.extend_from_slice(&((schemes.len() * 2) as u16).to_be_bytes());
    for scheme in schemes {
        data.extend_from_slice(&scheme.to_be_bytes());
    }
    Extension::new(ext_type::SIGNATURE_ALGORITHMS, data)
}

#[allow(missing_docs)]
pub fn parse(data: &[u8]) -> Result<Vec<u16>> {
    if data.len() < 2 {
        return Err(Error::Truncated("signature_algorithms length"));
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if len % 2 != 0 || data.len() != 2 + len {
        return Err(Error::Decode("malformed signature_algorithms list".to_owned()));
    }
    Ok(data[2..]
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect())
}
