//! TLS/DTLS extensions used by the WebRTC profile.
//!
//! Every extension on the wire is `extension_type(2) || length(2) || data`. The
//! per-extension submodules build and parse the `data` payloads; this module
//! provides the [`Extension`] container and codecs for the extension block that
//! appears at the end of `ClientHello` / `ServerHello`.

pub mod ec_point_formats;
pub mod extended_master_secret;
pub mod renegotiation_info;
pub mod signature_algorithms;
pub mod supported_groups;
pub mod use_srtp;

use crate::error::{Error, Result};

/// Extension type code points.
pub mod ext_type {
    /// `supported_groups` (RFC 7919 / RFC 8422).
    pub const SUPPORTED_GROUPS: u16 = 10;
    /// `ec_point_formats`.
    pub const EC_POINT_FORMATS: u16 = 11;
    /// `signature_algorithms`.
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    /// `use_srtp` (RFC 5764).
    pub const USE_SRTP: u16 = 14;
    /// `extended_master_secret` (RFC 7627).
    pub const EXTENDED_MASTER_SECRET: u16 = 23;
    /// `renegotiation_info` (RFC 5746).
    pub const RENEGOTIATION_INFO: u16 = 0xFF01;
}

/// A single decoded extension.
#[derive(Debug, Clone)]
pub struct Extension {
    /// The extension type code point.
    pub extension_type: u16,
    /// The raw extension data (without the type/length prefix).
    pub data: Vec<u8>,
}

impl Extension {
    /// Construct an extension.
    #[must_use]
    pub fn new(extension_type: u16, data: Vec<u8>) -> Self {
        Self {
            extension_type,
            data,
        }
    }

    /// Append the encoded `type || length || data` form to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.extension_type.to_be_bytes());
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
    }
}

/// Encode a list of extensions as a length-prefixed block, or nothing if empty.
#[must_use]
pub fn encode_block(extensions: &[Extension]) -> Vec<u8> {
    let mut body = Vec::new();
    for extension in extensions {
        extension.encode_into(&mut body);
    }
    let mut out = Vec::with_capacity(body.len() + 2);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Decode an extensions block (the `length(2) || extensions...` form).
///
/// # Errors
///
/// Returns [`Error::Truncated`] / [`Error::Decode`] on malformed input.
pub fn decode_block(buf: &[u8]) -> Result<Vec<Extension>> {
    if buf.is_empty() {
        return Ok(Vec::new());
    }
    if buf.len() < 2 {
        return Err(Error::Truncated("extensions length"));
    }
    let total = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let body = buf
        .get(2..2 + total)
        .ok_or(Error::Truncated("extensions block"))?;
    if buf.len() != 2 + total {
        return Err(Error::Decode("trailing bytes after extensions block".to_owned()));
    }
    let mut extensions: Vec<Extension> = Vec::new();
    let mut pos = 0;
    while pos < body.len() {
        if pos + 4 > body.len() {
            return Err(Error::Truncated("extension header"));
        }
        let extension_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        let start = pos + 4;
        let data = body
            .get(start..start + len)
            .ok_or(Error::Truncated("extension data"))?
            .to_vec();
        if find(&extensions, extension_type).is_some() {
            return Err(Error::Decode(format!(
                "duplicate extension type {extension_type}"
            )));
        }
        extensions.push(Extension::new(extension_type, data));
        pos = start + len;
    }
    Ok(extensions)
}

/// Find the first extension of a given type.
#[must_use]
pub fn find(extensions: &[Extension], extension_type: u16) -> Option<&Extension> {
    extensions
        .iter()
        .find(|extension| extension.extension_type == extension_type)
}
