//! `ec_point_formats` extension (RFC 8422 §5.1.2).

use crate::error::{Error, Result};

use super::{ext_type, Extension};

/// Uncompressed point format.
pub const UNCOMPRESSED: u8 = 0;

/// Build an `ec_point_formats` extension listing `formats`.
#[must_use]
pub fn build(formats: &[u8]) -> Extension {
    let mut data = Vec::with_capacity(formats.len() + 1);
    data.push(formats.len() as u8);
    data.extend_from_slice(formats);
    Extension::new(ext_type::EC_POINT_FORMATS, data)
}

#[allow(missing_docs)]
pub fn parse(data: &[u8]) -> Result<Vec<u8>> {
    let (&len, formats) = data
        .split_first()
        .ok_or(Error::Truncated("ec_point_formats length"))?;
    if len == 0 || formats.len() != usize::from(len) {
        return Err(Error::Decode("malformed ec_point_formats list".to_owned()));
    }
    Ok(formats.to_vec())
}
