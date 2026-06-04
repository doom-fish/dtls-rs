//! `ec_point_formats` extension (RFC 8422 §5.1.2).

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
