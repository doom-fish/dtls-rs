//! `renegotiation_info` extension (RFC 5746). For an initial handshake the
//! `renegotiated_connection` field is empty.

use super::{ext_type, Extension};

/// Build a `renegotiation_info` extension with an empty connection field.
#[must_use]
pub fn build() -> Extension {
    Extension::new(ext_type::RENEGOTIATION_INFO, vec![0])
}
