//! `extended_master_secret` extension (RFC 7627). The extension carries no data.

use super::{ext_type, Extension};

/// Build an empty `extended_master_secret` extension.
#[must_use]
pub fn build() -> Extension {
    Extension::new(ext_type::EXTENDED_MASTER_SECRET, Vec::new())
}
