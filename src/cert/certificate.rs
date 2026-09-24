use std::fmt;
use std::sync::Arc;

use crate::cert::emit::{generate, SelfSignedCertificate};
use crate::cert::fingerprint::{format_colon_hex, sha256_fingerprint};
use crate::crypto::ecdsa_sign::EcdsaSigningKey;
use crate::error::Result;

#[allow(missing_docs)]
#[derive(Clone)]
pub struct Certificate {
    inner: Arc<SelfSignedCertificate>,
    fingerprint: [u8; 32],
}

impl Certificate {
    #[allow(missing_docs)]
    pub fn generate() -> Result<Self> {
        let inner = generate()?;
        let fingerprint = sha256_fingerprint(&inner.der)?;
        Ok(Self {
            inner: Arc::new(inner),
            fingerprint,
        })
    }

    #[allow(missing_docs)]
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    #[allow(missing_docs)]
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.inner.der
    }

    pub(crate) fn key(&self) -> &EcdsaSigningKey {
        &self.inner.key
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("fingerprint", &format_colon_hex(&self.fingerprint))
            .field("key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
