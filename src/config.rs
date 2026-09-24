//! Connection configuration: role, SRTP profiles, and peer-fingerprint pinning.

use crate::cert::Certificate;
use crate::extensions::use_srtp;
use crate::role::Role;

/// An SRTP protection profile negotiated through the `use_srtp` extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpProfile {
    /// `SRTP_AEAD_AES_128_GCM` (RFC 7714).
    AeadAes128Gcm,
    /// `SRTP_AEAD_AES_256_GCM` (RFC 7714).
    AeadAes256Gcm,
}

impl SrtpProfile {
    /// The 16-bit code point for this profile.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            SrtpProfile::AeadAes128Gcm => use_srtp::SRTP_AEAD_AES_128_GCM,
            SrtpProfile::AeadAes256Gcm => use_srtp::SRTP_AEAD_AES_256_GCM,
        }
    }

    /// Resolve a code point to a known profile.
    #[must_use]
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            use_srtp::SRTP_AEAD_AES_128_GCM => Some(SrtpProfile::AeadAes128Gcm),
            use_srtp::SRTP_AEAD_AES_256_GCM => Some(SrtpProfile::AeadAes256Gcm),
            _ => None,
        }
    }
}

/// Configuration for a DTLS [`crate::Connection`].
#[derive(Debug, Clone)]
pub struct Config {
    /// Whether to act as client or server.
    pub role: Role,
    /// SRTP profiles to offer/accept, in preference order.
    pub srtp_profiles: Vec<SrtpProfile>,
    /// If set, the peer certificate's SHA-256 fingerprint must match this
    /// value (as carried out-of-band in an SDP `a=fingerprint` line).
    pub expected_peer_fingerprint: Option<[u8; 32]>,
    #[allow(missing_docs)]
    pub certificate: Option<Certificate>,
}

impl Config {
    /// A client configuration offering AES-128-GCM SRTP.
    #[must_use]
    pub fn client() -> Self {
        Self {
            role: Role::Client,
            srtp_profiles: vec![SrtpProfile::AeadAes128Gcm],
            expected_peer_fingerprint: None,
            certificate: None,
        }
    }

    /// A server configuration offering AES-128-GCM SRTP.
    #[must_use]
    pub fn server() -> Self {
        Self {
            role: Role::Server,
            srtp_profiles: vec![SrtpProfile::AeadAes128Gcm],
            expected_peer_fingerprint: None,
            certificate: None,
        }
    }

    /// Pin the expected peer fingerprint (builder style).
    #[must_use]
    pub fn with_expected_peer_fingerprint(mut self, fingerprint: [u8; 32]) -> Self {
        self.expected_peer_fingerprint = Some(fingerprint);
        self
    }

    #[allow(missing_docs)]
    #[must_use]
    pub fn with_certificate(mut self, certificate: Certificate) -> Self {
        self.certificate = Some(certificate);
        self
    }

    /// Set the SRTP profiles (builder style).
    #[must_use]
    pub fn with_srtp_profiles(mut self, profiles: Vec<SrtpProfile>) -> Self {
        self.srtp_profiles = profiles;
        self
    }
}
