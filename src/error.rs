//! Error and result types for `dtls-rs`.

use std::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced by the DTLS state machine and its supporting codecs.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A wire buffer ended before a structure was fully decoded.
    Truncated(&'static str),
    /// A field held a value outside the range this profile accepts.
    Decode(String),
    /// The peer sent a record or message that violates the handshake order.
    UnexpectedMessage(String),
    /// AEAD authentication failed when opening a record.
    BadRecordMac,
    /// A `Finished` `verify_data` did not match the locally computed value.
    BadFinished,
    /// Peer signature verification (`ServerKeyExchange`/`CertificateVerify`) failed.
    BadSignature,
    /// The peer certificate fingerprint did not match the expected SDP value.
    FingerprintMismatch,
    /// No mutually supported cipher suite, curve, or SRTP profile was found.
    Negotiation(&'static str),
    /// The peer sent a fatal alert or closed the connection.
    #[allow(missing_docs)]
    Alert { level: u8, description: u8 },
    /// The handshake exceeded the retransmission deadline.
    Timeout,
    /// A method was called while the connection was in the wrong state.
    InvalidState(&'static str),
    #[allow(missing_docs)]
    InvalidArgument(&'static str),
    /// An underlying CryptoKit operation failed.
    Crypto(String),
    /// An underlying Security.framework operation failed.
    Security(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated(what) => write!(f, "buffer truncated while decoding {what}"),
            Self::Decode(msg) => write!(f, "decode error: {msg}"),
            Self::UnexpectedMessage(msg) => write!(f, "unexpected message: {msg}"),
            Self::BadRecordMac => f.write_str("AEAD record authentication failed"),
            Self::BadFinished => f.write_str("Finished verify_data mismatch"),
            Self::BadSignature => f.write_str("peer signature verification failed"),
            Self::FingerprintMismatch => f.write_str("peer certificate fingerprint mismatch"),
            Self::Negotiation(what) => write!(f, "negotiation failed: no common {what}"),
            Self::Alert { level, description } => {
                write!(f, "peer sent alert {description} (level {level})")
            }
            Self::Timeout => f.write_str("handshake retransmission deadline exceeded"),
            Self::InvalidState(msg) => write!(f, "invalid state: {msg}"),
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::Crypto(msg) => write!(f, "crypto error: {msg}"),
            Self::Security(msg) => write!(f, "security framework error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<cryptokit::error::CryptoKitError> for Error {
    fn from(value: cryptokit::error::CryptoKitError) -> Self {
        Self::Crypto(value.to_string())
    }
}

impl From<security::error::SecurityError> for Error {
    fn from(value: security::error::SecurityError) -> Self {
        Self::Security(value.to_string())
    }
}
