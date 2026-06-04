//! DTLS record layer (RFC 6347 §4.1).

pub mod ciphertext;
pub mod epoch;
pub mod plaintext;

/// The DTLS 1.2 `ProtocolVersion` (`{254, 253}`).
pub const DTLS_1_2: u16 = 0xFEFD;

/// DTLS record content types.
pub mod content_type {
    /// `change_cipher_spec(20)`.
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    /// `alert(21)`.
    pub const ALERT: u8 = 21;
    /// `handshake(22)`.
    pub const HANDSHAKE: u8 = 22;
    /// `application_data(23)`.
    pub const APPLICATION_DATA: u8 = 23;
}

pub use ciphertext::AeadKeys;
pub use epoch::EpochSeq;
pub use plaintext::Record;
