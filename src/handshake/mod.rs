//! DTLS handshake layer: message codecs, fragment reassembly, cookies, the key
//! schedule, and the per-role flight builders driven by [`crate::Connection`].

pub mod client;
pub mod cookie;
pub mod flight;
pub mod fragment;
pub mod keyschedule;
pub mod messages;
pub mod server;

/// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02B;
/// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (for Firefox interop).
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02F;

/// The `ChangeCipherSpec` message body (a single `0x01`).
pub const CHANGE_CIPHER_SPEC_BODY: [u8; 1] = [1];

pub use cookie::CookieSecret;
pub use fragment::Reassembler;
pub use messages::frame as frame_message;
