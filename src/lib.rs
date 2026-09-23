//! `dtls` — a minimal DTLS 1.2 (RFC 6347) implementation for the WebRTC
//! DTLS-SRTP profile.
//!
//! This crate exists because the WebRTC media stack needs two things no system
//! DTLS API exposes cleanly: a DTLS endpoint that operates over a *memory
//! buffer* (so it can share one UDP socket with STUN and SRTP, demultiplexed by
//! the application), and the RFC 5705 keying-material exporter used to derive
//! SRTP keys.
//!
//! The implementation is deliberately narrow:
//!
//! * a single cipher-suite family —
//!   `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (plus the `ECDHE_RSA` variant for
//!   interop), P-256 only;
//! * self-signed certificates whose trust comes from an out-of-band SHA-256
//!   fingerprint (as carried in an SDP `a=fingerprint` line), not a PKI;
//! * the extended-master-secret extension (RFC 7627) always in effect;
//! * a sans-I/O [`Connection`] driven entirely by the caller — no sockets, no
//!   threads, no clock of its own.
//!
//! # Example
//!
//! ```no_run
//! use std::net::SocketAddr;
//!
//! use dtls::{Config, Connection};
//!
//! let client_addr = SocketAddr::from(([127, 0, 0, 1], 50000));
//! let server_addr = SocketAddr::from(([127, 0, 0, 1], 50001));
//! let mut server = Connection::new(Config::server())?;
//! let mut client = Connection::new(
//!     Config::client().with_expected_peer_fingerprint(server.local_fingerprint()),
//! )?;
//! server.set_expected_peer_fingerprint(client.local_fingerprint())?;
//!
//! // Pump datagrams between the two until both report completion.
//! while !(client.is_handshake_done() && server.is_handshake_done()) {
//!     if let Some(dg) = client.poll_send() {
//!         server.feed_recv(&dg, client_addr, 0)?;
//!     }
//!     if let Some(dg) = server.poll_send() {
//!         client.feed_recv(&dg, server_addr, 0)?;
//!     }
//! }
//! # Ok::<(), dtls::Error>(())
//! ```
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]

pub mod asn1;
pub mod cert;
pub mod config;
pub mod connection;
pub mod crypto;
pub mod error;
pub mod exporter;
pub mod extensions;
pub mod handshake;
pub mod record;
pub mod role;
pub mod timer;

pub use config::{Config, SrtpProfile};
pub use connection::Connection;
pub use error::{Error, Result};
pub use role::Role;
pub use zeroize::Zeroizing;
