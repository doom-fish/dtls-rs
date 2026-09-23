//! Stateless DTLS cookie generation (RFC 6347 §4.2.1).
//!
//! The server derives a cookie as `HMAC-SHA256(secret, peer_id || client_hello
//! fields)` truncated to 32 bytes, where `secret` is a per-process random value.
//! Because the cookie is a keyed MAC over the client's own parameters, the
//! server need not store per-client state between the two `ClientHello`s.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use zeroize::Zeroize;

use crate::crypto::constant_time_eq;
use crate::crypto::hmac::hmac_sha256;
use crate::handshake::messages::ClientHello;

/// Maximum DTLS cookie length.
pub const MAX_COOKIE_LEN: usize = 32;

/// A per-process secret used to key the cookie MAC.
#[derive(Clone)]
pub struct CookieSecret {
    secret: [u8; 32],
}

impl fmt::Debug for CookieSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CookieSecret([REDACTED])")
    }
}

impl Drop for CookieSecret {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl CookieSecret {
    /// Generate a fresh random cookie secret.
    ///
    /// # Errors
    ///
    /// Returns an error if the system RNG fails.
    pub fn generate() -> crate::error::Result<Self> {
        let mut secret = [0u8; 32];
        crate::crypto::fill_random(&mut secret)?;
        Ok(Self { secret })
    }

    /// Compute the cookie for a given peer address and `ClientHello`.
    ///
    /// # Errors
    ///
    /// Returns an error if the MAC computation fails.
    pub fn compute(&self, peer: SocketAddr, hello: &ClientHello) -> crate::error::Result<Vec<u8>> {
        let mac = hmac_sha256(&self.secret, &cookie_input(peer, hello))?;
        Ok(mac[..MAX_COOKIE_LEN].to_vec())
    }

    /// Constant-time check that the `ClientHello` cookie matches the expected
    /// value.
    ///
    /// # Errors
    ///
    /// Returns an error if the MAC computation fails.
    pub fn verify(&self, peer: SocketAddr, hello: &ClientHello) -> crate::error::Result<bool> {
        let expected = self.compute(peer, hello)?;
        Ok(constant_time_eq(&expected, &hello.cookie))
    }
}

fn cookie_input(peer: SocketAddr, hello: &ClientHello) -> Vec<u8> {
    let mut input = Vec::with_capacity(64 + hello.cipher_suites.len() * 2);
    match peer.ip().to_canonical() {
        IpAddr::V4(ip) => {
            input.push(4);
            input.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            input.push(6);
            input.extend_from_slice(&ip.octets());
        }
    }
    input.extend_from_slice(&peer.port().to_be_bytes());
    input.extend_from_slice(&hello.version.to_be_bytes());
    input.extend_from_slice(&hello.random);
    input.push(hello.session_id.len() as u8);
    input.extend_from_slice(&hello.session_id);
    input.extend_from_slice(&((hello.cipher_suites.len() * 2) as u16).to_be_bytes());
    for suite in &hello.cipher_suites {
        input.extend_from_slice(&suite.to_be_bytes());
    }
    input.push(hello.compression_methods.len() as u8);
    input.extend_from_slice(&hello.compression_methods);
    input
}
