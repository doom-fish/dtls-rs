//! Stateless DTLS cookie generation (RFC 6347 §4.2.1).
//!
//! The server derives a cookie as `HMAC-SHA256(secret, peer_id || client_hello
//! fields)` truncated to 32 bytes, where `secret` is a per-process random value.
//! Because the cookie is a keyed MAC over the client's own parameters, the
//! server need not store per-client state between the two `ClientHello`s.

use crate::crypto::hmac::hmac_sha256;

/// Maximum DTLS cookie length.
pub const MAX_COOKIE_LEN: usize = 32;

/// A per-process secret used to key the cookie MAC.
#[derive(Debug, Clone)]
pub struct CookieSecret {
    secret: [u8; 32],
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

    /// Compute the cookie for a given peer identity and `ClientHello` body.
    ///
    /// # Errors
    ///
    /// Returns an error if the MAC computation fails.
    pub fn compute(&self, peer_id: &[u8], client_hello_body: &[u8]) -> crate::error::Result<Vec<u8>> {
        let mut message = Vec::with_capacity(peer_id.len() + client_hello_body.len());
        message.extend_from_slice(peer_id);
        message.extend_from_slice(client_hello_body);
        let mac = hmac_sha256(&self.secret, &message)?;
        Ok(mac[..MAX_COOKIE_LEN].to_vec())
    }

    /// Constant-time check that `cookie` matches the expected value.
    ///
    /// # Errors
    ///
    /// Returns an error if the MAC computation fails.
    pub fn verify(
        &self,
        peer_id: &[u8],
        client_hello_body: &[u8],
        cookie: &[u8],
    ) -> crate::error::Result<bool> {
        let expected = self.compute(peer_id, client_hello_body)?;
        if expected.len() != cookie.len() {
            return Ok(false);
        }
        let mut diff = 0u8;
        for (a, b) in expected.iter().zip(cookie) {
            diff |= a ^ b;
        }
        Ok(diff == 0)
    }
}
