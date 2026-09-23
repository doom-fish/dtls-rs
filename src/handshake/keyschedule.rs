//! TLS 1.2 key schedule for the AES-128-GCM cipher suites with the extended
//! master secret extension (RFC 7627) always in effect.

use std::fmt;

use zeroize::Zeroizing;

use crate::crypto::hash::sha256;
use crate::error::{Error, Result};
use crate::crypto::prf::prf_sha256;
use crate::record::AeadKeys;

/// Length of the AES-128-GCM key block: two 16-byte keys + two 4-byte IVs.
pub const KEY_BLOCK_LEN: usize = 40;
/// Length of `Finished.verify_data`.
pub const VERIFY_DATA_LEN: usize = 12;

const LABEL_EXTENDED_MASTER_SECRET: &[u8] = b"extended master secret";
const LABEL_KEY_EXPANSION: &[u8] = b"key expansion";
const LABEL_CLIENT_FINISHED: &[u8] = b"client finished";
const LABEL_SERVER_FINISHED: &[u8] = b"server finished";

/// Derive the 48-byte extended master secret from the premaster secret and the
/// session-hash (hash of the handshake transcript through `ClientKeyExchange`).
///
/// # Errors
///
/// Returns an error if the PRF fails.
pub fn extended_master_secret(
    premaster: &[u8],
    session_hash: &[u8],
) -> Result<Zeroizing<[u8; 48]>> {
    let block = prf_sha256(premaster, LABEL_EXTENDED_MASTER_SECRET, session_hash, 48)?;
    let mut out = Zeroizing::new([0u8; 48]);
    out.copy_from_slice(&block);
    Ok(out)
}

/// The directional key material derived from a key block.
#[derive(Clone)]
pub struct KeyMaterial {
    /// Keys protecting the client's writes.
    pub client: AeadKeys,
    /// Keys protecting the server's writes.
    pub server: AeadKeys,
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyMaterial { client: [REDACTED], server: [REDACTED] }")
    }
}

/// Derive the client/server AEAD keys from the master secret and randoms.
///
/// Note the `server_random || client_random` ordering required for key
/// expansion (RFC 5246 §6.3).
///
/// # Errors
///
/// Returns an error if the PRF fails.
pub fn derive_keys(
    master_secret: &[u8],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
) -> Result<KeyMaterial> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let block = prf_sha256(master_secret, LABEL_KEY_EXPANSION, &seed, KEY_BLOCK_LEN)?;
    if block.len() != KEY_BLOCK_LEN {
        return Err(Error::Crypto("short key block".to_owned()));
    }

    let mut material = KeyMaterial {
        client: AeadKeys {
            key: [0u8; 16],
            salt: [0u8; 4],
        },
        server: AeadKeys {
            key: [0u8; 16],
            salt: [0u8; 4],
        },
    };
    material.client.key.copy_from_slice(&block[0..16]);
    material.server.key.copy_from_slice(&block[16..32]);
    material.client.salt.copy_from_slice(&block[32..36]);
    material.server.salt.copy_from_slice(&block[36..40]);
    Ok(material)
}

/// Compute the client's `Finished.verify_data` over the transcript bytes.
///
/// # Errors
///
/// Returns an error if the hash or PRF fails.
pub fn client_finished_verify_data(master_secret: &[u8], transcript: &[u8]) -> Result<Vec<u8>> {
    let hash = sha256(transcript)?;
    Ok(prf_sha256(master_secret, LABEL_CLIENT_FINISHED, &hash, VERIFY_DATA_LEN)?.to_vec())
}

/// Compute the server's `Finished.verify_data` over the transcript bytes.
///
/// # Errors
///
/// Returns an error if the hash or PRF fails.
pub fn server_finished_verify_data(master_secret: &[u8], transcript: &[u8]) -> Result<Vec<u8>> {
    let hash = sha256(transcript)?;
    Ok(prf_sha256(master_secret, LABEL_SERVER_FINISHED, &hash, VERIFY_DATA_LEN)?.to_vec())
}
