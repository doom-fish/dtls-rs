//! `DTLSPlaintext` / `DTLSCiphertext` record framing.
//!
//! Both share the same 13-byte header; only the fragment interpretation
//! differs (cleartext vs. AEAD-protected). The encoder writes one record; the
//! decoder reads one record and reports how many bytes it consumed so a caller
//! can walk a datagram that coalesces several records.

use crate::error::{Error, Result};

use super::DTLS_1_2;

/// Length of the DTLS record header in bytes.
pub const HEADER_LEN: usize = 13;

/// A single DTLS record (header plus fragment).
#[derive(Debug, Clone)]
pub struct Record {
    /// Content type (handshake, alert, …).
    pub content_type: u8,
    /// Protocol version, normally [`DTLS_1_2`].
    pub version: u16,
    /// Epoch counter (incremented on each `ChangeCipherSpec`).
    pub epoch: u16,
    /// 48-bit per-epoch sequence number.
    pub sequence: u64,
    /// The (possibly encrypted) fragment payload.
    pub fragment: Vec<u8>,
}

impl Record {
    /// Build a record with the standard DTLS 1.2 version.
    #[must_use]
    pub fn new(content_type: u8, epoch: u16, sequence: u64, fragment: Vec<u8>) -> Self {
        Self {
            content_type,
            version: DTLS_1_2,
            epoch,
            sequence,
            fragment,
        }
    }

    /// Serialize the record (13-byte header followed by the fragment).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.fragment.len());
        out.push(self.content_type);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes()[2..]); // low 48 bits
        out.extend_from_slice(&(self.fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.fragment);
        out
    }

    /// Decode one record from the front of `buf`, returning the record and the
    /// number of bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if the buffer is shorter than the header or
    /// the declared fragment length.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < HEADER_LEN {
            return Err(Error::Truncated("record header"));
        }
        let content_type = buf[0];
        let version = u16::from_be_bytes([buf[1], buf[2]]);
        let epoch = u16::from_be_bytes([buf[3], buf[4]]);
        let sequence = u64::from_be_bytes([0, 0, buf[5], buf[6], buf[7], buf[8], buf[9], buf[10]]);
        let length = u16::from_be_bytes([buf[11], buf[12]]) as usize;
        let end = HEADER_LEN + length;
        let fragment = buf
            .get(HEADER_LEN..end)
            .ok_or(Error::Truncated("record fragment"))?
            .to_vec();
        Ok((
            Self {
                content_type,
                version,
                epoch,
                sequence,
                fragment,
            },
            end,
        ))
    }
}
