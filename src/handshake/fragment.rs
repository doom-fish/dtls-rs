//! Reassembly of fragmented handshake messages.
//!
//! Handshake messages may be split across several DTLS records. The
//! [`Reassembler`] buffers fragments keyed by `message_seq`, tracks which byte
//! ranges have arrived, and delivers fully-received messages in sequence order.
//! Retransmitted fragments (for already-delivered sequences) are ignored.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

use super::messages::HandshakeHeader;

struct Partial {
    msg_type: u8,
    length: u32,
    data: Vec<u8>,
    filled: Vec<bool>,
    filled_count: usize,
}

/// Buffers handshake fragments and yields complete messages in order.
#[derive(Default)]
pub struct Reassembler {
    next_seq: u16,
    pending: BTreeMap<u16, Partial>,
}

impl Reassembler {
    /// Create an empty reassembler expecting `message_seq` 0 first.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_seq: 0,
            pending: BTreeMap::new(),
        }
    }

    /// The next message sequence number expected to be delivered.
    #[must_use]
    pub fn next_seq(&self) -> u16 {
        self.next_seq
    }

    /// Feed one handshake fragment. Returns any messages (type, `message_seq`,
    /// body) that became complete and in-order as a result, in delivery order.
    ///
    /// # Errors
    ///
    /// Returns an error if a fragment is internally inconsistent (offset/length
    /// out of range, or a length mismatch against an earlier fragment).
    pub fn feed(
        &mut self,
        header: &HandshakeHeader,
        fragment: &[u8],
    ) -> Result<Vec<(u8, u16, Vec<u8>)>> {
        if header.message_seq < self.next_seq {
            return Ok(Vec::new()); // retransmit of an already-delivered message
        }
        if header.fragment_length as usize != fragment.len() {
            return Err(Error::Decode("fragment_length mismatch".to_owned()));
        }
        let end = header
            .fragment_offset
            .checked_add(header.fragment_length)
            .ok_or(Error::Decode("fragment offset overflow".to_owned()))?;
        if end > header.length {
            return Err(Error::Decode("fragment exceeds message length".to_owned()));
        }

        let entry = self.pending.entry(header.message_seq).or_insert_with(|| Partial {
            msg_type: header.msg_type,
            length: header.length,
            data: vec![0u8; header.length as usize],
            filled: vec![false; header.length as usize],
            filled_count: 0,
        });
        if entry.length != header.length || entry.msg_type != header.msg_type {
            return Err(Error::Decode("inconsistent fragment metadata".to_owned()));
        }

        let start = header.fragment_offset as usize;
        let stop = end as usize;
        entry.data[start..stop].copy_from_slice(fragment);
        for filled in &mut entry.filled[start..stop] {
            if !*filled {
                *filled = true;
                entry.filled_count += 1;
            }
        }

        let mut delivered = Vec::new();
        while let Some(partial) = self.pending.get(&self.next_seq) {
            if partial.filled_count != partial.length as usize {
                break;
            }
            let seq = self.next_seq;
            let partial = self.pending.remove(&self.next_seq).unwrap();
            delivered.push((partial.msg_type, seq, partial.data));
            self.next_seq += 1;
        }
        Ok(delivered)
    }
}
