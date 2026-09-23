//! Reassembly of fragmented handshake messages.
//!
//! Handshake messages may be split across several DTLS records. The
//! [`Reassembler`] buffers fragments keyed by `message_seq`, tracks which byte
//! ranges have arrived, and delivers fully-received messages in sequence order.
//! Retransmitted fragments (for already-delivered sequences) are ignored.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

use super::messages::HandshakeHeader;

#[allow(missing_docs)]
pub const MAX_MESSAGE_LEN: u32 = 64 * 1024;

#[allow(missing_docs)]
pub const MAX_BUFFERED_BYTES: usize = 128 * 1024;

#[allow(missing_docs)]
pub const SEQUENCE_WINDOW: u16 = 8;

const CHUNK_OVERHEAD: usize = 64;

#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeMessage {
    pub msg_type: u8,
    pub message_seq: u16,
    pub epoch: u16,
    pub body: Vec<u8>,
}

struct Partial {
    msg_type: u8,
    length: u32,
    epoch: u16,
    chunks: BTreeMap<u32, Vec<u8>>,
    received: u32,
}

impl Partial {
    fn missing(&self, start: u32, end: u32) -> Vec<(u32, u32)> {
        let mut gaps = Vec::new();
        let mut cursor = start;
        for (&offset, chunk) in &self.chunks {
            let chunk_end = offset + chunk.len() as u32;
            if chunk_end <= cursor {
                continue;
            }
            if offset >= end {
                break;
            }
            if offset > cursor {
                gaps.push((cursor, offset));
            }
            cursor = cursor.max(chunk_end);
            if cursor >= end {
                break;
            }
        }
        if cursor < end {
            gaps.push((cursor, end));
        }
        gaps
    }

    fn cost(&self) -> usize {
        self.chunks
            .values()
            .map(|chunk| chunk.len() + CHUNK_OVERHEAD)
            .sum()
    }

    fn is_complete(&self) -> bool {
        self.received == self.length
    }

    fn into_body(self) -> Vec<u8> {
        let mut body = Vec::with_capacity(self.length as usize);
        for chunk in self.chunks.into_values() {
            body.extend_from_slice(&chunk);
        }
        body
    }
}

/// Buffers handshake fragments and yields complete messages in order.
pub struct Reassembler {
    next_seq: u16,
    pending: BTreeMap<u16, Partial>,
    buffered: usize,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    /// Create an empty reassembler expecting `message_seq` 0 first.
    #[must_use]
    pub fn new() -> Self {
        Self::starting_at(0)
    }

    #[allow(missing_docs)]
    #[must_use]
    pub fn starting_at(next_seq: u16) -> Self {
        Self {
            next_seq,
            pending: BTreeMap::new(),
            buffered: 0,
        }
    }

    /// The next message sequence number expected to be delivered.
    #[must_use]
    pub fn next_seq(&self) -> u16 {
        self.next_seq
    }

    #[allow(missing_docs)]
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.buffered
    }

    #[allow(missing_docs)]
    #[must_use]
    pub fn pending_messages(&self) -> usize {
        self.pending.len()
    }

    #[allow(missing_docs)]
    pub fn clear(&mut self) {
        self.pending.clear();
        self.buffered = 0;
    }

    /// Feed one handshake fragment. Returns any messages (type, `message_seq`,
    /// epoch, body) that became complete and in-order as a result, in delivery
    /// order.
    ///
    /// # Errors
    ///
    /// Returns an error if a fragment is internally inconsistent (offset/length
    /// out of range, or a length mismatch against an earlier fragment).
    pub fn feed(
        &mut self,
        epoch: u16,
        header: &HandshakeHeader,
        fragment: &[u8],
    ) -> Result<Vec<HandshakeMessage>> {
        if header.fragment_length as usize != fragment.len() {
            return Err(Error::Decode("fragment_length mismatch".to_owned()));
        }
        if header.length > MAX_MESSAGE_LEN {
            return Err(Error::Decode(format!(
                "handshake message length {} exceeds {MAX_MESSAGE_LEN}",
                header.length
            )));
        }
        let end = header
            .fragment_offset
            .checked_add(header.fragment_length)
            .ok_or(Error::Decode("fragment offset overflow".to_owned()))?;
        if end > header.length {
            return Err(Error::Decode("fragment exceeds message length".to_owned()));
        }
        let Some(distance) = header.message_seq.checked_sub(self.next_seq) else {
            return Ok(Vec::new()); // retransmit of an already-delivered message
        };
        if distance >= SEQUENCE_WINDOW {
            return Ok(Vec::new());
        }

        let partial = self
            .pending
            .entry(header.message_seq)
            .or_insert_with(|| Partial {
                msg_type: header.msg_type,
                length: header.length,
                epoch,
                chunks: BTreeMap::new(),
                received: 0,
            });
        if partial.length != header.length
            || partial.msg_type != header.msg_type
            || partial.epoch != epoch
        {
            return Err(Error::Decode("inconsistent fragment metadata".to_owned()));
        }

        let gaps = partial.missing(header.fragment_offset, end);
        let cost: usize = gaps
            .iter()
            .map(|&(start, stop)| (stop - start) as usize + CHUNK_OVERHEAD)
            .sum();
        if self.buffered + cost > MAX_BUFFERED_BYTES {
            return Err(Error::Decode(
                "handshake reassembly buffer limit exceeded".to_owned(),
            ));
        }
        for (start, stop) in gaps {
            let from = (start - header.fragment_offset) as usize;
            let to = (stop - header.fragment_offset) as usize;
            partial.chunks.insert(start, fragment[from..to].to_vec());
            partial.received += stop - start;
        }
        self.buffered += cost;

        let mut delivered = Vec::new();
        while self
            .pending
            .get(&self.next_seq)
            .is_some_and(Partial::is_complete)
        {
            let following = self
                .next_seq
                .checked_add(1)
                .ok_or(Error::Decode("handshake message_seq exhausted".to_owned()))?;
            let Some(partial) = self.pending.remove(&self.next_seq) else {
                break;
            };
            self.buffered -= partial.cost();
            delivered.push(HandshakeMessage {
                msg_type: partial.msg_type,
                message_seq: self.next_seq,
                epoch: partial.epoch,
                body: partial.into_body(),
            });
            self.next_seq = following;
        }
        Ok(delivered)
    }
}
