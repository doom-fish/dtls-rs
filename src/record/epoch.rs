//! Per-epoch sequence-number bookkeeping.
//!
//! Each epoch has an independent 48-bit sequence-number space. The writer hands
//! out monotonically increasing values and refuses to wrap; the reader rejects
//! duplicate and stale records with a 64-record sliding anti-replay window
//! (RFC 6347 §4.1.2.6).

use crate::error::{Error, Result};

#[allow(missing_docs)]
pub const MAX_SEQUENCE: u64 = 0x0000_FFFF_FFFF_FFFF;

#[allow(missing_docs)]
pub const REPLAY_WINDOW_SIZE: u64 = 64;

/// A monotonically increasing 48-bit sequence counter for one epoch.
#[derive(Debug, Default, Clone)]
pub struct EpochSeq {
    next: u64,
}

impl EpochSeq {
    /// Create a fresh counter starting at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    #[allow(missing_docs)]
    #[must_use]
    pub const fn starting_at(next: u64) -> Self {
        Self { next }
    }

    /// Return the next sequence number and advance the counter.
    pub fn take(&mut self) -> Result<u64> {
        if self.next > MAX_SEQUENCE {
            return Err(Error::InvalidState("record sequence number space exhausted"));
        }
        let value = self.next;
        self.next += 1;
        Ok(value)
    }

    /// The value that will be returned by the next [`Self::take`].
    #[must_use]
    pub const fn peek(&self) -> u64 {
        self.next
    }
}

#[allow(missing_docs)]
#[derive(Debug, Default, Clone)]
pub struct ReplayWindow {
    latest: Option<u64>,
    seen: u64,
}

impl ReplayWindow {
    #[allow(missing_docs)]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            latest: None,
            seen: 0,
        }
    }

    #[allow(missing_docs)]
    #[must_use]
    pub fn accepts(&self, sequence: u64) -> bool {
        match self.latest {
            None => true,
            Some(latest) if sequence > latest => true,
            Some(latest) => {
                let age = latest - sequence;
                age < REPLAY_WINDOW_SIZE && self.seen & (1 << age) == 0
            }
        }
    }

    #[allow(missing_docs)]
    pub fn mark(&mut self, sequence: u64) {
        match self.latest {
            None => {
                self.latest = Some(sequence);
                self.seen = 1;
            }
            Some(latest) if sequence > latest => {
                let shift = sequence - latest;
                self.seen = if shift >= REPLAY_WINDOW_SIZE {
                    1
                } else {
                    (self.seen << shift) | 1
                };
                self.latest = Some(sequence);
            }
            Some(latest) => {
                let age = latest - sequence;
                if age < REPLAY_WINDOW_SIZE {
                    self.seen |= 1 << age;
                }
            }
        }
    }
}
