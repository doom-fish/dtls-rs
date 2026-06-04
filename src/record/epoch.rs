//! Per-epoch sequence-number bookkeeping.
//!
//! Each epoch has an independent 48-bit sequence-number space. The writer hands
//! out monotonically increasing values; the reader tracks the highest sequence
//! seen for loose duplicate logging (full anti-replay windows are out of scope
//! for the WebRTC handshake profile).

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

    /// Return the next sequence number and advance the counter.
    pub fn take(&mut self) -> u64 {
        let value = self.next;
        self.next = (self.next + 1) & 0x0000_FFFF_FFFF_FFFF;
        value
    }

    /// The value that will be returned by the next [`Self::take`].
    #[must_use]
    pub const fn peek(&self) -> u64 {
        self.next
    }
}
