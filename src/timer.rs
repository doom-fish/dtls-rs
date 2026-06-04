//! Handshake retransmission timer (RFC 6347 §4.2.4).
//!
//! DTLS uses a simple exponential-backoff timer: the initial RTO is 1 second
//! and doubles on each expiry, capped at 60 seconds. The connection arms the
//! timer when it sends a flight that expects a reply and disarms it when the
//! expected flight arrives. This type is time-source agnostic — the caller
//! supplies "now" as a millisecond clock so tests can drive it deterministically.

/// Initial retransmission timeout in milliseconds.
pub const INITIAL_RTO_MS: u64 = 1000;
/// Maximum retransmission timeout in milliseconds.
pub const MAX_RTO_MS: u64 = 60_000;

/// Exponential-backoff retransmission timer.
#[derive(Debug, Clone)]
pub struct RetransmitTimer {
    rto_ms: u64,
    deadline_ms: Option<u64>,
}

impl Default for RetransmitTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl RetransmitTimer {
    /// Create a disarmed timer with the initial RTO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rto_ms: INITIAL_RTO_MS,
            deadline_ms: None,
        }
    }

    /// Arm the timer relative to `now_ms`, resetting the RTO to its initial value.
    pub fn arm(&mut self, now_ms: u64) {
        self.rto_ms = INITIAL_RTO_MS;
        self.deadline_ms = Some(now_ms + self.rto_ms);
    }

    /// Disarm the timer (the expected flight arrived).
    pub fn disarm(&mut self) {
        self.deadline_ms = None;
    }

    /// Whether the timer is currently armed.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.deadline_ms.is_some()
    }

    /// Milliseconds until the next expiry, or `None` if disarmed. Saturates at
    /// zero once the deadline has passed.
    #[must_use]
    pub fn remaining_ms(&self, now_ms: u64) -> Option<u64> {
        self.deadline_ms.map(|deadline| deadline.saturating_sub(now_ms))
    }

    /// Returns `true` if the timer has expired at `now_ms`. When expired, the
    /// RTO is doubled (capped) and the timer re-armed from `now_ms`.
    pub fn on_check(&mut self, now_ms: u64) -> bool {
        match self.deadline_ms {
            Some(deadline) if now_ms >= deadline => {
                self.rto_ms = (self.rto_ms * 2).min(MAX_RTO_MS);
                self.deadline_ms = Some(now_ms + self.rto_ms);
                true
            }
            _ => false,
        }
    }

    /// The current RTO in milliseconds.
    #[must_use]
    pub fn rto_ms(&self) -> u64 {
        self.rto_ms
    }
}
