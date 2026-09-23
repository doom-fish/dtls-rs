//! Outbound flight tracking for retransmission.
//!
//! A flight is the set of handshake records a peer sends before it expects a
//! reply. DTLS has no TCP underneath, so a lost flight must be retransmitted
//! on timeout. [`Flight`] remembers the plaintext records of the most recent
//! outbound flight so the connection can re-encode them with fresh record
//! sequence numbers.

#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlightRecord {
    pub content_type: u8,
    pub epoch: u16,
    pub plaintext: Vec<u8>,
}

/// The plaintext records of one outbound flight.
#[derive(Debug, Default, Clone)]
pub struct Flight {
    records: Vec<FlightRecord>,
}

impl Flight {
    /// Create an empty flight.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Add a record to the flight.
    pub fn push(&mut self, content_type: u8, epoch: u16, plaintext: Vec<u8>) {
        self.records.push(FlightRecord {
            content_type,
            epoch,
            plaintext,
        });
    }

    /// Whether the flight has any records to send.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Borrow the records.
    #[must_use]
    pub fn records(&self) -> &[FlightRecord] {
        &self.records
    }

    /// Clear the stored records.
    pub fn clear(&mut self) {
        self.records.clear();
    }
}
