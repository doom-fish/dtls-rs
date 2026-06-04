//! Outbound flight tracking for retransmission.
//!
//! A flight is the set of handshake records a peer sends before it expects a
//! reply. DTLS has no TCP underneath, so a lost flight must be retransmitted
//! verbatim on timeout. [`Flight`] simply remembers the encoded record bytes of
//! the most recent outbound flight so the connection can resend them.

/// The encoded records of one outbound flight.
#[derive(Debug, Default, Clone)]
pub struct Flight {
    records: Vec<Vec<u8>>,
}

impl Flight {
    /// Create an empty flight.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Add an encoded record to the flight.
    pub fn push(&mut self, record: Vec<u8>) {
        self.records.push(record);
    }

    /// Whether the flight has any records to send.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Borrow the encoded records.
    #[must_use]
    pub fn records(&self) -> &[Vec<u8>] {
        &self.records
    }

    /// Concatenate the records into a single datagram-friendly buffer.
    #[must_use]
    pub fn to_datagram(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for record in &self.records {
            out.extend_from_slice(record);
        }
        out
    }

    /// Clear the stored records.
    pub fn clear(&mut self) {
        self.records.clear();
    }
}
