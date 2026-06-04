//! The role a [`crate::Connection`] plays in the handshake.

/// Whether this endpoint acts as the DTLS client or server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Sends the first `ClientHello`.
    Client,
    /// Answers with `HelloVerifyRequest` / `ServerHello`.
    Server,
}

impl Role {
    /// Whether this is the client role.
    #[must_use]
    pub fn is_client(self) -> bool {
        matches!(self, Role::Client)
    }

    /// Whether this is the server role.
    #[must_use]
    pub fn is_server(self) -> bool {
        matches!(self, Role::Server)
    }
}
