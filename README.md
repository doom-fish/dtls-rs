# dtls-rs

A minimal, pure-Rust **DTLS 1.2 ([RFC 6347](https://www.rfc-editor.org/rfc/rfc6347))**
implementation for the **WebRTC DTLS-SRTP** profile. It is *sans-I/O*: the
[`Connection`] state machine operates entirely over in-memory datagram buffers,
so the caller owns the socket and can demultiplex DTLS, STUN, and SRTP over a
single UDP flow.

This crate is part of the doom-fish family of Apple-SDK-adjacent Rust crates. It
is **not published to crates.io** (`publish = false`) — it is an internal
building block for the media stack. Current version: 0.2.0.

## Why this exists

The WebRTC media stack needs two things no system DTLS API exposes cleanly:

1. A DTLS endpoint that runs over a **memory buffer** rather than a socket, so it
   can share one UDP port with STUN and SRTP (demultiplexed by the application).
2. The **RFC 5705 keying-material exporter** used to derive SRTP session keys
   (`EXTRACTOR-dtls_srtp`).

`dtls-rs` provides exactly those, and nothing more.

## Installation

`dtls-rs` is not on crates.io; depend on it by path from a sibling crate:

```toml
[dependencies]
dtls = { package = "dtls-rs", path = "../dtls-rs", version = ">=0.2, <0.3" }
```

Requires Rust 1.82 or later and macOS 13 or later (CryptoKit and
Security.framework): `security-rs`'s Swift bridge targets macOS 12, and it links
`apple-cf`, whose Swift bridge targets macOS 13.

## Scope

Deliberately narrow, matching the WebRTC profile:

| Area | Supported |
| --- | --- |
| Protocol version | DTLS 1.2 only |
| Cipher suites | Server: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xC02B). Client: 0xC02B and `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (0xC02F, to accept peers with RSA certificates) |
| Key exchange | ECDHE over NIST **P-256** only |
| Authentication | **Mutual**: the server always sends CertificateRequest and requires the client's Certificate + CertificateVerify; the client answers a CertificateRequest with both |
| Trust model | Self-signed certs, verified against the SHA-256 fingerprint from the SDP `a=fingerprint` line, **no PKI**. The fingerprint can be pinned so that it is checked the moment the peer's Certificate arrives |
| Handshake | Explicit client and server state machines that enforce the RFC 6347 / RFC 5246 message order; a missing, duplicate, out-of-order or unprotected message fails the handshake with a fatal alert |
| Cookie exchange | The server always sends a stateless HelloVerifyRequest, with the cookie bound to the peer's transport address and ClientHello parameters; the client also accepts servers that skip it |
| Record protection | AES-128-GCM AEAD, with a 64-record anti-replay window for protected records |
| Always on | Extended Master Secret ([RFC 7627](https://www.rfc-editor.org/rfc/rfc7627)), `use_srtp` ([RFC 5764](https://www.rfc-editor.org/rfc/rfc5764)) |
| Exporter | RFC 5705 `export_keying_material`, `EXTRACTOR-dtls_srtp`, available once the peer's Finished has been verified |

### Out of scope

DTLS 1.0/1.3, TLS-over-TCP, session resumption, renegotiation, RSA key
exchange, CBC/non-GCM suites, curves other than P-256, PKI /
certificate-chain validation, SRTP MKI, connection IDs, application data
(there is no API to send or receive it), sending `close_notify`,
PMTU-driven fragmentation of outgoing handshake messages (each message is sent
in a single record, which fits the certificates WebRTC uses), and any form of
built-in socket or timer.

## Dependencies

Runtime dependencies are intentionally minimal: `libc`, `zeroize` and two
sibling path crates:

* [`cryptokit-rs`](../cryptokit-rs) — SHA-256, HMAC, AES-GCM, ECDHE/ECDSA P-256.
* [`security-rs`](../security-rs) — RSA signature verification (for ECDHE-RSA
  interop) and the system CSPRNG.

## Usage

```rust,no_run
use std::net::SocketAddr;

use dtls::{Config, Connection};

let client_addr = SocketAddr::from(([127, 0, 0, 1], 50000));
let server_addr = SocketAddr::from(([127, 0, 0, 1], 50001));

// Each side pins the fingerprint it learned from the peer's SDP.
let mut server = Connection::new(Config::server())?;
let mut client = Connection::new(
    Config::client().with_expected_peer_fingerprint(server.local_fingerprint()),
)?;
server.set_expected_peer_fingerprint(client.local_fingerprint())?;

// Pump datagrams between the two endpoints until both complete. The second
// argument is the address the datagram came from.
while !(client.is_handshake_done() && server.is_handshake_done()) {
    if let Some(datagram) = client.poll_send() {
        server.feed_recv(&datagram, client_addr, 0)?;
    }
    if let Some(datagram) = server.poll_send() {
        client.feed_recv(&datagram, server_addr, 0)?;
    }
}

// Derive SRTP keying material.
let srtp_keys = client.export_keying_material(
    dtls::exporter::DTLS_SRTP_LABEL,
    None,
    56, // 2 * (16-byte key + 12-byte salt) for SRTP_AEAD_AES_128_GCM
)?;
# Ok::<(), dtls::Error>(())
```

### Pinning the peer fingerprint

Pinning is the recommended way to authenticate the peer. Set it in the
`Config` with `with_expected_peer_fingerprint`, or, when the connection has to
exist before the remote description arrives (a WebRTC offerer publishes its own
fingerprint first), call `Connection::set_expected_peer_fingerprint` once the
remote `a=fingerprint` is known and before feeding the peer's handshake. The
pin is compared in constant time as soon as the peer's Certificate arrives, and
a mismatch aborts the handshake with `Error::FingerprintMismatch` before the
certificate's key is used.

Without a pin, compare `peer_fingerprint()` with the expected value before
using any exported keys. `peer_fingerprint()`, `selected_srtp_profile()` and
`export_keying_material()` return nothing (or `Error::InvalidState`) until the
handshake has completed, so they never report an unverified peer.

### Certificates

`Connection::new` generates a fresh self-signed ECDSA-P256 certificate unless
the `Config` carries one. When the fingerprint has to be published before the
role is known — a WebRTC offerer puts its `a=fingerprint` in an
`a=setup:actpass` offer and the answer decides which side is the DTLS client —
create a `Certificate` first, publish `Certificate::fingerprint()`, and pass the
certificate with `Config::with_certificate` once the role is known. Clones share
one private key; it is zeroized when the last clone is dropped, and `Debug`
never prints it.

### Driving the connection

* `feed_recv(datagram, peer, now_ms)` takes the datagram's source address. The
  server binds its HelloVerifyRequest cookie to that address; the client
  ignores it. Pass the real address of the remote transport (for WebRTC, the
  address of the selected ICE candidate pair).
* Malformed, unauthenticated, replayed and unexpected records are dropped
  silently (RFC 6347 §4.1.2.7). Plaintext alerts are honoured only while the
  handshake is still unencrypted; after the peer's ChangeCipherSpec only
  authenticated alerts close the connection.
* Any error returned by `feed_recv`, `handle_timeout` or
  `set_expected_peer_fingerprint` is fatal: the connection closes, a fatal
  alert is queued where appropriate (flush it with `poll_send`), and later calls
  return `Error::InvalidState`.
* Call `handle_timeout(now_ms)` when `timeout(now_ms)` elapses. Flights are
  retransmitted with fresh record sequence numbers and exponential backoff;
  after `timer::MAX_RETRANSMISSIONS` unanswered retransmissions the handshake
  fails with `Error::Timeout`. A completed server resends its final flight when
  the client retransmits its Finished.

### Limits

Handshake reassembly allocates only as fragments arrive and is bounded:
messages are capped at 64 KiB (`handshake::fragment::MAX_MESSAGE_LEN`), all
buffered fragments at 128 KiB (`MAX_BUFFERED_BYTES`), and only message
sequence numbers within 8 of the next expected one are buffered
(`SEQUENCE_WINDOW`).

### Secrets

`AeadKeys`, `KeyMaterial`, `CookieSecret` and `ExportedKeyingMaterial`
redact their `Debug` output and are zeroized on drop. The master secret,
premaster secret, HMAC blocks and PRF output are held in `Zeroizing` buffers
(the low-level `crypto` and `handshake::keyschedule` functions return them that
way, so avoid printing those). Finished messages, cookies, fingerprints and
exported keying material are compared in constant time.

## Examples

```sh
cargo run --example 01_self_signed_cert    # generate a cert, print its fingerprint
cargo run --example 02_handshake_loopback  # full in-process handshake
cargo run --example 03_exporter            # handshake + SRTP keying material
```

## Testing

```sh
cargo test
```

The suite covers the TLS 1.2 PRF against the official IETF known-answer vector,
the AES-GCM record layer (roundtrip, tamper rejection and the anti-replay
window), strict handshake message and extension codecs, ClientHello /
ServerHello negotiation checks, DTLS fragment reassembly and its memory and
sequence limits, the stateless cookie exchange, certificate emit/parse, the key
schedule + exporter, the `use_srtp` extension, secret redaction, negative
handshake tests driven by a scripted malicious client and server (Finished
without Certificate/CertificateVerify, a second or swapped Certificate,
out-of-order and duplicate messages, pin mismatches, unauthenticated alerts),
retransmission and timeout handling, and full end-to-end handshakes both in
memory and over UDP sockets bound to 127.0.0.1.

## License

Licensed under either of MIT or Apache-2.0 at your option.
