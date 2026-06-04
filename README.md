# dtls-rs

A minimal, pure-Rust **DTLS 1.2 ([RFC 6347](https://www.rfc-editor.org/rfc/rfc6347))**
implementation for the **WebRTC DTLS-SRTP** profile. It is *sans-I/O*: the
[`Connection`] state machine operates entirely over in-memory datagram buffers,
so the caller owns the socket and can demultiplex DTLS, STUN, and SRTP over a
single UDP flow.

This crate is part of the doom-fish family of Apple-SDK-adjacent Rust crates. It
is **not published to crates.io** (`publish = false`) — it is an internal
building block for the media stack.

## Why this exists

The WebRTC media stack needs two things no system DTLS API exposes cleanly:

1. A DTLS endpoint that runs over a **memory buffer** rather than a socket, so it
   can share one UDP port with STUN and SRTP (demultiplexed by the application).
2. The **RFC 5705 keying-material exporter** used to derive SRTP session keys
   (`EXTRACTOR-dtls_srtp`).

`dtls-rs` provides exactly those, and nothing more.

## Scope

Deliberately narrow, matching the WebRTC profile:

| Area | Supported |
| --- | --- |
| Protocol version | DTLS 1.2 only |
| Cipher suites | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xC02B) and `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (0xC02F, for Firefox interop) |
| Key exchange | ECDHE over NIST **P-256** only |
| Authentication | **Mutual** — both peers send a Certificate + CertificateVerify |
| Trust model | Self-signed certs, verified out-of-band via SHA-256 fingerprint (SDP `a=fingerprint`), **no PKI** |
| Record protection | AES-128-GCM AEAD |
| Always on | Extended Master Secret ([RFC 7627](https://www.rfc-editor.org/rfc/rfc7627)), `use_srtp` ([RFC 5764](https://www.rfc-editor.org/rfc/rfc5764)) |
| Exporter | RFC 5705 `export_keying_material`, `EXTRACTOR-dtls_srtp` |

### Out of scope

DTLS 1.0/1.3, TLS-over-TCP, session resumption, RSA key exchange, CBC/non-GCM
suites, curves other than P-256, PKI / certificate-chain validation, and any
form of built-in socket or timer.

## Dependencies

Runtime dependencies are intentionally minimal — only `libc` and two sibling
path crates:

* [`cryptokit-rs`](../cryptokit-rs) — SHA-256, HMAC, AES-GCM, ECDHE/ECDSA P-256.
* [`security-rs`](../security-rs) — RSA signature verification (for ECDHE-RSA
  interop).

There are **no crates.io runtime dependencies** beyond `libc`.

## Usage

```rust,no_run
use dtls::{Config, Connection};

let mut client = Connection::new(Config::client())?;
let mut server = Connection::new(Config::server())?;

// Pump datagrams between the two endpoints until both complete.
while !(client.is_handshake_done() && server.is_handshake_done()) {
    if let Some(datagram) = client.poll_send() {
        server.feed_recv(&datagram, 0)?;
    }
    if let Some(datagram) = server.poll_send() {
        client.feed_recv(&datagram, 0)?;
    }
}

// Cross-check the peer's certificate fingerprint against the SDP value, then
// derive SRTP keying material.
let fingerprint = client.peer_fingerprint().unwrap();
let srtp_keys = client.export_keying_material(
    dtls::exporter::DTLS_SRTP_LABEL,
    None,
    60, // 2 * (16-byte key + 14-byte salt) for AES-128-GCM
)?;
# Ok::<(), dtls::Error>(())
```

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
the AES-GCM record layer (roundtrip + tamper/replay rejection), handshake
message codecs, DTLS fragment reassembly, the stateless cookie exchange,
certificate emit/parse, the key schedule + exporter, the `use_srtp` extension,
and a full end-to-end loopback handshake.

## License

Licensed under either of MIT or Apache-2.0 at your option.
