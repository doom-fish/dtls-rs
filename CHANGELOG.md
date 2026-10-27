# Changelog

All notable changes to `dtls-rs` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-10-27

### Changed

- **Breaking:** require `cryptokit-rs` 0.4 and `security-rs` 0.8. The `From` conversions for
  `CryptoKitError` and `SecurityError` now take the error types of those releases.

## [0.2.1] - 2026-10-26

### Fixed

- Update the test assertions for Clippy 1.99 on hosted runners.

## [0.2.0] - Unreleased

### Security

- The handshake dispatched messages by type only. The server accepted Finished
  without Certificate or CertificateVerify, and a Certificate that arrived after
  CertificateVerify replaced the verified key; the client let a second
  Certificate after a verified ServerKeyExchange replace the peer key and
  fingerprint. Either let an attacker impersonate a peer. Explicit client and
  server state machines now enforce the RFC 6347 / RFC 5246 message order;
  missing, duplicate, out-of-order and unprotected messages are fatal and send a
  fatal alert, and a peer key or fingerprint is never replaced.
- A pinned peer fingerprint (`Config::with_expected_peer_fingerprint` or the new
  `Connection::set_expected_peer_fingerprint`) is compared in constant time when
  the peer's Certificate arrives, before its key is used.
- `peer_fingerprint()`, `selected_srtp_profile()` and `export_keying_material()`
  are only available after the peer's Finished has been verified.
- Handshake reassembly allocated twice the declared length for every
  `message_seq` and never freed it, and `message_seq` 65535 panicked or wrapped.
  Fragments are now stored as they arrive, messages are capped at 64 KiB,
  buffered fragments at 128 KiB, only an 8-message window of `message_seq`
  values is buffered, and the arithmetic is checked.
- Plaintext epoch-0 handshake records are only accepted in states that expect
  them and before the peer's ChangeCipherSpec. Plaintext alerts no longer tear
  down a connection once the peer has changed cipher, and protected records are
  authenticated and replay-checked (64-record window, RFC 6347 §4.1.2.6) before
  their content, including alerts, is acted on.
- A spoofed ClientHello could consume the server's expected `message_seq` and
  stall the handshake. The server now answers cookieless ClientHellos
  statelessly, and cookies are bound to the peer transport address and the
  ClientHello parameters instead of a constant peer id.
- `AeadKeys`, `KeyMaterial` and `CookieSecret` printed keys through a derived
  `Debug`. They are redacted and zeroized on drop; the master and premaster
  secrets, HMAC blocks and PRF output are held in `Zeroizing` buffers; Finished,
  cookies and fingerprints are compared in constant time.
- Duplicate-extension detection and fragment gap tracking are linear, so
  crafted ClientHellos and fragment floods cannot cost quadratic CPU.

### Fixed

- Every handshake message in a record is processed, not only the first.
- The client accepts servers that skip HelloVerifyRequest and handles repeated
  HelloVerifyRequests, hashes messages with their real `message_seq`, and sends
  no Certificate or CertificateVerify when no CertificateRequest was received.
- The client checks the ServerHello against its offer (DTLS 1.2, null
  compression, an offered cipher suite, only offered extensions, the extended
  master secret echo, an empty `renegotiation_info`, the uncompressed point
  format, exactly one offered SRTP profile with an empty MKI), the
  CertificateRequest, and that ServerKeyExchange uses P-256 with a signature
  algorithm and key type matching the cipher suite. Parse errors are fatal.
- The server no longer selects `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` while
  presenting its ECDSA certificate, and requires the extended master secret,
  P-256, `ecdsa_secp256r1_sha256` and an empty `renegotiation_info`.
- Retransmitted flights get fresh record sequence numbers, a completed server
  resends its final flight when the client retransmits its Finished (RFC 6347
  §4.2.4), and HelloVerifyRequest and the initial ServerHello reuse the
  ClientHello record sequence number (RFC 6347 §4.2.1).
- `Error::Timeout` is returned after `timer::MAX_RETRANSMISSIONS` unanswered
  retransmissions; it was documented but never produced.
- Decoders reject trailing bytes, duplicate extensions, empty certificate
  entries and Finished messages that are not 12 bytes. The ClientHello omits
  `use_srtp` when no profile is configured.
- The exporter rejects contexts longer than 65535 bytes instead of truncating
  the length prefix, the PRF rejects outputs above `MAX_OUTPUT_LEN` instead of
  panicking, and record sequence numbers refuse to wrap at 2^48.
- The README, loopback test and exporter example requested 60 bytes of SRTP
  keying material ("14-byte salt"); `SRTP_AEAD_AES_128_GCM` needs
  2 × (16 + 12) = 56.
- A malformed ServerKeyExchange or client flight returned an error instead of
  panicking on a missing ServerHello random (unreleased fix since 0.1.0).
- The README states that binaries need macOS 13 or later: security-rs's Swift
  bridge targets macOS 12, and security-rs links apple-cf, whose Swift bridge
  targets macOS 13. 0.1.0 had the same requirement but did not state it.

### Changed

- **Breaking:** `Connection::feed_recv(datagram, peer, now_ms)` takes the
  datagram's source `SocketAddr`.
- **Breaking:** errors from `feed_recv`, `handle_timeout` and
  `set_expected_peer_fingerprint` close the connection (later calls return
  `Error::InvalidState`); malformed, unauthenticated and unexpected records are
  dropped instead of returning errors.
- **Breaking:** `peer_fingerprint()` and `selected_srtp_profile()` return
  `None`, and `export_keying_material()` returns `Error::InvalidState`, until the
  handshake completes.
- **Breaking:** `export_keying_material` returns `ExportedKeyingMaterial`
  (derefs to `[u8]`, zeroized, redacted `Debug`, constant-time `==`).
- **Breaking:** `Error::Alert(u8)` is `Error::Alert { level, description }`,
  and `Error::InvalidArgument` was added.
- **Breaking:** `CookieSecret::compute` and `verify` take the peer `SocketAddr`
  and the parsed `ClientHello`.
- **Breaking:** `Reassembler::feed` takes the record epoch and returns
  `HandshakeMessage` values; `ClientPhase` and `ServerPhase` have one state per
  expected message.
- **Breaking:** `ClientHello` and `ServerHello` have a `version` field,
  `Finished::decode` returns `Result`, `use_srtp::parse` replaces
  `parse_profiles` and also returns the MKI, `client::check_server_hello`
  replaces `client::selected_srtp`, and `client::verify_server_key_exchange`
  takes the negotiated cipher suite.
- **Breaking:** `Flight` stores plaintext `FlightRecord`s so retransmissions can
  be re-encoded; `Flight::push` takes the content type, epoch and plaintext.
- **Breaking:** `EpochSeq::take` returns `Result`; `prf_sha256`, `hmac_sha256`,
  `extended_master_secret` and `EcdheKeyPair::agree` return `Zeroizing` buffers.
- **Breaking:** `Config` has a new public field, `certificate`; code that builds
  a `Config` with a struct literal has to set it (for example with
  `..Config::client()`).
- Requires cryptokit-rs `>=0.3, <0.4` and security-rs `>=0.6, <0.7`, and adds
  zeroize `>=1.6, <1.9`.
- `rust-version` is 1.82.

### Added

- `Certificate` (`generate`, `fingerprint`, `der`) and
  `Config::with_certificate`, so a certificate can be created, and its
  fingerprint published, before the role is known; `Connection::new` still
  generates one when none is given. Clones share one private key, which is
  zeroized on drop and redacted in `Debug`.
- `Connection::set_expected_peer_fingerprint`, `ExportedKeyingMaterial`,
  `record::ReplayWindow`, the `CertificateRequest` codec,
  `client::check_certificate_request`,
  `client::check_initial_renegotiation_info`, `server::check_client_hello`,
  `crypto::constant_time_eq`, `Reassembler::starting_at`, `buffered_bytes`,
  `pending_messages` and `clear`, `EpochSeq::starting_at`, parsers for
  `signature_algorithms` and `ec_point_formats`, `timer::MAX_RETRANSMISSIONS`,
  `RetransmitTimer::expirations`, and a root re-export of `zeroize::Zeroizing`.
- Negative handshake tests driven by a scripted malicious client and server,
  plus reassembler-limit, replay-window, negotiation, secret-hygiene, UDP
  loopback (127.0.0.1) and supplied-certificate tests.

### Removed

- `Flight::to_datagram`, `client::selected_srtp`, `use_srtp::parse_profiles`,
  and the `ClientPhase::{Start, WaitHelloVerify, WaitServerFlight,
  WaitServerFinished}` and `ServerPhase::{WaitClientHelloWithCookie,
  WaitClientFinished}` variants.
- The exporter example no longer prints exported key bytes.

## [0.1.0] - 2026-06-04

Initial release.

### Added

- Sans-I/O DTLS 1.2 ([RFC 6347](https://www.rfc-editor.org/rfc/rfc6347))
  `Connection` state machine driven entirely over in-memory datagram buffers.
- Client and server roles with **mutual authentication** — both peers send a
  Certificate and CertificateVerify.
- Single cipher-suite family: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xC02B)
  and `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (0xC02F) for Firefox interop;
  ECDHE over NIST P-256.
- AES-128-GCM AEAD record protection with epoch handling and the DTLS explicit
  nonce.
- Stateless `HelloVerifyRequest` cookie exchange.
- DTLS handshake fragmentation and in-order reassembly.
- Extended Master Secret ([RFC 7627](https://www.rfc-editor.org/rfc/rfc7627)),
  always negotiated.
- `use_srtp` extension ([RFC 5764](https://www.rfc-editor.org/rfc/rfc5764)) and
  the RFC 5705 `EXTRACTOR-dtls_srtp` keying-material exporter.
- Self-signed P-256 certificate generation, ASN.1/DER emit + parse, and SHA-256
  fingerprint formatting for SDP `a=fingerprint` lines.
- Trust by out-of-band fingerprint comparison; no PKI / chain validation.
- Three runnable examples (self-signed cert, loopback handshake, exporter) and a
  test suite covering the PRF KAT, record layer, message codecs, fragment
  reassembly, cookie exchange, certificate emit/parse, key schedule, the
  `use_srtp` extension, and a full end-to-end loopback handshake.

[0.1.0]: https://github.com/doom-fish/dtls-rs/releases/tag/v0.1.0
