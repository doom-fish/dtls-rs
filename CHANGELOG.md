# Changelog

All notable changes to `dtls-rs` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025

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
