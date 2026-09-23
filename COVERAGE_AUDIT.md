# Coverage audit

Unlike the SDK-binding crates in this workspace, `dtls-rs` has no Apple
swiftinterface to diff against — it is a from-scratch protocol implementation.
This audit is therefore an **honest wrapper-vs-specification diff**: it states
exactly which spec features are implemented, which are deliberately omitted, and
where behaviour is delegated to another crate.

## Methodology

The reference surface is the set of features the **WebRTC DTLS-SRTP** profile
requires, drawn from RFC 6347 (DTLS 1.2), RFC 5246 (TLS 1.2), RFC 5764
(DTLS-SRTP), RFC 5705 (exporter), RFC 7627 (extended master secret), and
RFC 4492/8422 (ECC cipher suites). Anything outside that profile is recorded as
an intentional gap, not a defect.

## 🟢 Implemented and exercised

| Feature | Where | Test |
| --- | --- | --- |
| Plaintext + AEAD record layer, anti-replay window | `record/{plaintext,ciphertext,epoch}.rs` | `record_layer` |
| TLS 1.2 PRF (SHA-256) | `crypto/prf.rs` | `prf_vectors` (IETF KAT) |
| Handshake message and extension codecs (strict) | `handshake/messages.rs`, `extensions/*.rs` | `handshake_messages`, `use_srtp_extension` |
| ClientHello / ServerHello negotiation checks | `handshake/{client,server}.rs` | `hello_negotiation` |
| Stateless cookie bound to the peer address | `handshake/cookie.rs`, `connection.rs` | `cookie_exchange`, `loopback_handshake` |
| Bounded fragmentation / reassembly | `handshake/fragment.rs` | `fragment_reassembly` |
| Self-signed cert emit/parse/fingerprint | `cert/*.rs`, `asn1.rs` | `cert_emit_parse` |
| ECDHE P-256 key agreement | `crypto/ecdhe_p256.rs` | `loopback_handshake`, `handshake_state_machine` |
| ECDSA P-256 sign/verify | `crypto/ecdsa_{sign,verify}.rs` | `loopback_handshake`, `hello_negotiation` |
| Key schedule + EMS | `handshake/keyschedule.rs` | `key_schedule`, `handshake_state_machine` |
| RFC 5705 exporter | `exporter.rs` | `key_schedule`, `loopback_handshake` |
| `use_srtp` extension | `extensions/use_srtp.rs` | `use_srtp_extension`, `hello_negotiation` |
| Client and server handshake state machines | `connection.rs` | `handshake_state_machine`, `loopback_handshake` |
| Fingerprint pinning | `config.rs`, `connection.rs` | `loopback_handshake`, `handshake_state_machine`, `udp_loopback` |
| Retransmission, final-flight resend, timeout | `connection.rs`, `timer.rs`, `handshake/flight.rs` | `loopback_handshake` |
| Secret redaction and zeroization | `record/ciphertext.rs`, `handshake/{keyschedule,cookie}.rs`, `exporter.rs` | `secret_hygiene` |
| Full handshake to completion | `connection.rs` | `loopback_handshake`, `udp_loopback` |

Correction to the previous version of this file: it said the loopback test
proved that CertificateVerify was required, because the server could only
cross-check the client's fingerprint after verifying it. That was wrong. The
2026-09-23 audit showed that the server accepted Finished without Certificate or
CertificateVerify, and that a later Certificate replaced a verified key, so the
loopback test only showed that an honest peer completes. The requirement is now
enforced by the state machine and covered by the negative tests in
`handshake_state_machine`, which drive a scripted malicious client and server.

## 🟡 Delegated (not reimplemented here)

| Primitive | Delegated to | Rationale |
| --- | --- | --- |
| SHA-256 / HMAC / AES-GCM / ECDHE / ECDSA | `cryptokit-rs` | System-vetted, constant-time primitives; reimplementing crypto in this crate would be a liability. |
| RSA signature verification | `security-rs` | Only needed for ECDHE-RSA interop (Firefox); `SecKey` verification avoids a bespoke RSA/PKCS#1 implementation. |

These are counted as covered: the protocol logic that *uses* them lives here and
is tested end-to-end.

## 🔴 Intentional gaps (out of profile)

| Omitted | Reason |
| --- | --- |
| DTLS 1.0 and DTLS 1.3 | WebRTC negotiates 1.2 in practice; 1.3 record/handshake is a separate effort. |
| TLS over TCP | This crate is datagram-only by design. |
| Session resumption / session tickets | Not used by the WebRTC media handshake. |
| RSA **key exchange** (static RSA) | Forbidden by the profile; only ECDHE is allowed. |
| CBC / non-GCM cipher suites | GCM-only by policy; avoids the Lucky-13 / padding-oracle surface. |
| Curves other than P-256 | The profile pins P-256; no P-384/P-521/X25519 here. |
| PKI / certificate-chain validation | Trust is by out-of-band fingerprint; there is no CA path to validate. |
| Built-in sockets, threads, timers | Sans-I/O by design — the caller drives all transport and retransmission timing. The `timer` module only computes DTLS retransmit deadlines; it does not sleep. |
| Renegotiation | `renegotiation_info` is sent empty (RFC 5746 minimal compliance); renegotiation itself is not supported and is not used by WebRTC. |
| Application data, sending `close_notify` | The crate only negotiates keys for SRTP; there is no API to send or receive application data or to close the association. Received application data is dropped. |
| Fragmenting outgoing handshake messages | Each outgoing message is sent in one record. WebRTC certificates fit comfortably; there is no PMTU back-off. |
| SRTP MKI, connection IDs | Not used by WebRTC. |

## ⚠️ Known deviations and limits

| Item | Detail |
| --- | --- |
| HelloVerifyRequest version | RFC 6347 §4.2.1 says servers SHOULD put DTLS 1.0 in `server_version`; this server sends DTLS 1.2. Clients must ignore the field, and this crate's client does. |
| Epoch-0 replay | The anti-replay window covers protected records. Plaintext handshake records are unauthenticated, so duplicates are discarded by `message_seq` instead of a record window an attacker could advance. |
| Handshake injection | Plaintext handshake messages are unauthenticated until Finished. An attacker who can inject packets on the flow can make a handshake fail (as with any DTLS 1.2 stack), but cannot make it complete with the wrong peer. Source-address filtering belongs to the transport (ICE). |
| Interoperability | Tests run against this crate itself and against scripted peers built from its own codecs; there is no automated interop test against another DTLS implementation yet. |

## Summary

- Features in the WebRTC DTLS-SRTP profile are implemented, with the
  deviations and limits listed above.
- The handshake enforces message order and peer authentication, and the
  negative tests exercise the attacks from the 2026-09-23 audit.
- Cryptographic primitives are delegated to sibling crates.
- Everything omitted is outside the WebRTC DTLS-SRTP profile and recorded
  above as a deliberate decision.
- This is a specification diff for a protocol crate, not an SDK-symbol diff, so
  its format differs from the COVERAGE_AUDIT files of the binding crates.
