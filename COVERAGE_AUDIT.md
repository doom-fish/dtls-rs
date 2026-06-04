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
| Plaintext + AEAD record layer | `record/{plaintext,ciphertext,epoch}.rs` | `record_layer` |
| TLS 1.2 PRF (SHA-256) | `crypto/prf.rs` | `prf_vectors` (IETF KAT) |
| ClientHello / ServerHello / HVR | `handshake/messages.rs` | `handshake_messages` |
| Stateless cookie | `handshake/cookie.rs` | `cookie_exchange` |
| Fragmentation / reassembly | `handshake/fragment.rs` | `fragment_reassembly` |
| Self-signed cert emit/parse/fingerprint | `cert/*.rs`, `asn1.rs` | `cert_emit_parse` |
| ECDHE P-256 key agreement | `crypto/ecdhe_p256.rs` | `loopback_handshake` |
| ECDSA P-256 sign/verify | `crypto/ecdsa_{sign,verify}.rs` | `loopback_handshake` |
| Key schedule + EMS | `handshake/keyschedule.rs` | `key_schedule` |
| RFC 5705 exporter | `exporter.rs` | `key_schedule`, `loopback_handshake` |
| `use_srtp` extension | `extensions/use_srtp.rs` | `use_srtp_extension` |
| Mutual auth (Certificate + CertificateVerify both ways) | `handshake/{client,server}.rs`, `connection.rs` | `loopback_handshake` |
| Full handshake to completion | `connection.rs` | `loopback_handshake` |

The `CertificateVerify` path — noted in earlier drafts as deferred — is now
**fully implemented and required**: the loopback test only passes because the
server learns and verifies the client's certificate, so both endpoints can
cross-check the SDP fingerprint.

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

## Summary

- Spec features in profile: **fully implemented**.
- Cryptographic primitives: **delegated to audited sibling crates**.
- Everything omitted is **outside the WebRTC DTLS-SRTP profile** and recorded
  above as a deliberate decision, not a missing capability.
