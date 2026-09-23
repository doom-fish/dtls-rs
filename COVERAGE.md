# Coverage

`dtls-rs` is a protocol implementation, not an SDK binding, so "coverage" here
means *which parts of the relevant RFC surface are implemented* — scoped to what
the WebRTC DTLS-SRTP profile actually exercises. "Implemented" means the
feature exists and is exercised by the test suite; it is not a claim of
interoperability testing against other DTLS stacks (see the gaps below).

## Protocol surface

| Feature | RFC | Status |
| --- | --- | --- |
| DTLS 1.2 record layer (plaintext) | 6347 §4.1 | ✅ implemented |
| DTLS 1.2 record layer (AES-128-GCM AEAD) | 5246 / 5288 | ✅ implemented |
| Epoch + sequence-number handling | 6347 §4.1 | ✅ implemented; 48-bit counters refuse to wrap |
| Anti-replay window | 6347 §4.1.2.6 | ✅ 64-record window for protected (epoch 1) records, updated only after authentication; plaintext epoch-0 duplicates are discarded by `message_seq` |
| Invalid record handling | 6347 §4.1.2.7 | ✅ malformed, unauthenticated and unexpected records are discarded silently |
| ChangeCipherSpec | 6347 §4.1 | ✅ accepted only after the last pre-CCS message of the flight |
| ClientHello / ServerHello | 6347 §4.2 | ✅ implemented, with negotiation checks on both sides |
| HelloVerifyRequest + stateless cookie | 6347 §4.2.1 | ✅ server always sends it statelessly, cookie bound to the peer address and ClientHello parameters; client accepts servers that skip it and repeated HelloVerifyRequests |
| Handshake state machines (message order) | 5246 §7.3, 6347 §4.2 | ✅ explicit client and server state machines; violations are fatal |
| Handshake fragmentation + reassembly | 6347 §4.2.3 | ✅ receive side, bounded (64 KiB per message, 128 KiB buffered, 8-message window); ⚠️ outgoing messages are never fragmented |
| Timeout and retransmission | 6347 §4.2.4 | ✅ exponential backoff, fresh record sequence numbers, completed server resends its final flight, `Error::Timeout` after 6 retransmissions |
| Alerts | 5246 §7.2, 6347 §4.2.7 | ✅ fatal alerts sent on failure; peer alerts honoured when authenticated, or in plaintext only before the peer's ChangeCipherSpec |
| Certificate (emit + parse, self-signed P-256) | 5246 §7.4.2 | ✅ implemented |
| Fingerprint pinning | 5763 §5, 8122 | ✅ checked in constant time when the peer's Certificate arrives |
| ServerKeyExchange (ECDHE P-256, signed) | 4492 | ✅ implemented |
| CertificateRequest | 5246 §7.4.4 | ✅ server always sends it; client checks and answers it |
| ServerHelloDone | 5246 §7.4.5 | ✅ implemented |
| ClientKeyExchange (ECDHE P-256) | 4492 | ✅ implemented |
| CertificateVerify (mutual auth) | 5246 §7.4.8 | ✅ required by the server |
| Finished + verify_data | 5246 §7.4.9 | ✅ implemented, compared in constant time |
| TLS 1.2 PRF (SHA-256) | 5246 §5 | ✅ implemented |
| Extended Master Secret | 7627 | ✅ implemented (always on; required from the peer) |
| Keying-material exporter | 5705 | ✅ available after the peer's Finished is verified |
| `use_srtp` extension + profiles | 5764 | ✅ implemented (empty MKI only) |
| `supported_groups`, `ec_point_formats` | 4492 / 8422 | ✅ implemented |
| `signature_algorithms` | 5246 §7.4.1.4.1 | ✅ implemented |
| `renegotiation_info` (sent empty) | 5746 | ✅ implemented; a non-empty value is rejected |

## Cipher suites

| Suite | Code | Status |
| --- | --- | --- |
| `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | 0xC02B | ✅ client and server |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 0xC02F | ✅ client only (verifies RSA server certificates); the server's certificate is ECDSA, so it never selects this suite |

## Cryptographic primitives

All primitives are delegated to sibling crates, not reimplemented:

| Primitive | Provided by |
| --- | --- |
| SHA-256 | `cryptokit-rs` |
| HMAC-SHA-256 | `cryptokit-rs` |
| AES-128-GCM | `cryptokit-rs` |
| ECDHE P-256 | `cryptokit-rs` |
| ECDSA P-256 sign/verify | `cryptokit-rs` |
| RSA signature verify | `security-rs` |
| CSPRNG | `security-rs` |

## Public modules

`asn1`, `cert`, `config`, `connection`, `crypto`, `error`, `exporter`,
`extensions`, `handshake`, `record`, `role`, `timer`.

## Tests

121 integration test functions across 13 files plus one doctest:

- `prf_vectors` — official IETF TLS 1.2 PRF-SHA256 known-answer vector, output cap.
- `record_layer` — AES-GCM roundtrip, tamper and sequence-number rejection, anti-replay window, non-wrapping sequence numbers.
- `handshake_messages` — header and body codec roundtrips, trailing-byte and duplicate-extension rejection.
- `hello_negotiation` — ClientHello and ServerHello checks (versions, suites, EMS, SRTP, extensions), CertificateRequest and ServerKeyExchange checks.
- `fragment_reassembly` — in-order delivery, overlaps, retransmit drop, length cap, buffer limit, sequence window, freeing, `message_seq` exhaustion.
- `cookie_exchange` — cookie binding to the peer address, port and ClientHello parameters.
- `cert_emit_parse` — self-signed cert generation, DER parse, fingerprint.
- `key_schedule` — EMS, key expansion split, exporter vs PRF, verify_data length, context length.
- `use_srtp_extension` — profile code points, strict parsing, roundtrip.
- `secret_hygiene` — redacted `Debug`, constant-time comparison.
- `handshake_state_machine` — a scripted malicious client and server: Finished without Certificate/CertificateVerify, second and swapped certificates, pin mismatches, out-of-order, duplicate and unprotected messages, bad Finished, unauthenticated and authenticated alerts, stateless HelloVerifyRequest handling, a server that skips HelloVerifyRequest and CertificateRequest.
- `loopback_handshake` — full mutual-auth handshake with cross-matched fingerprints and matching exporter output, pinning, gating of keys until Finished, retransmission, replay, timeout, spoofed ClientHello, cookie address binding.
- `udp_loopback` — a pinned handshake over two UDP sockets bound to 127.0.0.1.
