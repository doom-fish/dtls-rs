# Coverage

`dtls-rs` is a protocol implementation, not an SDK binding, so "coverage" here
means *which parts of the relevant RFC surface are implemented* — scoped to what
the WebRTC DTLS-SRTP profile actually exercises.

## Protocol surface

| Feature | RFC | Status |
| --- | --- | --- |
| DTLS 1.2 record layer (plaintext) | 6347 §4.1 | ✅ implemented |
| DTLS 1.2 record layer (AES-128-GCM AEAD) | 5246 / 5288 | ✅ implemented |
| Epoch + sequence-number handling | 6347 §4.1 | ✅ implemented |
| ChangeCipherSpec | 6347 §4.1 | ✅ implemented |
| ClientHello / ServerHello | 6347 §4.2 | ✅ implemented |
| HelloVerifyRequest + stateless cookie | 6347 §4.2.1 | ✅ implemented |
| Handshake fragmentation + reassembly | 6347 §4.2.3 | ✅ implemented |
| Certificate (emit + parse, self-signed P-256) | 5246 §7.4.2 | ✅ implemented |
| ServerKeyExchange (ECDHE P-256, signed) | 4492 | ✅ implemented |
| CertificateRequest | 5246 §7.4.4 | ✅ implemented |
| ServerHelloDone | 5246 §7.4.5 | ✅ implemented |
| ClientKeyExchange (ECDHE P-256) | 4492 | ✅ implemented |
| CertificateVerify (mutual auth) | 5246 §7.4.8 | ✅ implemented |
| Finished + verify_data | 5246 §7.4.9 | ✅ implemented |
| TLS 1.2 PRF (SHA-256) | 5246 §5 | ✅ implemented |
| Extended Master Secret | 7627 | ✅ implemented (always on) |
| Keying-material exporter | 5705 | ✅ implemented |
| `use_srtp` extension + profiles | 5764 | ✅ implemented |
| `supported_groups`, `ec_point_formats` | 4492 / 8422 | ✅ implemented |
| `signature_algorithms` | 5246 §7.4.1.4.1 | ✅ implemented |
| `renegotiation_info` (sent empty) | 5746 | ✅ implemented |

## Cipher suites

| Suite | Code | Status |
| --- | --- | --- |
| `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | 0xC02B | ✅ |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 0xC02F | ✅ (verify only, for interop) |

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

## Public modules

`asn1`, `cert`, `config`, `connection`, `crypto`, `error`, `exporter`,
`extensions`, `handshake`, `record`, `role`, `timer`.

## Tests

31 unit/integration test functions across 9 files plus one doctest:

- `prf_vectors` — official IETF TLS 1.2 PRF-SHA256 known-answer vector.
- `record_layer` — AES-GCM roundtrip, tamper rejection, replay/sequence rejection.
- `handshake_messages` — message header + body codec roundtrips.
- `fragment_reassembly` — in-order delivery, retransmit drop, oversize rejection.
- `cookie_exchange` — cookie compute/verify binding.
- `cert_emit_parse` — self-signed cert generation, DER parse, fingerprint.
- `key_schedule` — EMS, key expansion split, exporter vs PRF, verify_data length.
- `use_srtp_extension` — profile code points, extension roundtrip.
- `loopback_handshake` — full mutual-auth handshake to completion with
  cross-matched fingerprints and matching exporter output.
