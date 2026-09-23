//! AES-128-GCM record protection round-trips and tamper detection.

use dtls::record::ciphertext::{protect, unprotect, AeadKeys};
use dtls::record::{content_type, DTLS_1_2};

fn keys() -> AeadKeys {
    AeadKeys {
        key: [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ],
        salt: [0xaa, 0xbb, 0xcc, 0xdd],
    }
}

#[test]
fn aes_gcm_record_roundtrip() {
    let keys = keys();
    let plaintext = b"the quick brown fox jumps over the lazy dog";
    let fragment = protect(
        &keys,
        1,
        7,
        content_type::APPLICATION_DATA,
        DTLS_1_2,
        plaintext,
    )
    .unwrap();
    // Wire fragment = 8-byte explicit nonce + ciphertext + 16-byte tag.
    assert_eq!(fragment.len(), 8 + plaintext.len() + 16);
    let recovered = unprotect(
        &keys,
        1,
        7,
        content_type::APPLICATION_DATA,
        DTLS_1_2,
        &fragment,
    )
    .unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn aes_gcm_record_rejects_tampering() {
    let keys = keys();
    let mut fragment = protect(
        &keys,
        1,
        1,
        content_type::APPLICATION_DATA,
        DTLS_1_2,
        b"secret payload",
    )
    .unwrap();
    let last = fragment.len() - 1;
    fragment[last] ^= 0x01;
    assert!(unprotect(
        &keys,
        1,
        1,
        content_type::APPLICATION_DATA,
        DTLS_1_2,
        &fragment
    )
    .is_err());
}

#[test]
fn aes_gcm_record_rejects_wrong_sequence() {
    let keys = keys();
    let fragment = protect(
        &keys,
        1,
        1,
        content_type::APPLICATION_DATA,
        DTLS_1_2,
        b"payload",
    )
    .unwrap();
    // The sequence number is part of the AAD, so a mismatch must fail.
    assert!(unprotect(
        &keys,
        1,
        2,
        content_type::APPLICATION_DATA,
        DTLS_1_2,
        &fragment
    )
    .is_err());
}

#[test]
fn replay_window_rejects_duplicates_and_stale_records() {
    use dtls::record::epoch::REPLAY_WINDOW_SIZE;
    use dtls::record::ReplayWindow;

    let mut window = ReplayWindow::new();
    assert!(window.accepts(5));
    window.mark(5);
    assert!(!window.accepts(5), "duplicate");
    assert!(window.accepts(4), "older but inside the window");
    window.mark(4);
    assert!(!window.accepts(4));
    assert!(window.accepts(6));
    window.mark(100);
    assert!(!window.accepts(100));
    assert!(!window.accepts(100 - REPLAY_WINDOW_SIZE), "left of the window");
    assert!(window.accepts(100 - REPLAY_WINDOW_SIZE + 1));
    assert!(!window.accepts(5), "stale after the window moved");
    window.mark(100 + 10 * REPLAY_WINDOW_SIZE);
    assert!(window.accepts(100 + 10 * REPLAY_WINDOW_SIZE - 1));
    assert!(!window.accepts(100));
}

#[test]
fn record_sequence_numbers_do_not_wrap() {
    use dtls::record::epoch::MAX_SEQUENCE;
    use dtls::record::EpochSeq;

    let mut seq = EpochSeq::starting_at(MAX_SEQUENCE);
    assert_eq!(seq.take().unwrap(), MAX_SEQUENCE);
    assert!(seq.take().is_err());
    assert!(seq.take().is_err());
}
