//! Out-of-order and fragmented handshake reassembly.

use dtls::handshake::messages::{msg_type, HandshakeHeader};
use dtls::handshake::Reassembler;

fn header(msg_type: u8, message_seq: u16, total: u32, offset: u32, len: u32) -> HandshakeHeader {
    HandshakeHeader {
        msg_type,
        length: total,
        message_seq,
        fragment_offset: offset,
        fragment_length: len,
    }
}

#[test]
fn reassembles_split_message() {
    let mut r = Reassembler::new();
    let body = b"abcdefghij"; // 10 bytes
    // Deliver the second half first.
    let out = r
        .feed(&header(msg_type::CERTIFICATE, 0, 10, 5, 5), &body[5..])
        .unwrap();
    assert!(out.is_empty(), "message not yet complete");
    let out = r
        .feed(&header(msg_type::CERTIFICATE, 0, 10, 0, 5), &body[..5])
        .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0], (msg_type::CERTIFICATE, 0, body.to_vec()));
}

#[test]
fn delivers_in_message_seq_order() {
    let mut r = Reassembler::new();
    // seq 1 arrives before seq 0; nothing should be delivered yet.
    let out = r
        .feed(&header(msg_type::SERVER_HELLO, 1, 3, 0, 3), b"two")
        .unwrap();
    assert!(out.is_empty());
    // seq 0 arrives, unblocking both.
    let out = r
        .feed(&header(msg_type::CLIENT_HELLO, 0, 3, 0, 3), b"one")
        .unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].1, 0);
    assert_eq!(out[1].1, 1);
}

#[test]
fn ignores_retransmit_of_delivered_message() {
    let mut r = Reassembler::new();
    let out = r
        .feed(&header(msg_type::CLIENT_HELLO, 0, 3, 0, 3), b"one")
        .unwrap();
    assert_eq!(out.len(), 1);
    // A duplicate of seq 0 is silently dropped.
    let out = r
        .feed(&header(msg_type::CLIENT_HELLO, 0, 3, 0, 3), b"one")
        .unwrap();
    assert!(out.is_empty());
}

#[test]
fn rejects_fragment_beyond_message_length() {
    let mut r = Reassembler::new();
    assert!(r
        .feed(&header(msg_type::CERTIFICATE, 0, 4, 2, 5), b"toolong")
        .is_err());
}
