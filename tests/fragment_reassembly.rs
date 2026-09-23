//! Out-of-order and fragmented handshake reassembly.

use dtls::handshake::fragment::{
    HandshakeMessage, MAX_BUFFERED_BYTES, MAX_MESSAGE_LEN, SEQUENCE_WINDOW,
};
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

fn whole(r: &mut Reassembler, msg_type: u8, seq: u16, body: &[u8]) -> Vec<HandshakeMessage> {
    let len = body.len() as u32;
    r.feed(0, &header(msg_type, seq, len, 0, len), body).unwrap()
}

#[test]
fn reassembles_split_message() {
    let mut r = Reassembler::new();
    let body = b"abcdefghij";
    let out = r
        .feed(0, &header(msg_type::CERTIFICATE, 0, 10, 5, 5), &body[5..])
        .unwrap();
    assert!(out.is_empty(), "message not yet complete");
    let out = r
        .feed(0, &header(msg_type::CERTIFICATE, 0, 10, 0, 5), &body[..5])
        .unwrap();
    assert_eq!(
        out,
        vec![HandshakeMessage {
            msg_type: msg_type::CERTIFICATE,
            message_seq: 0,
            epoch: 0,
            body: body.to_vec(),
        }]
    );
}

#[test]
fn delivers_in_message_seq_order() {
    let mut r = Reassembler::new();
    assert!(whole(&mut r, msg_type::SERVER_HELLO, 1, b"two").is_empty());
    let out = whole(&mut r, msg_type::CLIENT_HELLO, 0, b"one");
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].message_seq, 0);
    assert_eq!(out[1].message_seq, 1);
    assert_eq!(r.next_seq(), 2);
}

#[test]
fn ignores_retransmit_of_delivered_message() {
    let mut r = Reassembler::new();
    assert_eq!(whole(&mut r, msg_type::CLIENT_HELLO, 0, b"one").len(), 1);
    assert!(whole(&mut r, msg_type::CLIENT_HELLO, 0, b"one").is_empty());
    assert_eq!(r.next_seq(), 1);
}

#[test]
fn rejects_fragment_beyond_message_length() {
    let mut r = Reassembler::new();
    assert!(r
        .feed(0, &header(msg_type::CERTIFICATE, 0, 4, 2, 5), b"toolong")
        .is_err());
}

#[test]
fn handles_overlapping_fragments_without_double_counting() {
    let mut r = Reassembler::new();
    let body = b"0123456789";
    assert!(r
        .feed(0, &header(msg_type::CERTIFICATE, 0, 10, 0, 6), &body[..6])
        .unwrap()
        .is_empty());
    let after_first = r.buffered_bytes();
    assert!(r
        .feed(0, &header(msg_type::CERTIFICATE, 0, 10, 2, 4), &body[2..6])
        .unwrap()
        .is_empty());
    assert_eq!(r.buffered_bytes(), after_first, "duplicate bytes are not stored twice");
    let out = r
        .feed(0, &header(msg_type::CERTIFICATE, 0, 10, 4, 6), &body[4..])
        .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].body, body);
}

#[test]
fn rejects_declared_length_above_cap() {
    let mut r = Reassembler::new();
    let err = r
        .feed(0, &header(msg_type::CERTIFICATE, 0, MAX_MESSAGE_LEN + 1, 0, 1), b"x")
        .unwrap_err();
    assert!(err.to_string().contains("exceeds"), "{err}");
    assert_eq!(r.pending_messages(), 0);
    assert_eq!(r.buffered_bytes(), 0);
}

#[test]
fn delivers_message_at_length_cap() {
    let mut r = Reassembler::new();
    let body = vec![0x5a; MAX_MESSAGE_LEN as usize];
    let out = whole(&mut r, msg_type::CERTIFICATE, 0, &body);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].body.len(), MAX_MESSAGE_LEN as usize);
}

#[test]
fn sparse_fragment_does_not_allocate_the_declared_length() {
    let mut r = Reassembler::new();
    let out = r
        .feed(
            0,
            &header(msg_type::CERTIFICATE, 0, MAX_MESSAGE_LEN, MAX_MESSAGE_LEN - 1, 1),
            b"x",
        )
        .unwrap();
    assert!(out.is_empty());
    assert!(r.buffered_bytes() < 128, "{} bytes buffered", r.buffered_bytes());
}

#[test]
fn total_buffered_bytes_are_bounded() {
    let mut r = Reassembler::new();
    let chunk = vec![0u8; 16 * 1024];
    let mut hit_limit = false;
    'outer: for seq in 1..SEQUENCE_WINDOW {
        for part in 0..3u32 {
            let offset = part * 16 * 1024;
            let result = r.feed(
                0,
                &header(msg_type::CERTIFICATE, seq, MAX_MESSAGE_LEN, offset, 16 * 1024),
                &chunk,
            );
            if result.is_err() {
                hit_limit = true;
                break 'outer;
            }
            assert!(r.buffered_bytes() <= MAX_BUFFERED_BYTES);
        }
    }
    assert!(hit_limit, "the buffer limit must be enforced");
    assert!(r.buffered_bytes() <= MAX_BUFFERED_BYTES);
}

#[test]
fn ignores_sequences_outside_the_window() {
    let mut r = Reassembler::new();
    let far = r
        .feed(0, &header(msg_type::FINISHED, SEQUENCE_WINDOW, 12, 0, 1), b"x")
        .unwrap();
    assert!(far.is_empty());
    assert_eq!(r.pending_messages(), 0);
    assert_eq!(r.buffered_bytes(), 0);

    let near = r
        .feed(0, &header(msg_type::FINISHED, SEQUENCE_WINDOW - 1, 12, 0, 1), b"x")
        .unwrap();
    assert!(near.is_empty());
    assert_eq!(r.pending_messages(), 1);
}

#[test]
fn completed_messages_are_freed() {
    let mut r = Reassembler::new();
    assert!(whole(&mut r, msg_type::SERVER_HELLO, 1, b"later").is_empty());
    assert!(r.buffered_bytes() > 0);
    assert_eq!(whole(&mut r, msg_type::CLIENT_HELLO, 0, b"first").len(), 2);
    assert_eq!(r.pending_messages(), 0);
    assert_eq!(r.buffered_bytes(), 0);
}

#[test]
fn clear_frees_partial_messages() {
    let mut r = Reassembler::new();
    r.feed(0, &header(msg_type::CERTIFICATE, 0, 100, 0, 10), &[1u8; 10])
        .unwrap();
    assert_eq!(r.pending_messages(), 1);
    r.clear();
    assert_eq!(r.pending_messages(), 0);
    assert_eq!(r.buffered_bytes(), 0);
    assert_eq!(r.next_seq(), 0);
}

#[test]
fn zero_length_messages_advance_in_order() {
    let mut r = Reassembler::new();
    for seq in 0..100u16 {
        let out = whole(&mut r, msg_type::SERVER_HELLO_DONE, seq, &[]);
        assert_eq!(out.len(), 1);
        assert!(out[0].body.is_empty());
    }
    assert_eq!(r.next_seq(), 100);
    assert_eq!(r.buffered_bytes(), 0);
}

#[test]
fn message_seq_exhaustion_is_an_error_not_a_wrap() {
    let mut r = Reassembler::starting_at(u16::MAX - 1);
    assert_eq!(whole(&mut r, msg_type::SERVER_HELLO_DONE, u16::MAX - 1, &[]).len(), 1);
    assert_eq!(r.next_seq(), u16::MAX);
    let err = r
        .feed(0, &header(msg_type::SERVER_HELLO_DONE, u16::MAX, 0, 0, 0), &[])
        .unwrap_err();
    assert!(err.to_string().contains("exhausted"), "{err}");
    assert_eq!(r.next_seq(), u16::MAX);
    assert!(whole(&mut Reassembler::starting_at(u16::MAX), 1, 0, b"old").is_empty());
}

#[test]
fn rejects_inconsistent_metadata() {
    let mut r = Reassembler::new();
    r.feed(0, &header(msg_type::CERTIFICATE, 0, 10, 0, 5), &[0u8; 5])
        .unwrap();
    assert!(r
        .feed(0, &header(msg_type::CERTIFICATE, 0, 11, 5, 5), &[0u8; 5])
        .is_err());
    assert!(r
        .feed(0, &header(msg_type::SERVER_KEY_EXCHANGE, 0, 10, 5, 5), &[0u8; 5])
        .is_err());
    assert!(r
        .feed(1, &header(msg_type::CERTIFICATE, 0, 10, 5, 5), &[0u8; 5])
        .is_err());
}

#[test]
fn reports_the_record_epoch() {
    let mut r = Reassembler::starting_at(5);
    let out = r
        .feed(1, &header(msg_type::FINISHED, 5, 12, 0, 12), &[7u8; 12])
        .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].epoch, 1);
    assert_eq!(out[0].message_seq, 5);
}

#[test]
fn rejects_fragment_length_mismatch() {
    let mut r = Reassembler::new();
    assert!(r
        .feed(0, &header(msg_type::CERTIFICATE, 0, 10, 0, 5), &[0u8; 4])
        .is_err());
}

#[test]
fn many_tiny_interleaved_and_duplicate_fragments_reassemble_correctly() {
    let mut r = Reassembler::new();
    let body: Vec<u8> = (0..1200u32).map(|i| (i % 251) as u8).collect();
    let len = body.len() as u32;
    for offset in (0..len).step_by(2) {
        let out = r
            .feed(
                0,
                &header(msg_type::CERTIFICATE, 0, len, offset, 1),
                &body[offset as usize..=offset as usize],
            )
            .unwrap();
        assert!(out.is_empty());
    }
    let buffered = r.buffered_bytes();
    for _ in 0..3 {
        for offset in (0..len).step_by(2) {
            r.feed(
                0,
                &header(msg_type::CERTIFICATE, 0, len, offset, 1),
                &body[offset as usize..=offset as usize],
            )
            .unwrap();
        }
    }
    assert_eq!(r.buffered_bytes(), buffered);
    let out = r
        .feed(0, &header(msg_type::CERTIFICATE, 0, len, 0, len), &body)
        .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].body, body);
    assert_eq!(r.buffered_bytes(), 0);
}
