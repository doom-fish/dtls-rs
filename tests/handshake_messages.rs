//! Encode/decode round-trips for the handshake message codecs.

use dtls::extensions::{supported_groups, use_srtp};
use dtls::handshake::messages::{
    frame, msg_type, Certificate, ClientHello, HandshakeHeader, HelloVerifyRequest, ServerHello,
    HANDSHAKE_HEADER_LEN,
};
use dtls::handshake::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

#[test]
fn handshake_header_roundtrip() {
    let header = HandshakeHeader {
        msg_type: msg_type::CLIENT_HELLO,
        length: 0x0001_0203,
        message_seq: 0x0405,
        fragment_offset: 0x0000_0006,
        fragment_length: 0x0001_0203,
    };
    let bytes = header.encode();
    let decoded = HandshakeHeader::decode(&bytes).unwrap();
    assert_eq!(decoded.msg_type, header.msg_type);
    assert_eq!(decoded.length, header.length);
    assert_eq!(decoded.message_seq, header.message_seq);
    assert_eq!(decoded.fragment_offset, header.fragment_offset);
    assert_eq!(decoded.fragment_length, header.fragment_length);
}

#[test]
fn frame_is_canonical_unfragmented() {
    let body = b"hello body";
    let framed = frame(msg_type::FINISHED, 3, body);
    assert_eq!(framed.len(), HANDSHAKE_HEADER_LEN + body.len());
    let header = HandshakeHeader::decode(&framed).unwrap();
    assert_eq!(header.fragment_offset, 0);
    assert_eq!(header.fragment_length as usize, body.len());
    assert_eq!(header.length as usize, body.len());
    assert_eq!(&framed[HANDSHAKE_HEADER_LEN..], body);
}

#[test]
fn client_hello_roundtrip() {
    let ch = ClientHello {
        random: [7u8; 32],
        session_id: Vec::new(),
        cookie: vec![1, 2, 3, 4],
        cipher_suites: vec![TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
        compression_methods: vec![0],
        extensions: vec![
            supported_groups::build(&[supported_groups::SECP256R1]),
            use_srtp::build(&[use_srtp::SRTP_AEAD_AES_128_GCM]),
        ],
    };
    let encoded = ch.encode();
    let decoded = ClientHello::decode(&encoded).unwrap();
    assert_eq!(decoded.random, ch.random);
    assert_eq!(decoded.cookie, ch.cookie);
    assert_eq!(decoded.cipher_suites, ch.cipher_suites);
    assert_eq!(decoded.extensions.len(), 2);
}

#[test]
fn server_hello_roundtrip() {
    let sh = ServerHello {
        random: [9u8; 32],
        session_id: Vec::new(),
        cipher_suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        compression_method: 0,
        extensions: vec![use_srtp::build(&[use_srtp::SRTP_AEAD_AES_128_GCM])],
    };
    let decoded = ServerHello::decode(&sh.encode()).unwrap();
    assert_eq!(decoded.random, sh.random);
    assert_eq!(decoded.cipher_suite, sh.cipher_suite);
    assert_eq!(decoded.extensions.len(), 1);
}

#[test]
fn hello_verify_request_roundtrip() {
    let hvr = HelloVerifyRequest {
        cookie: vec![0xde, 0xad, 0xbe, 0xef],
    };
    let decoded = HelloVerifyRequest::decode(&hvr.encode()).unwrap();
    assert_eq!(decoded.cookie, hvr.cookie);
}

#[test]
fn certificate_roundtrip() {
    let cert = Certificate {
        certificates: vec![vec![0x30, 0x03, 0x01, 0x02, 0x03], vec![0x30, 0x01, 0xff]],
    };
    let decoded = Certificate::decode(&cert.encode()).unwrap();
    assert_eq!(decoded.certificates, cert.certificates);
}
