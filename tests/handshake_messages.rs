//! Encode/decode round-trips for the handshake message codecs.

use dtls::extensions::{decode_block, supported_groups, use_srtp, Extension};
use dtls::handshake::messages::{
    frame, msg_type, Certificate, CertificateRequest, CertificateVerify, ClientHello,
    ClientKeyExchange, Finished, HandshakeHeader, HelloVerifyRequest, ServerHello,
    ServerKeyExchange, HANDSHAKE_HEADER_LEN,
};
use dtls::handshake::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
use dtls::record::DTLS_1_2;

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
        version: DTLS_1_2,
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
    assert_eq!(decoded.version, DTLS_1_2);
    assert_eq!(decoded.random, ch.random);
    assert_eq!(decoded.cookie, ch.cookie);
    assert_eq!(decoded.cipher_suites, ch.cipher_suites);
    assert_eq!(decoded.extensions.len(), 2);
}

#[test]
fn server_hello_roundtrip() {
    let sh = ServerHello {
        version: DTLS_1_2,
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

fn with_trailing_byte(mut body: Vec<u8>) -> Vec<u8> {
    body.push(0);
    body
}

#[test]
fn decoders_reject_trailing_bytes() {
    let hvr = HelloVerifyRequest { cookie: vec![1, 2] }.encode();
    assert!(HelloVerifyRequest::decode(&with_trailing_byte(hvr)).is_err());

    let sh = ServerHello {
        version: DTLS_1_2,
        random: [9u8; 32],
        session_id: Vec::new(),
        cipher_suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        compression_method: 0,
        extensions: vec![use_srtp::build(&[use_srtp::SRTP_AEAD_AES_128_GCM])],
    }
    .encode();
    assert!(ServerHello::decode(&with_trailing_byte(sh)).is_err());

    let cert = Certificate {
        certificates: vec![vec![0x30, 0x00]],
    }
    .encode();
    assert!(Certificate::decode(&with_trailing_byte(cert)).is_err());

    let ske = ServerKeyExchange {
        named_curve: supported_groups::SECP256R1,
        public_point: vec![4; 65],
        signature_algorithm: 0x0403,
        signature: vec![1, 2, 3],
    }
    .encode();
    assert!(ServerKeyExchange::decode(&with_trailing_byte(ske)).is_err());

    let cke = ClientKeyExchange {
        public_point: vec![4; 65],
    }
    .encode();
    assert!(ClientKeyExchange::decode(&with_trailing_byte(cke)).is_err());

    let cv = CertificateVerify {
        signature_algorithm: 0x0403,
        signature: vec![5; 8],
    }
    .encode();
    assert!(CertificateVerify::decode(&with_trailing_byte(cv)).is_err());

    let cr = CertificateRequest {
        certificate_types: vec![64],
        signature_algorithms: vec![0x0403],
        certificate_authorities: Vec::new(),
    }
    .encode();
    assert!(CertificateRequest::decode(&with_trailing_byte(cr)).is_err());
}

#[test]
fn certificate_request_roundtrip() {
    let request = CertificateRequest {
        certificate_types: vec![64, 1],
        signature_algorithms: vec![0x0403, 0x0804, 0x0401],
        certificate_authorities: Vec::new(),
    };
    assert_eq!(CertificateRequest::decode(&request.encode()).unwrap(), request);
    assert_eq!(
        dtls::handshake::server::build_certificate_request(),
        request.encode()
    );
}

#[test]
fn finished_requires_twelve_bytes() {
    assert_eq!(Finished::decode(&[7u8; 12]).unwrap().verify_data, vec![7u8; 12]);
    assert!(Finished::decode(&[7u8; 11]).is_err());
    assert!(Finished::decode(&[7u8; 13]).is_err());
}

#[test]
fn certificate_rejects_empty_entries() {
    let body = Certificate {
        certificates: vec![Vec::new()],
    }
    .encode();
    assert!(Certificate::decode(&body).is_err());
}

#[test]
fn extension_block_rejects_duplicates_and_trailing_bytes() {
    let mut block = Vec::new();
    for extension in [Extension::new(23, Vec::new()), Extension::new(23, Vec::new())] {
        extension.encode_into(&mut block);
    }
    let mut encoded = (block.len() as u16).to_be_bytes().to_vec();
    encoded.extend_from_slice(&block);
    assert!(decode_block(&encoded).is_err());

    let mut single = Vec::new();
    Extension::new(23, Vec::new()).encode_into(&mut single);
    let mut encoded = (single.len() as u16).to_be_bytes().to_vec();
    encoded.extend_from_slice(&single);
    assert_eq!(decode_block(&encoded).unwrap().len(), 1);
    encoded.push(0);
    assert!(decode_block(&encoded).is_err());
}
