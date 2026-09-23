use dtls::cert::generate;
use dtls::cert::parse::parse_leaf_public_key;
use dtls::extensions::{
    ec_point_formats, ext_type, extended_master_secret, renegotiation_info, signature_algorithms,
    supported_groups, use_srtp, Extension,
};
use dtls::handshake::client::{
    build_client_hello, check_certificate_request, check_server_hello, verify_server_key_exchange,
};
use dtls::handshake::messages::{CertificateRequest, ClientHello, ServerHello, ServerKeyExchange};
use dtls::handshake::server::{build_server_key_exchange, check_client_hello};
use dtls::handshake::{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256};
use dtls::record::DTLS_1_2;
use dtls::Error;

const GCM128: u16 = use_srtp::SRTP_AEAD_AES_128_GCM;
const GCM256: u16 = use_srtp::SRTP_AEAD_AES_256_GCM;

fn offered_hello() -> ClientHello {
    ClientHello::decode(&build_client_hello([1u8; 32], &[], &[GCM128, GCM256])).unwrap()
}

fn without(mut hello: ClientHello, extension_type: u16) -> ClientHello {
    hello.extensions.retain(|e| e.extension_type != extension_type);
    hello
}

fn replace(mut extensions: Vec<Extension>, extension: Extension) -> Vec<Extension> {
    extensions.retain(|e| e.extension_type != extension.extension_type);
    extensions.push(extension);
    extensions
}

fn good_server_hello() -> ServerHello {
    ServerHello {
        version: DTLS_1_2,
        random: [2u8; 32],
        session_id: Vec::new(),
        cipher_suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        compression_method: 0,
        extensions: vec![
            use_srtp::build(&[GCM128]),
            ec_point_formats::build(&[ec_point_formats::UNCOMPRESSED]),
            extended_master_secret::build(),
            renegotiation_info::build(),
        ],
    }
}

fn negotiation(err: &Error) -> bool {
    matches!(err, Error::Negotiation(_))
}

#[test]
fn server_accepts_our_client_hello_and_prefers_its_own_srtp_order() {
    let choice = check_client_hello(&offered_hello(), &[GCM256, GCM128]).unwrap();
    assert_eq!(choice.cipher_suite, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    assert_eq!(choice.srtp_profile, Some(GCM256));
    let none = check_client_hello(&without(offered_hello(), ext_type::USE_SRTP), &[GCM128]).unwrap();
    assert_eq!(none.srtp_profile, None);
}

#[test]
fn server_requires_extended_master_secret() {
    let hello = without(offered_hello(), ext_type::EXTENDED_MASTER_SECRET);
    assert!(negotiation(&check_client_hello(&hello, &[GCM128]).unwrap_err()));
}

#[test]
fn server_only_selects_the_ecdsa_suite() {
    let mut hello = offered_hello();
    hello.cipher_suites = vec![TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256];
    assert!(negotiation(&check_client_hello(&hello, &[GCM128]).unwrap_err()));
}

#[test]
fn server_rejects_dtls_1_0_and_non_dtls_versions() {
    let mut hello = offered_hello();
    hello.version = 0xFEFF;
    assert!(negotiation(&check_client_hello(&hello, &[GCM128]).unwrap_err()));
    hello.version = 0x0303;
    assert!(negotiation(&check_client_hello(&hello, &[GCM128]).unwrap_err()));
    hello.version = 0xFEFC;
    assert!(check_client_hello(&hello, &[GCM128]).is_ok());
}

#[test]
fn server_rejects_missing_null_compression() {
    let mut hello = offered_hello();
    hello.compression_methods = vec![1];
    assert!(negotiation(&check_client_hello(&hello, &[GCM128]).unwrap_err()));
}

#[test]
fn server_rejects_groups_and_signature_algorithms_it_cannot_use() {
    let mut hello = offered_hello();
    hello.extensions = replace(hello.extensions, supported_groups::build(&[0x001d]));
    assert!(negotiation(&check_client_hello(&hello, &[GCM128]).unwrap_err()));

    let mut hello = offered_hello();
    hello.extensions = replace(
        hello.extensions,
        signature_algorithms::build(&[signature_algorithms::RSA_PKCS1_SHA256]),
    );
    assert!(negotiation(&check_client_hello(&hello, &[GCM128]).unwrap_err()));

    let mut hello = offered_hello();
    hello.extensions = replace(hello.extensions, ec_point_formats::build(&[1]));
    assert!(negotiation(&check_client_hello(&hello, &[GCM128]).unwrap_err()));
}

#[test]
fn server_rejects_renegotiation_data_in_an_initial_handshake() {
    let mut hello = offered_hello();
    hello.extensions = replace(
        hello.extensions,
        Extension::new(ext_type::RENEGOTIATION_INFO, vec![1, 0]),
    );
    assert!(check_client_hello(&hello, &[GCM128]).is_err());
}

#[test]
fn client_accepts_a_matching_server_hello() {
    assert_eq!(
        check_server_hello(&good_server_hello(), &[GCM128, GCM256]).unwrap(),
        Some(GCM128)
    );
    let mut no_srtp = good_server_hello();
    no_srtp.extensions.retain(|e| e.extension_type != ext_type::USE_SRTP);
    assert_eq!(check_server_hello(&no_srtp, &[GCM128]).unwrap(), None);
}

#[test]
fn client_requires_the_extended_master_secret_echo() {
    let mut hello = good_server_hello();
    hello
        .extensions
        .retain(|e| e.extension_type != ext_type::EXTENDED_MASTER_SECRET);
    assert!(negotiation(&check_server_hello(&hello, &[GCM128]).unwrap_err()));
}

#[test]
fn client_rejects_a_cipher_suite_it_did_not_offer() {
    let mut hello = good_server_hello();
    hello.cipher_suite = 0xC030;
    assert!(negotiation(&check_server_hello(&hello, &[GCM128]).unwrap_err()));
}

#[test]
fn client_rejects_unsolicited_extensions() {
    let mut hello = good_server_hello();
    hello.extensions.push(Extension::new(0x0010, vec![0, 0]));
    assert!(matches!(
        check_server_hello(&hello, &[GCM128]).unwrap_err(),
        Error::UnexpectedMessage(_)
    ));
    assert!(matches!(
        check_server_hello(&good_server_hello(), &[]).unwrap_err(),
        Error::UnexpectedMessage(_)
    ));
}

#[test]
fn client_rejects_srtp_selections_it_did_not_offer() {
    let mut hello = good_server_hello();
    hello.extensions = replace(hello.extensions, use_srtp::build(&[GCM256]));
    assert!(negotiation(&check_server_hello(&hello, &[GCM128]).unwrap_err()));

    let mut hello = good_server_hello();
    hello.extensions = replace(hello.extensions, use_srtp::build(&[GCM128, GCM256]));
    assert!(check_server_hello(&hello, &[GCM128, GCM256]).is_err());

    let mut hello = good_server_hello();
    hello.extensions = replace(
        hello.extensions,
        Extension::new(ext_type::USE_SRTP, vec![0, 2, 0, 7, 1, 9]),
    );
    assert!(check_server_hello(&hello, &[GCM128]).is_err());

    let mut hello = good_server_hello();
    hello.extensions = replace(
        hello.extensions,
        Extension::new(ext_type::USE_SRTP, vec![0, 2, 0]),
    );
    assert!(check_server_hello(&hello, &[GCM128]).is_err());
}

#[test]
fn client_rejects_version_compression_and_renegotiation_mismatches() {
    let mut hello = good_server_hello();
    hello.version = 0xFEFF;
    assert!(check_server_hello(&hello, &[GCM128]).is_err());

    let mut hello = good_server_hello();
    hello.compression_method = 1;
    assert!(check_server_hello(&hello, &[GCM128]).is_err());

    let mut hello = good_server_hello();
    hello.extensions = replace(
        hello.extensions,
        Extension::new(ext_type::RENEGOTIATION_INFO, vec![0x01, 0x00]),
    );
    assert!(check_server_hello(&hello, &[GCM128]).is_err());

    let mut hello = good_server_hello();
    hello.extensions = replace(hello.extensions, ec_point_formats::build(&[1]));
    assert!(check_server_hello(&hello, &[GCM128]).is_err());
}

#[test]
fn client_checks_the_certificate_request() {
    let ours = CertificateRequest::decode(&dtls::handshake::server::build_certificate_request())
        .unwrap();
    assert!(check_certificate_request(&ours).is_ok());
    let rsa_only = CertificateRequest {
        certificate_types: vec![1],
        signature_algorithms: vec![signature_algorithms::RSA_PKCS1_SHA256],
        certificate_authorities: Vec::new(),
    };
    assert!(negotiation(&check_certificate_request(&rsa_only).unwrap_err()));
}

#[test]
fn server_key_exchange_must_match_curve_suite_and_key() {
    let cert = generate().unwrap();
    let key = parse_leaf_public_key(&cert.der).unwrap();
    let client_random = [3u8; 32];
    let server_random = [4u8; 32];
    let point = dtls::crypto::ecdhe_p256::EcdheKeyPair::generate()
        .unwrap()
        .public_point()
        .to_vec();
    let body = build_server_key_exchange(&cert.key, &client_random, &server_random, point).unwrap();
    let ske = ServerKeyExchange::decode(&body).unwrap();

    verify_server_key_exchange(
        &key,
        &cert.der,
        &client_random,
        &server_random,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        &ske,
    )
    .unwrap();

    assert!(negotiation(
        &verify_server_key_exchange(
            &key,
            &cert.der,
            &client_random,
            &server_random,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            &ske,
        )
        .unwrap_err()
    ));

    let mut other_curve = ske.clone();
    other_curve.named_curve = 0x0018;
    assert!(negotiation(
        &verify_server_key_exchange(
            &key,
            &cert.der,
            &client_random,
            &server_random,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            &other_curve,
        )
        .unwrap_err()
    ));

    assert!(matches!(
        verify_server_key_exchange(
            &key,
            &cert.der,
            &server_random,
            &client_random,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            &ske,
        )
        .unwrap_err(),
        Error::BadSignature
    ));
}
