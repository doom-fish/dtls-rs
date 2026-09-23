//! The `use_srtp` extension encodes and parses SRTP protection profiles.

use dtls::extensions::ext_type;
use dtls::extensions::use_srtp::{build, parse, SRTP_AEAD_AES_128_GCM, SRTP_AEAD_AES_256_GCM};

#[test]
fn use_srtp_builds_with_correct_extension_type() {
    let ext = build(&[SRTP_AEAD_AES_128_GCM]);
    assert_eq!(ext.extension_type, ext_type::USE_SRTP);
}

#[test]
fn use_srtp_roundtrips_profiles() {
    let ext = build(&[SRTP_AEAD_AES_128_GCM, SRTP_AEAD_AES_256_GCM]);
    let parsed = parse(&ext.data).unwrap();
    assert_eq!(parsed.profiles, vec![SRTP_AEAD_AES_128_GCM, SRTP_AEAD_AES_256_GCM]);
    assert!(parsed.mki.is_empty());
}

#[test]
fn srtp_profile_code_points() {
    assert_eq!(SRTP_AEAD_AES_128_GCM, 0x0007);
    assert_eq!(SRTP_AEAD_AES_256_GCM, 0x0008);
}

#[test]
fn use_srtp_parse_is_strict() {
    assert!(parse(&[0, 0, 0]).is_err());
    assert!(parse(&[0, 3, 0, 7, 0, 0]).is_err());
    assert!(parse(&[0, 2, 0, 7]).is_err());
    assert!(parse(&[0, 2, 0, 7, 2, 1]).is_err());
    assert!(parse(&[0, 2, 0, 7, 0, 9]).is_err());
    let with_mki = parse(&[0, 2, 0, 7, 2, 0xAA, 0xBB]).unwrap();
    assert_eq!(with_mki.mki, vec![0xAA, 0xBB]);
}
