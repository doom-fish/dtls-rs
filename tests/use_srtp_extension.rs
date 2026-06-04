//! The `use_srtp` extension encodes and parses SRTP protection profiles.

use dtls::extensions::ext_type;
use dtls::extensions::use_srtp::{
    build, parse_profiles, SRTP_AEAD_AES_128_GCM, SRTP_AEAD_AES_256_GCM,
};

#[test]
fn use_srtp_builds_with_correct_extension_type() {
    let ext = build(&[SRTP_AEAD_AES_128_GCM]);
    assert_eq!(ext.extension_type, ext_type::USE_SRTP);
}

#[test]
fn use_srtp_roundtrips_profiles() {
    let ext = build(&[SRTP_AEAD_AES_128_GCM, SRTP_AEAD_AES_256_GCM]);
    let profiles = parse_profiles(&ext.data).unwrap();
    assert_eq!(profiles, vec![SRTP_AEAD_AES_128_GCM, SRTP_AEAD_AES_256_GCM]);
}

#[test]
fn srtp_profile_code_points() {
    assert_eq!(SRTP_AEAD_AES_128_GCM, 0x0007);
    assert_eq!(SRTP_AEAD_AES_256_GCM, 0x0008);
}
