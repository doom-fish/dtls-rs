use std::fmt::Write;

use dtls::crypto::constant_time_eq;
use dtls::exporter::{export_keying_material, DTLS_SRTP_LABEL};
use dtls::handshake::keyschedule::derive_keys;
use dtls::handshake::CookieSecret;
use dtls::record::AeadKeys;

fn assert_redacted(debug: &str, secret: &[u8]) {
    assert!(debug.contains("REDACTED"), "{debug}");
    let hex = secret.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    });
    assert!(!debug.to_lowercase().contains(&hex), "{debug}");
    let decimal = format!("{secret:?}");
    assert!(!debug.contains(&decimal[1..decimal.len() - 1]), "{debug}");
}

#[test]
fn aead_keys_debug_is_redacted() {
    let keys = AeadKeys {
        key: [0xAB; 16],
        salt: [0xCD; 4],
    };
    assert_redacted(&format!("{keys:?}"), &keys.key);
    assert_redacted(&format!("{keys:?}"), &keys.salt);
}

#[test]
fn key_material_debug_is_redacted() {
    let material = derive_keys(&[0x24u8; 48], &[1u8; 32], &[2u8; 32]).unwrap();
    let debug = format!("{material:?}");
    assert_redacted(&debug, &material.client.key);
    assert_redacted(&debug, &material.server.key);
}

#[test]
fn cookie_secret_debug_is_redacted() {
    let secret = CookieSecret::generate().unwrap();
    assert_eq!(format!("{secret:?}"), "CookieSecret([REDACTED])");
}

#[test]
fn exported_keying_material_is_redacted_and_compares_by_value() {
    let a = export_keying_material(&[7u8; 48], &[1u8; 32], &[2u8; 32], DTLS_SRTP_LABEL, None, 56)
        .unwrap();
    let b = export_keying_material(&[7u8; 48], &[1u8; 32], &[2u8; 32], DTLS_SRTP_LABEL, None, 56)
        .unwrap();
    let c = export_keying_material(&[8u8; 48], &[1u8; 32], &[2u8; 32], DTLS_SRTP_LABEL, None, 56)
        .unwrap();
    assert_eq!(a.len(), 56);
    assert_eq!(a, b);
    assert_ne!(a, c);
    let debug = format!("{a:?}");
    assert_eq!(debug, "ExportedKeyingMaterial([REDACTED; 56 bytes])");
    assert_redacted(&debug, &a[..8]);
}

#[test]
fn constant_time_eq_matches_byte_equality() {
    assert!(constant_time_eq(b"", b""));
    assert!(constant_time_eq(b"fingerprint", b"fingerprint"));
    assert!(!constant_time_eq(b"fingerprint", b"fingerprinT"));
    assert!(!constant_time_eq(b"short", b"shorter"));
    assert!(!constant_time_eq(&[0u8; 32], &[0u8; 31]));
}
