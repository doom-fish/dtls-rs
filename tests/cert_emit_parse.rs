//! Self-signed certificate emission, fingerprinting, and public-key parsing.

use dtls::cert::parse::PeerPublicKey;
use dtls::cert::{format_colon_hex, generate, parse_leaf_public_key, sha256_fingerprint};
use dtls::crypto::ecdsa_verify::verify_ecdsa_p256;

#[test]
fn generated_cert_parses_to_ecdsa_p256() {
    let cert = generate().unwrap();
    let parsed = parse_leaf_public_key(&cert.der).unwrap();
    match parsed {
        PeerPublicKey::EcdsaP256 { point } => {
            assert_eq!(point.len(), 65, "uncompressed P-256 point");
            assert_eq!(point[0], 0x04);
            assert_eq!(point, cert.key.public_point());
        }
        PeerPublicKey::Rsa => panic!("expected an ECDSA certificate"),
    }
}

#[test]
fn cert_signing_key_matches_parsed_point() {
    let cert = generate().unwrap();
    let message = b"transcript bytes";
    let signature = cert.key.sign_der(message).unwrap();
    let PeerPublicKey::EcdsaP256 { point } = parse_leaf_public_key(&cert.der).unwrap() else {
        panic!("expected ECDSA");
    };
    // The point parsed out of the certificate must verify the key's signatures.
    verify_ecdsa_p256(&point, message, &signature).unwrap();
}

#[test]
fn fingerprint_is_stable_and_formats_as_sdp() {
    let cert = generate().unwrap();
    let fp1 = sha256_fingerprint(&cert.der).unwrap();
    let fp2 = sha256_fingerprint(&cert.der).unwrap();
    assert_eq!(fp1, fp2);
    let text = format_colon_hex(&fp1);
    // 32 bytes -> 32 hex pairs joined by 31 colons, uppercase.
    assert_eq!(text.len(), 32 * 2 + 31);
    assert_eq!(text.matches(':').count(), 31);
    assert!(text
        .chars()
        .all(|c| c.is_ascii_hexdigit() && (!c.is_alphabetic() || c.is_uppercase()) || c == ':'));
}

#[test]
fn distinct_certs_have_distinct_fingerprints() {
    let a = generate().unwrap();
    let b = generate().unwrap();
    assert_ne!(
        sha256_fingerprint(&a.der).unwrap(),
        sha256_fingerprint(&b.der).unwrap()
    );
}
