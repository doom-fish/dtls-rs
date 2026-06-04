//! Stateless cookie generation and verification.

use dtls::handshake::CookieSecret;

const PEER: &[u8] = b"192.0.2.1:5000";

#[test]
fn cookie_verifies_against_same_inputs() {
    let secret = CookieSecret::generate().unwrap();
    let client_random = [0x11u8; 32];
    let cookie = secret.compute(PEER, &client_random).unwrap();
    assert_eq!(cookie.len(), 32);
    assert!(secret.verify(PEER, &client_random, &cookie).unwrap());
}

#[test]
fn cookie_rejects_wrong_random() {
    let secret = CookieSecret::generate().unwrap();
    let cookie = secret.compute(PEER, &[0x11u8; 32]).unwrap();
    assert!(!secret.verify(PEER, &[0x22u8; 32], &cookie).unwrap());
}

#[test]
fn cookie_rejects_wrong_peer() {
    let secret = CookieSecret::generate().unwrap();
    let client_random = [0x33u8; 32];
    let cookie = secret.compute(PEER, &client_random).unwrap();
    assert!(!secret
        .verify(b"198.51.100.9:5000", &client_random, &cookie)
        .unwrap());
}

#[test]
fn cookie_rejects_different_secret() {
    let a = CookieSecret::generate().unwrap();
    let b = CookieSecret::generate().unwrap();
    let client_random = [0x44u8; 32];
    let cookie = a.compute(PEER, &client_random).unwrap();
    assert!(!b.verify(PEER, &client_random, &cookie).unwrap());
}
