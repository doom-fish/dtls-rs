//! Stateless cookie generation and verification.

use std::net::SocketAddr;

use dtls::handshake::client::build_client_hello;
use dtls::handshake::messages::ClientHello;
use dtls::handshake::CookieSecret;

fn peer() -> SocketAddr {
    "192.0.2.1:5000".parse().unwrap()
}

fn hello(random: u8, cookie: &[u8]) -> ClientHello {
    ClientHello::decode(&build_client_hello([random; 32], cookie, &[0x0007])).unwrap()
}

fn with_cookie(secret: &CookieSecret, peer: SocketAddr, random: u8) -> ClientHello {
    let cookie = secret.compute(peer, &hello(random, &[])).unwrap();
    hello(random, &cookie)
}

#[test]
fn cookie_verifies_against_same_inputs() {
    let secret = CookieSecret::generate().unwrap();
    let cookie = secret.compute(peer(), &hello(0x11, &[])).unwrap();
    assert_eq!(cookie.len(), 32);
    assert!(secret.verify(peer(), &hello(0x11, &cookie)).unwrap());
}

#[test]
fn cookie_rejects_wrong_random() {
    let secret = CookieSecret::generate().unwrap();
    let cookie = secret.compute(peer(), &hello(0x11, &[])).unwrap();
    assert!(!secret.verify(peer(), &hello(0x22, &cookie)).unwrap());
}

#[test]
fn cookie_rejects_wrong_peer_address_or_port() {
    let secret = CookieSecret::generate().unwrap();
    let echoed = with_cookie(&secret, peer(), 0x33);
    assert!(secret.verify(peer(), &echoed).unwrap());
    assert!(!secret
        .verify("198.51.100.9:5000".parse().unwrap(), &echoed)
        .unwrap());
    assert!(!secret
        .verify("192.0.2.1:5001".parse().unwrap(), &echoed)
        .unwrap());
}

#[test]
fn cookie_treats_ipv4_mapped_ipv6_as_the_same_peer() {
    let secret = CookieSecret::generate().unwrap();
    let echoed = with_cookie(&secret, peer(), 0x55);
    assert!(secret
        .verify("[::ffff:192.0.2.1]:5000".parse().unwrap(), &echoed)
        .unwrap());
}

#[test]
fn cookie_rejects_changed_client_hello_parameters() {
    let secret = CookieSecret::generate().unwrap();
    let mut echoed = with_cookie(&secret, peer(), 0x66);
    echoed.cipher_suites.retain(|&suite| suite != 0xC02F);
    assert!(!secret.verify(peer(), &echoed).unwrap());
}

#[test]
fn cookie_rejects_different_secret() {
    let a = CookieSecret::generate().unwrap();
    let b = CookieSecret::generate().unwrap();
    let echoed = with_cookie(&a, peer(), 0x44);
    assert!(!b.verify(peer(), &echoed).unwrap());
}

#[test]
fn cookie_rejects_truncated_and_empty_cookies() {
    let secret = CookieSecret::generate().unwrap();
    let cookie = secret.compute(peer(), &hello(0x77, &[])).unwrap();
    assert!(!secret.verify(peer(), &hello(0x77, &cookie[..31])).unwrap());
    assert!(!secret.verify(peer(), &hello(0x77, &[])).unwrap());
}
