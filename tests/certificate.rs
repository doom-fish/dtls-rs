use std::net::SocketAddr;

use dtls::cert::format_colon_hex;
use dtls::exporter::DTLS_SRTP_LABEL;
use dtls::{Certificate, Config, Connection, Error};

fn client_addr() -> SocketAddr {
    "127.0.0.1:50000".parse().unwrap()
}

fn server_addr() -> SocketAddr {
    "127.0.0.1:50001".parse().unwrap()
}

fn pump(client: &mut Connection, server: &mut Connection) -> Result<(), Error> {
    for _ in 0..64 {
        let mut progress = false;
        if let Some(dg) = client.poll_send() {
            server.feed_recv(&dg, client_addr(), 0)?;
            progress = true;
        }
        if let Some(dg) = server.poll_send() {
            client.feed_recv(&dg, server_addr(), 0)?;
            progress = true;
        }
        if client.is_handshake_done() && server.is_handshake_done() {
            return Ok(());
        }
        if !progress {
            break;
        }
    }
    panic!("handshake did not complete");
}

fn handshake(client_cert: &Certificate, server_cert: &Certificate) -> (Connection, Connection) {
    let mut client = Connection::new(
        Config::client()
            .with_certificate(client_cert.clone())
            .with_expected_peer_fingerprint(server_cert.fingerprint()),
    )
    .expect("client");
    let mut server = Connection::new(
        Config::server()
            .with_certificate(server_cert.clone())
            .with_expected_peer_fingerprint(client_cert.fingerprint()),
    )
    .expect("server");
    pump(&mut client, &mut server).expect("handshake");
    (client, server)
}

#[test]
fn certificates_created_before_the_role_work_in_either_role() {
    let a = Certificate::generate().expect("a");
    let b = Certificate::generate().expect("b");
    assert_ne!(a.fingerprint(), b.fingerprint());

    for (client_cert, server_cert) in [(&a, &b), (&b, &a)] {
        let (client, server) = handshake(client_cert, server_cert);
        assert_eq!(client.local_fingerprint(), client_cert.fingerprint());
        assert_eq!(server.local_fingerprint(), server_cert.fingerprint());
        assert_eq!(client.peer_fingerprint(), Some(server_cert.fingerprint()));
        assert_eq!(server.peer_fingerprint(), Some(client_cert.fingerprint()));
        let client_keys = client.export_keying_material(DTLS_SRTP_LABEL, None, 56).unwrap();
        let server_keys = server.export_keying_material(DTLS_SRTP_LABEL, None, 56).unwrap();
        assert_eq!(client_keys, server_keys);
    }
}

#[test]
fn a_supplied_certificate_is_still_checked_against_the_pin() {
    let client_cert = Certificate::generate().expect("client cert");
    let server_cert = Certificate::generate().expect("server cert");
    let impostor = Certificate::generate().expect("impostor");
    let mut client = Connection::new(
        Config::client()
            .with_certificate(client_cert.clone())
            .with_expected_peer_fingerprint(server_cert.fingerprint()),
    )
    .expect("client");
    let mut server = Connection::new(
        Config::server()
            .with_certificate(impostor)
            .with_expected_peer_fingerprint(client_cert.fingerprint()),
    )
    .expect("server");
    let error = pump(&mut client, &mut server).expect_err("impostor must be refused");
    assert!(matches!(error, Error::FingerprintMismatch), "{error:?}");
    assert!(!client.is_handshake_done());
    assert!(client.peer_fingerprint().is_none());
}

#[test]
fn der_hashes_to_the_fingerprint() {
    let cert = Certificate::generate().expect("cert");
    let digest = dtls::cert::sha256_fingerprint(cert.der()).expect("hash");
    assert_eq!(digest, cert.fingerprint());
    assert_eq!(cert.clone().fingerprint(), cert.fingerprint());
    assert!(dtls::cert::parse_leaf_public_key(cert.der()).is_ok());
}

#[test]
fn certificate_debug_redacts_the_key() {
    let cert = Certificate::generate().expect("cert");
    let expected = format!(
        "Certificate {{ fingerprint: {:?}, key: \"[REDACTED]\", .. }}",
        format_colon_hex(&cert.fingerprint())
    );
    assert_eq!(format!("{cert:?}"), expected);
    let config = format!("{:?}", Config::server().with_certificate(cert));
    assert!(config.contains(&expected), "{config}");
}
