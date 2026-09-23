//! Gating integration test: a full in-process DTLS 1.2 handshake between a
//! client and a server `Connection`, ending in matching exporter output and
//! cross-validated fingerprints.

use std::net::SocketAddr;

use dtls::exporter::DTLS_SRTP_LABEL;
use dtls::record::{content_type, Record};
use dtls::timer::MAX_RETRANSMISSIONS;
use dtls::{Config, Connection, Error, SrtpProfile};

const SRTP_AES_128_GCM_KEYING_LEN: usize = 2 * (16 + 12);

fn client_addr() -> SocketAddr {
    "127.0.0.1:50000".parse().unwrap()
}

fn server_addr() -> SocketAddr {
    "127.0.0.1:50001".parse().unwrap()
}

fn pump(client: &mut Connection, server: &mut Connection) {
    for _ in 0..64 {
        let mut progress = false;
        if let Some(dg) = client.poll_send() {
            server.feed_recv(&dg, client_addr(), 0).expect("server feed");
            progress = true;
        }
        if let Some(dg) = server.poll_send() {
            client.feed_recv(&dg, server_addr(), 0).expect("client feed");
            progress = true;
        }
        if client.is_handshake_done() && server.is_handshake_done() {
            return;
        }
        if !progress {
            break;
        }
    }
    panic!(
        "handshake did not complete (client_done={}, server_done={})",
        client.is_handshake_done(),
        server.is_handshake_done()
    );
}

fn records(datagram: &[u8]) -> Vec<Record> {
    let mut out = Vec::new();
    let mut rest = datagram;
    while !rest.is_empty() {
        let (record, consumed) = Record::decode(rest).unwrap();
        out.push(record);
        rest = &rest[consumed..];
    }
    out
}

fn step(from: &mut Connection, to: &mut Connection, from_addr: SocketAddr) -> Vec<u8> {
    let datagram = from.poll_send().expect("pending datagram");
    to.feed_recv(&datagram, from_addr, 0).expect("feed");
    datagram
}

#[test]
fn loopback_handshake_completes() {
    let mut client = Connection::new(Config::client()).expect("client");
    let mut server = Connection::new(Config::server()).expect("server");

    pump(&mut client, &mut server);

    assert!(client.is_handshake_done());
    assert!(server.is_handshake_done());

    assert_eq!(
        client.peer_fingerprint().expect("client saw server cert"),
        server.local_fingerprint(),
        "client's view of server fingerprint must match server's own"
    );
    assert_eq!(
        server.peer_fingerprint().expect("server saw client cert"),
        client.local_fingerprint(),
        "server's view of client fingerprint must match client's own"
    );

    let ckm = client
        .export_keying_material(DTLS_SRTP_LABEL, None, SRTP_AES_128_GCM_KEYING_LEN)
        .expect("client export");
    let skm = server
        .export_keying_material(DTLS_SRTP_LABEL, None, SRTP_AES_128_GCM_KEYING_LEN)
        .expect("server export");
    assert_eq!(ckm, skm, "exported keying material must match");
    assert_eq!(ckm.len(), 56);

    assert_eq!(
        client.selected_srtp_profile(),
        server.selected_srtp_profile()
    );
    assert!(matches!(
        client.selected_srtp_profile(),
        Some(SrtpProfile::AeadAes128Gcm | SrtpProfile::AeadAes256Gcm)
    ));
}

#[test]
fn pinned_handshake_completes() {
    let mut client = Connection::new(Config::client()).unwrap();
    let mut server = Connection::new(Config::server()).unwrap();
    client
        .set_expected_peer_fingerprint(server.local_fingerprint())
        .unwrap();
    server
        .set_expected_peer_fingerprint(client.local_fingerprint())
        .unwrap();
    pump(&mut client, &mut server);
    assert_eq!(client.peer_fingerprint(), Some(server.local_fingerprint()));
    assert_eq!(server.peer_fingerprint(), Some(client.local_fingerprint()));
}

#[test]
fn config_pinning_completes_with_the_right_fingerprint() {
    let mut server = Connection::new(Config::server()).unwrap();
    let mut client = Connection::new(
        Config::client().with_expected_peer_fingerprint(server.local_fingerprint()),
    )
    .unwrap();
    pump(&mut client, &mut server);
    assert!(client.is_handshake_done());
}

#[test]
fn client_pin_mismatch_aborts_before_sending_its_key_exchange() {
    let mut client = Connection::new(Config::client().with_expected_peer_fingerprint([0xEE; 32]))
        .unwrap();
    let mut server = Connection::new(Config::server()).unwrap();
    step(&mut client, &mut server, client_addr());
    step(&mut server, &mut client, server_addr());
    step(&mut client, &mut server, client_addr());
    let flight = server.poll_send().unwrap();
    let err = client.feed_recv(&flight, server_addr(), 0).unwrap_err();
    assert!(matches!(err, Error::FingerprintMismatch), "{err}");
    let sent = records(&client.poll_send().expect("fatal alert queued"));
    assert_eq!(sent.len(), 1, "only the alert, no ClientKeyExchange");
    assert_eq!(sent[0].content_type, content_type::ALERT);
    assert_eq!(sent[0].fragment, vec![2, 42]);
    assert!(!client.is_handshake_done());
    assert!(client.peer_fingerprint().is_none());
    assert!(matches!(
        client.feed_recv(&flight, server_addr(), 0),
        Err(Error::InvalidState(_))
    ));
}

#[test]
fn server_pin_mismatch_aborts_at_the_client_certificate() {
    let mut client = Connection::new(Config::client()).unwrap();
    let mut server =
        Connection::new(Config::server().with_expected_peer_fingerprint([0x11; 32])).unwrap();
    step(&mut client, &mut server, client_addr());
    step(&mut server, &mut client, server_addr());
    step(&mut client, &mut server, client_addr());
    step(&mut server, &mut client, server_addr());
    let flight = client.poll_send().unwrap();
    let err = server.feed_recv(&flight, client_addr(), 0).unwrap_err();
    assert!(matches!(err, Error::FingerprintMismatch), "{err}");
    assert!(!server.is_handshake_done());
    assert!(server
        .export_keying_material(DTLS_SRTP_LABEL, None, SRTP_AES_128_GCM_KEYING_LEN)
        .is_err());
}

#[test]
fn late_pin_that_disagrees_with_the_received_certificate_fails() {
    let mut client = Connection::new(Config::client()).unwrap();
    let mut server = Connection::new(Config::server()).unwrap();
    step(&mut client, &mut server, client_addr());
    step(&mut server, &mut client, server_addr());
    step(&mut client, &mut server, client_addr());
    step(&mut server, &mut client, server_addr());
    assert!(matches!(
        client.set_expected_peer_fingerprint([0x22; 32]),
        Err(Error::FingerprintMismatch)
    ));
    assert!(client.poll_send().is_some(), "fatal alert queued");
}

#[test]
fn a_second_different_pin_is_rejected() {
    let mut client = Connection::new(Config::client()).unwrap();
    client.set_expected_peer_fingerprint([1; 32]).unwrap();
    client.set_expected_peer_fingerprint([1; 32]).unwrap();
    assert!(matches!(
        client.set_expected_peer_fingerprint([2; 32]),
        Err(Error::InvalidState(_))
    ));
}

#[test]
fn keys_and_peer_identity_are_unavailable_until_the_peer_finished_is_verified() {
    let mut client = Connection::new(Config::client()).unwrap();
    let mut server = Connection::new(Config::server()).unwrap();
    step(&mut client, &mut server, client_addr());
    step(&mut server, &mut client, server_addr());
    step(&mut client, &mut server, client_addr());
    step(&mut server, &mut client, server_addr());
    for connection in [&client, &server] {
        assert!(!connection.is_handshake_done());
        assert!(connection.peer_fingerprint().is_none());
        assert!(connection.selected_srtp_profile().is_none());
        assert!(matches!(
            connection.export_keying_material(DTLS_SRTP_LABEL, None, 56),
            Err(Error::InvalidState(_))
        ));
    }
    step(&mut client, &mut server, client_addr());
    assert!(server.is_handshake_done());
    assert!(!client.is_handshake_done());
    assert!(client.export_keying_material(DTLS_SRTP_LABEL, None, 56).is_err());
    step(&mut server, &mut client, server_addr());
    assert!(client.export_keying_material(DTLS_SRTP_LABEL, None, 56).is_ok());
}

#[test]
fn completed_server_retransmits_its_last_flight_when_the_client_finished_is_retransmitted() {
    let mut client = Connection::new(Config::client()).unwrap();
    let mut server = Connection::new(Config::server()).unwrap();
    step(&mut client, &mut server, client_addr());
    step(&mut server, &mut client, server_addr());
    step(&mut client, &mut server, client_addr());
    step(&mut server, &mut client, server_addr());
    let client_final = step(&mut client, &mut server, client_addr());
    assert!(server.is_handshake_done());
    let lost = server.poll_send().expect("server Finished flight");

    assert!(server.feed_recv(&client_final, client_addr(), 5).is_ok());
    assert!(
        server.poll_send().is_none(),
        "a replayed Finished record must not trigger a retransmission"
    );

    let deadline = client.timeout(0).expect("client waits for the server Finished");
    client.handle_timeout(deadline).unwrap();
    let retransmitted = client.poll_send().expect("client retransmits its final flight");
    let original_seqs: Vec<(u16, u64)> = records(&client_final)
        .iter()
        .map(|r| (r.epoch, r.sequence))
        .collect();
    let new_seqs: Vec<(u16, u64)> = records(&retransmitted)
        .iter()
        .map(|r| (r.epoch, r.sequence))
        .collect();
    assert_eq!(original_seqs.len(), new_seqs.len());
    assert!(original_seqs.iter().all(|seq| !new_seqs.contains(seq)));

    server.feed_recv(&retransmitted, client_addr(), 10).unwrap();
    let resent = server.poll_send().expect("server answers with its last flight");
    assert_eq!(records(&resent).len(), records(&lost).len());
    client.feed_recv(&resent, server_addr(), 10).unwrap();
    assert!(client.is_handshake_done());
    assert_eq!(
        client
            .export_keying_material(DTLS_SRTP_LABEL, None, 56)
            .unwrap(),
        server
            .export_keying_material(DTLS_SRTP_LABEL, None, 56)
            .unwrap()
    );
}

#[test]
fn lost_client_hello_is_retransmitted_with_a_fresh_record_sequence() {
    let mut client = Connection::new(Config::client()).unwrap();
    let mut server = Connection::new(Config::server()).unwrap();
    let first = client.poll_send().unwrap();
    let deadline = client.timeout(0).unwrap();
    client.handle_timeout(deadline).unwrap();
    let second = client.poll_send().unwrap();
    let (a, b) = (&records(&first)[0], &records(&second)[0]);
    assert_eq!(a.fragment, b.fragment, "same handshake message");
    assert_ne!(a.sequence, b.sequence, "new record sequence number");
    server.feed_recv(&second, client_addr(), deadline).unwrap();
    pump(&mut client, &mut server);
}

#[test]
fn handshake_gives_up_after_max_retransmissions() {
    let mut client = Connection::new(Config::client()).unwrap();
    let mut now = 0;
    let mut retransmissions = 0;
    let err = loop {
        client.poll_send();
        now += client.timeout(now).expect("timer armed");
        match client.handle_timeout(now) {
            Ok(()) => retransmissions += 1,
            Err(err) => break err,
        }
        assert!(retransmissions <= MAX_RETRANSMISSIONS);
    };
    assert!(matches!(err, Error::Timeout), "{err}");
    assert_eq!(retransmissions, MAX_RETRANSMISSIONS);
    assert!(client.timeout(now).is_none());
    assert!(matches!(
        client.handle_timeout(now + 1),
        Err(Error::InvalidState(_))
    ));
}

#[test]
fn unauthenticated_plaintext_after_the_handshake_is_ignored() {
    let mut client = Connection::new(Config::client()).unwrap();
    let mut server = Connection::new(Config::server()).unwrap();
    pump(&mut client, &mut server);

    let fatal_alert = Record::new(content_type::ALERT, 0, 99, vec![2, 40]).encode();
    let bogus_hello = Record::new(
        content_type::HANDSHAKE,
        0,
        100,
        dtls::handshake::messages::frame(1, 0, &[0u8; 40]),
    )
    .encode();
    let forged_ccs = Record::new(content_type::CHANGE_CIPHER_SPEC, 0, 101, vec![1]).encode();
    let forged_encrypted_alert =
        Record::new(content_type::ALERT, 1, 7, vec![0x55; 8 + 2 + 16]).encode();
    for datagram in [&fatal_alert, &bogus_hello, &forged_ccs, &forged_encrypted_alert] {
        server.feed_recv(datagram, client_addr(), 0).unwrap();
        client.feed_recv(datagram, server_addr(), 0).unwrap();
    }
    assert!(server.poll_send().is_none());
    assert!(client.poll_send().is_none());
    assert!(server.is_handshake_done() && client.is_handshake_done());
    assert_eq!(
        client.export_keying_material(DTLS_SRTP_LABEL, None, 56).unwrap(),
        server.export_keying_material(DTLS_SRTP_LABEL, None, 56).unwrap()
    );
}

#[test]
fn spoofed_client_hello_does_not_stall_the_server() {
    let mut server = Connection::new(Config::server()).unwrap();
    let mut attacker = Connection::new(Config::client()).unwrap();
    let forged_hello = attacker.poll_send().unwrap();
    let attacker_addr: SocketAddr = "127.0.0.1:6666".parse().unwrap();
    server.feed_recv(&forged_hello, attacker_addr, 0).unwrap();
    server.feed_recv(&forged_hello, attacker_addr, 0).unwrap();
    assert!(server.poll_send().is_some(), "stateless HelloVerifyRequests");

    let mut client = Connection::new(Config::client()).unwrap();
    pump(&mut client, &mut server);
}

#[test]
fn cookie_is_bound_to_the_client_address() {
    let mut client = Connection::new(Config::client()).unwrap();
    let mut server = Connection::new(Config::server()).unwrap();
    step(&mut client, &mut server, client_addr());
    step(&mut server, &mut client, server_addr());
    let hello_with_cookie = client.poll_send().unwrap();
    let elsewhere: SocketAddr = "127.0.0.1:50999".parse().unwrap();
    server.feed_recv(&hello_with_cookie, elsewhere, 0).unwrap();
    let reply = records(&server.poll_send().unwrap());
    assert_eq!(reply.len(), 1);
    assert_eq!(reply[0].fragment[0], 3, "a new HelloVerifyRequest, not a ServerHello");
    server.feed_recv(&hello_with_cookie, client_addr(), 0).unwrap();
    assert!(records(&server.poll_send().unwrap()).len() >= 5);
}

#[test]
fn client_handles_a_second_hello_verify_request() {
    let mut client = Connection::new(Config::client()).unwrap();
    let mut server = Connection::new(Config::server()).unwrap();
    step(&mut client, &mut server, client_addr());
    step(&mut server, &mut client, server_addr());
    let hello_with_cookie = client.poll_send().unwrap();
    let elsewhere: SocketAddr = "127.0.0.1:50999".parse().unwrap();
    server.feed_recv(&hello_with_cookie, elsewhere, 0).unwrap();
    let second_hvr = server.poll_send().unwrap();
    client.feed_recv(&second_hvr, server_addr(), 0).unwrap();
    pump(&mut client, &mut server);
}
