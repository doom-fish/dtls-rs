//! Gating integration test: a full in-process DTLS 1.2 handshake between a
//! client and a server `Connection`, ending in matching exporter output and
//! cross-validated fingerprints.

use dtls::exporter::DTLS_SRTP_LABEL;
use dtls::{Config, Connection, SrtpProfile};

fn pump(client: &mut Connection, server: &mut Connection) {
    for _ in 0..64 {
        let mut progress = false;
        if let Some(dg) = client.poll_send() {
            server.feed_recv(&dg, 0).expect("server feed");
            progress = true;
        }
        if let Some(dg) = server.poll_send() {
            client.feed_recv(&dg, 0).expect("client feed");
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

#[test]
fn loopback_handshake_completes() {
    let mut client = Connection::new(Config::client()).expect("client");
    let mut server = Connection::new(Config::server()).expect("server");

    pump(&mut client, &mut server);

    assert!(client.is_handshake_done());
    assert!(server.is_handshake_done());

    // Each side learned the other's certificate fingerprint.
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

    // The RFC 5705 exporter must agree on both ends.
    let ckm = client
        .export_keying_material(DTLS_SRTP_LABEL, None, 60)
        .expect("client export");
    let skm = server
        .export_keying_material(DTLS_SRTP_LABEL, None, 60)
        .expect("server export");
    assert_eq!(ckm, skm, "exported keying material must match");
    assert_eq!(ckm.len(), 60);

    // SRTP negotiation agrees.
    assert_eq!(
        client.selected_srtp_profile(),
        server.selected_srtp_profile()
    );
    assert!(matches!(
        client.selected_srtp_profile(),
        Some(SrtpProfile::AeadAes128Gcm | SrtpProfile::AeadAes256Gcm)
    ));
}
