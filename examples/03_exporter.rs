//! Complete a handshake and export SRTP keying material (RFC 5705), showing
//! that both endpoints derive identical bytes.
//!
//! Run with: `cargo run --example 03_exporter`

use std::net::SocketAddr;

use dtls::exporter::DTLS_SRTP_LABEL;
use dtls::{Config, Connection};

fn main() -> dtls::Result<()> {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 50000));
    let server_addr = SocketAddr::from(([127, 0, 0, 1], 50001));

    let mut server = Connection::new(Config::server())?;
    let mut client = Connection::new(
        Config::client().with_expected_peer_fingerprint(server.local_fingerprint()),
    )?;
    server.set_expected_peer_fingerprint(client.local_fingerprint())?;

    while !(client.is_handshake_done() && server.is_handshake_done()) {
        if let Some(dg) = client.poll_send() {
            server.feed_recv(&dg, client_addr, 0)?;
        }
        if let Some(dg) = server.poll_send() {
            client.feed_recv(&dg, server_addr, 0)?;
        }
    }

    // SRTP needs two keys, two salts: 2*(16 + 12) = 56 bytes for AES-128-GCM.
    let client_km = client.export_keying_material(DTLS_SRTP_LABEL, None, 56)?;
    let server_km = server.export_keying_material(DTLS_SRTP_LABEL, None, 56)?;

    assert_eq!(client_km, server_km, "exporters must agree");
    println!("exported {} bytes of SRTP keying material", client_km.len());

    Ok(())
}
