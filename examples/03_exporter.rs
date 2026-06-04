//! Complete a handshake and export SRTP keying material (RFC 5705), showing
//! that both endpoints derive identical bytes.
//!
//! Run with: `cargo run --example 03_exporter`

use dtls::exporter::DTLS_SRTP_LABEL;
use dtls::{Config, Connection};

fn main() -> dtls::Result<()> {
    let mut client = Connection::new(Config::client())?;
    let mut server = Connection::new(Config::server())?;

    while !(client.is_handshake_done() && server.is_handshake_done()) {
        if let Some(dg) = client.poll_send() {
            server.feed_recv(&dg, 0)?;
        }
        if let Some(dg) = server.poll_send() {
            client.feed_recv(&dg, 0)?;
        }
    }

    // SRTP needs two keys, two salts: 2*(16 + 14) = 60 bytes for AES-128-GCM.
    let client_km = client.export_keying_material(DTLS_SRTP_LABEL, None, 60)?;
    let server_km = server.export_keying_material(DTLS_SRTP_LABEL, None, 60)?;

    assert_eq!(client_km, server_km, "exporters must agree");
    println!("exported {} bytes of SRTP keying material", client_km.len());
    println!("first 16 bytes: {:02x?}", &client_km[..16]);

    Ok(())
}
