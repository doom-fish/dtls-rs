//! Drive a full DTLS 1.2 handshake between an in-process client and server,
//! then report the negotiated SRTP profile and cross-checked fingerprints.
//!
//! Run with: `cargo run --example 02_handshake_loopback`

use std::net::SocketAddr;

use dtls::cert::format_colon_hex;
use dtls::{Config, Connection};

fn main() -> dtls::Result<()> {
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 50000));
    let server_addr = SocketAddr::from(([127, 0, 0, 1], 50001));

    let mut server = Connection::new(Config::server())?;
    let mut client = Connection::new(
        Config::client().with_expected_peer_fingerprint(server.local_fingerprint()),
    )?;
    server.set_expected_peer_fingerprint(client.local_fingerprint())?;

    let mut datagrams = 0u32;
    while !(client.is_handshake_done() && server.is_handshake_done()) {
        let mut progress = false;
        if let Some(dg) = client.poll_send() {
            datagrams += 1;
            server.feed_recv(&dg, client_addr, 0)?;
            progress = true;
        }
        if let Some(dg) = server.poll_send() {
            datagrams += 1;
            client.feed_recv(&dg, server_addr, 0)?;
            progress = true;
        }
        assert!(progress, "handshake stalled");
    }

    println!("handshake complete after {datagrams} datagrams");
    println!(
        "client sees server fingerprint: {}",
        format_colon_hex(&client.peer_fingerprint().unwrap())
    );
    println!(
        "server sees client fingerprint: {}",
        format_colon_hex(&server.peer_fingerprint().unwrap())
    );
    println!("negotiated SRTP profile: {:?}", client.selected_srtp_profile());

    Ok(())
}
