use std::net::UdpSocket;
use std::time::{Duration, Instant};

use dtls::exporter::DTLS_SRTP_LABEL;
use dtls::{Config, Connection};

fn bind() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind 127.0.0.1");
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    socket
}

fn drive(connection: &mut Connection, socket: &UdpSocket, peer: std::net::SocketAddr, now: u64) {
    while let Some(datagram) = connection.poll_send() {
        socket.send_to(&datagram, peer).unwrap();
    }
    let mut buffer = [0u8; 4096];
    if let Ok((len, from)) = socket.recv_from(&mut buffer) {
        assert_eq!(from, peer);
        connection.feed_recv(&buffer[..len], from, now).unwrap();
    }
    connection.handle_timeout(now).unwrap();
}

#[test]
fn handshake_over_loopback_udp_sockets() {
    let client_socket = bind();
    let server_socket = bind();
    let client_addr = client_socket.local_addr().unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let mut server = Connection::new(Config::server()).unwrap();
    let mut client =
        Connection::new(Config::client().with_expected_peer_fingerprint(server.local_fingerprint()))
            .unwrap();
    server
        .set_expected_peer_fingerprint(client.local_fingerprint())
        .unwrap();

    let start = Instant::now();
    while !(client.is_handshake_done() && server.is_handshake_done()) {
        assert!(start.elapsed() < Duration::from_secs(10), "handshake timed out");
        let now = start.elapsed().as_millis() as u64;
        drive(&mut client, &client_socket, server_addr, now);
        drive(&mut server, &server_socket, client_addr, now);
    }

    assert_eq!(
        client.export_keying_material(DTLS_SRTP_LABEL, None, 56).unwrap(),
        server.export_keying_material(DTLS_SRTP_LABEL, None, 56).unwrap()
    );
    assert_eq!(server.peer_fingerprint(), Some(client.local_fingerprint()));
}
