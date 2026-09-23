use std::net::SocketAddr;

use dtls::cert::{generate, sha256_fingerprint, SelfSignedCertificate};
use dtls::crypto::ecdhe_p256::EcdheKeyPair;
use dtls::crypto::ecdsa_sign::EcdsaSigningKey;
use dtls::crypto::hash::sha256;
use dtls::exporter::{export_keying_material, DTLS_SRTP_LABEL};
use dtls::extensions::signature_algorithms::ECDSA_SECP256R1_SHA256;
use dtls::handshake::client::{build_client_hello, build_client_key_exchange};
use dtls::handshake::keyschedule::{
    client_finished_verify_data, derive_keys, extended_master_secret,
    server_finished_verify_data, KeyMaterial,
};
use dtls::handshake::messages::{
    frame, msg_type, CertificateVerify, ClientHello, ClientKeyExchange, Finished,
    HandshakeHeader, HelloVerifyRequest, ServerHello, ServerKeyExchange, HANDSHAKE_HEADER_LEN,
};
use dtls::handshake::server::{
    build_certificate, build_certificate_request, build_hello_verify_request, build_server_hello,
    build_server_key_exchange,
};
use dtls::handshake::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
use dtls::record::ciphertext::{protect, unprotect, AeadKeys};
use dtls::record::{content_type, Record, DTLS_1_2};
use dtls::{Config, Connection, Error, Zeroizing};

const GCM128: u16 = 0x0007;

fn client_addr() -> SocketAddr {
    "127.0.0.1:40001".parse().unwrap()
}

fn server_addr() -> SocketAddr {
    "127.0.0.1:40002".parse().unwrap()
}

#[derive(Debug)]
struct Message {
    msg_type: u8,
    seq: u16,
    body: Vec<u8>,
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

fn split_messages(plain: &[u8]) -> Vec<Message> {
    let mut out = Vec::new();
    let mut rest = plain;
    while !rest.is_empty() {
        let header = HandshakeHeader::decode(rest).unwrap();
        let end = HANDSHAKE_HEADER_LEN + header.fragment_length as usize;
        out.push(Message {
            msg_type: header.msg_type,
            seq: header.message_seq,
            body: rest[HANDSHAKE_HEADER_LEN..end].to_vec(),
        });
        rest = &rest[end..];
    }
    out
}

fn plaintext_messages(datagram: &[u8]) -> Vec<Message> {
    records(datagram)
        .into_iter()
        .filter(|r| r.epoch == 0 && r.content_type == content_type::HANDSHAKE)
        .flat_map(|r| split_messages(&r.fragment))
        .collect()
}

fn handshake_record(record_seq: u64, messages: &[(u8, u16, &[u8])]) -> Vec<u8> {
    let mut fragment = Vec::new();
    for (mtype, seq, body) in messages {
        fragment.extend_from_slice(&frame(*mtype, *seq, body));
    }
    Record::new(content_type::HANDSHAKE, 0, record_seq, fragment).encode()
}

fn ccs_record(record_seq: u64) -> Vec<u8> {
    Record::new(content_type::CHANGE_CIPHER_SPEC, 0, record_seq, vec![1]).encode()
}

fn protected_record(keys: &AeadKeys, seq: u64, content: u8, plaintext: &[u8]) -> Vec<u8> {
    let fragment = protect(keys, 1, seq, content, DTLS_1_2, plaintext).unwrap();
    Record::new(content, 1, seq, fragment).encode()
}

fn assert_fatal_alert(datagram: Option<Vec<u8>>, description: u8) {
    let sent = records(&datagram.expect("fatal alert queued"));
    let alert = sent.last().unwrap();
    assert_eq!(alert.content_type, content_type::ALERT);
    assert_eq!(alert.epoch, 0);
    assert_eq!(alert.fragment, vec![2, description]);
}

fn assert_unauthenticated(connection: &Connection) {
    assert!(!connection.is_handshake_done());
    assert!(connection.peer_fingerprint().is_none());
    assert!(connection.selected_srtp_profile().is_none());
    assert!(connection
        .export_keying_material(DTLS_SRTP_LABEL, None, 56)
        .is_err());
}

struct EvilClient {
    server: Connection,
    random: [u8; 32],
    transcript: Vec<u8>,
    server_random: [u8; 32],
    server_point: Vec<u8>,
    record_seq: u64,
    premaster: Option<Zeroizing<Vec<u8>>>,
}

impl EvilClient {
    fn connect(config: Config) -> Self {
        let mut server = Connection::new(config).unwrap();
        let random = [0x42; 32];
        let first = build_client_hello(random, &[], &[GCM128]);
        server
            .feed_recv(
                &handshake_record(0, &[(msg_type::CLIENT_HELLO, 0, &first)]),
                client_addr(),
                0,
            )
            .unwrap();
        let hvr = plaintext_messages(&server.poll_send().unwrap());
        assert_eq!(hvr.len(), 1);
        assert_eq!((hvr[0].msg_type, hvr[0].seq), (msg_type::HELLO_VERIFY_REQUEST, 0));
        let cookie = HelloVerifyRequest::decode(&hvr[0].body).unwrap().cookie;

        let second = build_client_hello(random, &cookie, &[GCM128]);
        server
            .feed_recv(
                &handshake_record(1, &[(msg_type::CLIENT_HELLO, 1, &second)]),
                client_addr(),
                0,
            )
            .unwrap();
        let flight = plaintext_messages(&server.poll_send().unwrap());
        let shape: Vec<(u8, u16)> = flight.iter().map(|m| (m.msg_type, m.seq)).collect();
        assert_eq!(
            shape,
            [
                (msg_type::SERVER_HELLO, 1),
                (msg_type::CERTIFICATE, 2),
                (msg_type::SERVER_KEY_EXCHANGE, 3),
                (msg_type::CERTIFICATE_REQUEST, 4),
                (msg_type::SERVER_HELLO_DONE, 5),
            ]
        );
        let mut transcript = frame(msg_type::CLIENT_HELLO, 1, &second);
        for message in &flight {
            transcript.extend_from_slice(&frame(message.msg_type, message.seq, &message.body));
        }
        Self {
            server,
            random,
            transcript,
            server_random: ServerHello::decode(&flight[0].body).unwrap().random,
            server_point: ServerKeyExchange::decode(&flight[2].body)
                .unwrap()
                .public_point,
            record_seq: 2,
            premaster: None,
        }
    }

    fn send(&mut self, messages: &[(u8, u16, &[u8])]) -> Result<(), Error> {
        for (mtype, seq, body) in messages {
            self.transcript.extend_from_slice(&frame(*mtype, *seq, body));
        }
        let record = handshake_record(self.record_seq, messages);
        self.record_seq += 1;
        self.server.feed_recv(&record, client_addr(), 0)
    }

    fn send_raw(&mut self, datagram: &[u8]) -> Result<(), Error> {
        self.server.feed_recv(datagram, client_addr(), 0)
    }

    fn client_key_exchange(&mut self) -> Vec<u8> {
        let ephemeral = EcdheKeyPair::generate().unwrap();
        self.premaster = Some(ephemeral.agree(&self.server_point).unwrap());
        build_client_key_exchange(ephemeral.public_point().to_vec())
    }

    fn keys(&self) -> (KeyMaterial, Zeroizing<[u8; 48]>) {
        let session_hash = sha256(&self.transcript).unwrap();
        let master =
            extended_master_secret(self.premaster.as_ref().unwrap(), &session_hash).unwrap();
        let keys = derive_keys(master.as_slice(), &self.server_random, &self.random).unwrap();
        (keys, master)
    }

    fn finished(&mut self, keys: &KeyMaterial, master: &[u8], seq: u16, record_seq: u64) -> Vec<u8> {
        let verify_data = client_finished_verify_data(master, &self.transcript).unwrap();
        let framed = frame(msg_type::FINISHED, seq, &Finished { verify_data }.encode());
        self.transcript.extend_from_slice(&framed);
        protected_record(&keys.client, record_seq, content_type::HANDSHAKE, &framed)
    }

    fn certificate_verify(&self, key: &EcdsaSigningKey) -> Vec<u8> {
        CertificateVerify {
            signature_algorithm: ECDSA_SECP256R1_SHA256,
            signature: key.sign_der(&self.transcript).unwrap(),
        }
        .encode()
    }
}

#[test]
fn evil_client_harness_completes_an_honest_handshake() {
    let own = generate().unwrap();
    let mut c = EvilClient::connect(Config::server());
    c.send(&[(msg_type::CERTIFICATE, 2, &build_certificate(own.der.clone()))])
        .unwrap();
    let cke = c.client_key_exchange();
    c.send(&[(msg_type::CLIENT_KEY_EXCHANGE, 3, &cke)]).unwrap();
    let (keys, master) = c.keys();
    let cv = c.certificate_verify(&own.key);
    c.send(&[(msg_type::CERTIFICATE_VERIFY, 4, &cv)]).unwrap();
    c.send_raw(&ccs_record(5)).unwrap();
    let finished = c.finished(&keys, master.as_slice(), 5, 0);
    c.send_raw(&finished).unwrap();

    assert!(c.server.is_handshake_done());
    assert_eq!(
        c.server.peer_fingerprint(),
        Some(sha256_fingerprint(&own.der).unwrap())
    );
    let reply = records(&c.server.poll_send().unwrap());
    assert_eq!(reply[0].content_type, content_type::CHANGE_CIPHER_SPEC);
    let server_finished = split_messages(
        &unprotect(&keys.server, 1, reply[1].sequence, content_type::HANDSHAKE, DTLS_1_2, &reply[1].fragment)
            .unwrap(),
    );
    assert_eq!(server_finished[0].msg_type, msg_type::FINISHED);
    assert_eq!(server_finished[0].seq, 6);
    assert_eq!(
        server_finished[0].body,
        server_finished_verify_data(master.as_slice(), &c.transcript).unwrap()
    );
}

#[test]
fn server_rejects_finished_without_certificate_or_certificate_verify() {
    let mut c = EvilClient::connect(Config::server());
    let cke = c.client_key_exchange();
    let err = c
        .send(&[(msg_type::CLIENT_KEY_EXCHANGE, 2, &cke)])
        .unwrap_err();
    assert!(matches!(err, Error::UnexpectedMessage(_)), "{err}");
    assert_fatal_alert(c.server.poll_send(), 10);
    assert_unauthenticated(&c.server);
    let (keys, master) = c.keys();
    let finished = c.finished(&keys, master.as_slice(), 3, 0);
    assert!(matches!(c.send_raw(&finished), Err(Error::InvalidState(_))));
    assert_unauthenticated(&c.server);
}

#[test]
fn server_rejects_victim_certificate_followed_by_finished_without_certificate_verify() {
    let victim = generate().unwrap();
    let mut c = EvilClient::connect(Config::server());
    c.send(&[(msg_type::CERTIFICATE, 2, &build_certificate(victim.der.clone()))])
        .unwrap();
    let cke = c.client_key_exchange();
    c.send(&[(msg_type::CLIENT_KEY_EXCHANGE, 3, &cke)]).unwrap();
    let (keys, master) = c.keys();
    c.send_raw(&ccs_record(4)).unwrap();
    let finished = c.finished(&keys, master.as_slice(), 4, 0);
    let err = c.send_raw(&finished).unwrap_err();
    assert!(matches!(err, Error::UnexpectedMessage(_)), "{err}");
    assert_unauthenticated(&c.server);
}

#[test]
fn server_never_completes_when_certificate_verify_is_skipped_by_numbering() {
    let victim = generate().unwrap();
    let attacker = generate().unwrap();
    let mut c = EvilClient::connect(Config::server());
    c.send(&[(msg_type::CERTIFICATE, 2, &build_certificate(victim.der.clone()))])
        .unwrap();
    let cke = c.client_key_exchange();
    c.send(&[(msg_type::CLIENT_KEY_EXCHANGE, 3, &cke)]).unwrap();
    let (keys, master) = c.keys();
    c.send_raw(&ccs_record(4)).unwrap();
    let finished = c.finished(&keys, master.as_slice(), 5, 0);
    c.send_raw(&finished).unwrap();
    assert_unauthenticated(&c.server);
    assert!(c.server.poll_send().is_none());

    let forged_cv = c.certificate_verify(&attacker.key);
    let err = c
        .send(&[(msg_type::CERTIFICATE_VERIFY, 4, &forged_cv)])
        .unwrap_err();
    assert!(matches!(err, Error::BadSignature), "{err}");
    assert_unauthenticated(&c.server);
}

#[test]
fn server_rejects_a_certificate_verify_made_with_a_different_key() {
    let victim = generate().unwrap();
    let attacker = generate().unwrap();
    let mut c = EvilClient::connect(Config::server());
    c.send(&[(msg_type::CERTIFICATE, 2, &build_certificate(victim.der.clone()))])
        .unwrap();
    let cke = c.client_key_exchange();
    c.send(&[(msg_type::CLIENT_KEY_EXCHANGE, 3, &cke)]).unwrap();
    let cv = c.certificate_verify(&attacker.key);
    let err = c
        .send(&[(msg_type::CERTIFICATE_VERIFY, 4, &cv)])
        .unwrap_err();
    assert!(matches!(err, Error::BadSignature), "{err}");
    assert_fatal_alert(c.server.poll_send(), 51);
    assert_unauthenticated(&c.server);
}

#[test]
fn pinned_server_rejects_the_wrong_certificate_before_any_key_exchange() {
    let victim = generate().unwrap();
    let attacker = generate().unwrap();
    let mut c = EvilClient::connect(
        Config::server().with_expected_peer_fingerprint(sha256_fingerprint(&victim.der).unwrap()),
    );
    let err = c
        .send(&[(msg_type::CERTIFICATE, 2, &build_certificate(attacker.der.clone()))])
        .unwrap_err();
    assert!(matches!(err, Error::FingerprintMismatch), "{err}");
    assert_fatal_alert(c.server.poll_send(), 42);
    assert_unauthenticated(&c.server);
}

#[test]
fn server_rejects_a_second_certificate() {
    let own = generate().unwrap();
    let victim = generate().unwrap();
    let mut c = EvilClient::connect(Config::server());
    c.send(&[(msg_type::CERTIFICATE, 2, &build_certificate(own.der.clone()))])
        .unwrap();
    let err = c
        .send(&[(msg_type::CERTIFICATE, 3, &build_certificate(victim.der.clone()))])
        .unwrap_err();
    assert!(matches!(err, Error::UnexpectedMessage(_)), "{err}");
    assert_unauthenticated(&c.server);
}

#[test]
fn server_rejects_a_certificate_after_certificate_verify() {
    let own = generate().unwrap();
    let victim = generate().unwrap();
    let mut c = EvilClient::connect(Config::server());
    c.send(&[(msg_type::CERTIFICATE, 2, &build_certificate(own.der.clone()))])
        .unwrap();
    let cke = c.client_key_exchange();
    c.send(&[(msg_type::CLIENT_KEY_EXCHANGE, 3, &cke)]).unwrap();
    let cv = c.certificate_verify(&own.key);
    let late_certificate = build_certificate(victim.der.clone());
    let err = c
        .send(&[
            (msg_type::CERTIFICATE_VERIFY, 4, &cv),
            (msg_type::CERTIFICATE, 5, &late_certificate),
        ])
        .unwrap_err();
    assert!(matches!(err, Error::UnexpectedMessage(_)), "{err}");
    assert_unauthenticated(&c.server);
}

#[test]
fn server_rejects_an_empty_client_certificate_list() {
    let mut c = EvilClient::connect(Config::server());
    let empty = dtls::handshake::messages::Certificate {
        certificates: Vec::new(),
    }
    .encode();
    let err = c
        .send(&[(msg_type::CERTIFICATE, 2, &empty)])
        .unwrap_err();
    assert!(matches!(err, Error::Negotiation(_)), "{err}");
    assert_fatal_alert(c.server.poll_send(), 40);
}

#[test]
fn server_rejects_out_of_order_client_messages() {
    let own = generate().unwrap();
    let mut c = EvilClient::connect(Config::server());
    c.send(&[(msg_type::CERTIFICATE, 2, &build_certificate(own.der.clone()))])
        .unwrap();
    let cv = c.certificate_verify(&own.key);
    let err = c
        .send(&[(msg_type::CERTIFICATE_VERIFY, 3, &cv)])
        .unwrap_err();
    assert!(matches!(err, Error::UnexpectedMessage(_)), "{err}");
    assert_unauthenticated(&c.server);
}

#[test]
fn server_rejects_an_unprotected_finished() {
    let own = generate().unwrap();
    let mut c = EvilClient::connect(Config::server());
    c.send(&[(msg_type::CERTIFICATE, 2, &build_certificate(own.der.clone()))])
        .unwrap();
    let cke = c.client_key_exchange();
    c.send(&[(msg_type::CLIENT_KEY_EXCHANGE, 3, &cke)]).unwrap();
    let (_, master) = c.keys();
    let cv = c.certificate_verify(&own.key);
    let mut transcript = c.transcript.clone();
    transcript.extend_from_slice(&frame(msg_type::CERTIFICATE_VERIFY, 4, &cv));
    let verify_data = client_finished_verify_data(master.as_slice(), &transcript).unwrap();
    let err = c
        .send(&[
            (msg_type::CERTIFICATE_VERIFY, 4, &cv),
            (msg_type::FINISHED, 5, &verify_data),
        ])
        .unwrap_err();
    assert!(matches!(err, Error::UnexpectedMessage(_)), "{err}");
    assert_unauthenticated(&c.server);
}

#[test]
fn server_ignores_retransmitted_duplicates_and_completes() {
    let own = generate().unwrap();
    let mut c = EvilClient::connect(Config::server());
    let certificate = build_certificate(own.der.clone());
    c.send(&[(msg_type::CERTIFICATE, 2, &certificate)]).unwrap();
    c.send_raw(&handshake_record(40, &[(msg_type::CERTIFICATE, 2, &certificate)]))
        .unwrap();
    let cke = c.client_key_exchange();
    c.send(&[(msg_type::CLIENT_KEY_EXCHANGE, 3, &cke)]).unwrap();
    c.send_raw(&handshake_record(41, &[(msg_type::CLIENT_KEY_EXCHANGE, 3, &cke)]))
        .unwrap();
    let (keys, master) = c.keys();
    let cv = c.certificate_verify(&own.key);
    c.send(&[(msg_type::CERTIFICATE_VERIFY, 4, &cv)]).unwrap();
    c.send_raw(&ccs_record(42)).unwrap();
    let finished = c.finished(&keys, master.as_slice(), 5, 0);
    c.send_raw(&finished).unwrap();
    assert!(c.server.is_handshake_done());
    assert_eq!(
        c.server.peer_fingerprint(),
        Some(sha256_fingerprint(&own.der).unwrap())
    );
}

#[test]
fn server_rejects_a_bad_client_finished() {
    let own = generate().unwrap();
    let mut c = EvilClient::connect(Config::server());
    c.send(&[(msg_type::CERTIFICATE, 2, &build_certificate(own.der.clone()))])
        .unwrap();
    let cke = c.client_key_exchange();
    c.send(&[(msg_type::CLIENT_KEY_EXCHANGE, 3, &cke)]).unwrap();
    let (keys, _) = c.keys();
    let cv = c.certificate_verify(&own.key);
    c.send(&[(msg_type::CERTIFICATE_VERIFY, 4, &cv)]).unwrap();
    c.send_raw(&ccs_record(5)).unwrap();
    let framed = frame(msg_type::FINISHED, 5, &[0u8; 12]);
    let bogus = protected_record(&keys.client, 0, content_type::HANDSHAKE, &framed);
    let err = c.send_raw(&bogus).unwrap_err();
    assert!(matches!(err, Error::BadFinished), "{err}");
    assert_unauthenticated(&c.server);
}

#[test]
fn server_acts_only_on_authenticated_alerts_after_the_handshake() {
    let own = generate().unwrap();
    let mut c = EvilClient::connect(Config::server());
    c.send(&[(msg_type::CERTIFICATE, 2, &build_certificate(own.der.clone()))])
        .unwrap();
    let cke = c.client_key_exchange();
    c.send(&[(msg_type::CLIENT_KEY_EXCHANGE, 3, &cke)]).unwrap();
    let (keys, master) = c.keys();
    let cv = c.certificate_verify(&own.key);
    c.send(&[(msg_type::CERTIFICATE_VERIFY, 4, &cv)]).unwrap();
    c.send_raw(&ccs_record(5)).unwrap();
    let finished = c.finished(&keys, master.as_slice(), 5, 0);
    c.send_raw(&finished).unwrap();
    assert!(c.server.is_handshake_done());

    c.send_raw(&Record::new(content_type::ALERT, 0, 50, vec![2, 40]).encode())
        .unwrap();
    let mut forged = protected_record(&keys.client, 1, content_type::ALERT, &[2, 40]);
    let last = forged.len() - 1;
    forged[last] ^= 1;
    c.send_raw(&forged).unwrap();
    assert!(c.server.is_handshake_done());

    let err = c
        .send_raw(&protected_record(&keys.client, 2, content_type::ALERT, &[2, 40]))
        .unwrap_err();
    assert!(
        matches!(err, Error::Alert { level: 2, description: 40 }),
        "{err}"
    );
    assert!(!c.server.is_handshake_done());
    assert!(c
        .server
        .export_keying_material(DTLS_SRTP_LABEL, None, 56)
        .is_err());
}

#[test]
fn server_answers_every_cookieless_hello_statelessly() {
    let mut server = Connection::new(Config::server()).unwrap();
    for attempt in 0..3u64 {
        let hello = build_client_hello([attempt as u8; 32], &[], &[GCM128]);
        let spoofer: SocketAddr = format!("127.0.0.1:{}", 7000 + attempt).parse().unwrap();
        server
            .feed_recv(
                &handshake_record(attempt, &[(msg_type::CLIENT_HELLO, 0, &hello)]),
                spoofer,
                0,
            )
            .unwrap();
        let reply = records(&server.poll_send().unwrap());
        assert_eq!(reply.len(), 1);
        assert_eq!(reply[0].sequence, attempt, "HVR echoes the ClientHello record sequence");
        assert_eq!(split_messages(&reply[0].fragment)[0].msg_type, msg_type::HELLO_VERIFY_REQUEST);
    }
    assert!(server.timeout(0).is_none(), "no retransmission state for HVR");
}

#[test]
fn server_ignores_fragmented_and_malformed_client_hellos() {
    let mut server = Connection::new(Config::server()).unwrap();
    let hello = build_client_hello([9; 32], &[], &[GCM128]);
    let header = HandshakeHeader {
        msg_type: msg_type::CLIENT_HELLO,
        length: hello.len() as u32,
        message_seq: 0,
        fragment_offset: 0,
        fragment_length: 10,
    };
    let mut fragment = header.encode().to_vec();
    fragment.extend_from_slice(&hello[..10]);
    let partial = Record::new(content_type::HANDSHAKE, 0, 0, fragment).encode();
    server.feed_recv(&partial, client_addr(), 0).unwrap();
    let garbage = handshake_record(1, &[(msg_type::CLIENT_HELLO, 0, &[1, 2, 3])]);
    server.feed_recv(&garbage, client_addr(), 0).unwrap();
    server.feed_recv(&[0x16, 0xfe], client_addr(), 0).unwrap();
    assert!(server.poll_send().is_none());
}

struct EvilServer {
    client: Connection,
    cert: SelfSignedCertificate,
    random: [u8; 32],
    client_random: [u8; 32],
    transcript: Vec<u8>,
    next_seq: u16,
    ephemeral: Option<EcdheKeyPair>,
}

impl EvilServer {
    fn connect(config: Config, hello_verify: bool) -> Self {
        let mut client = Connection::new(config).unwrap();
        let first = plaintext_messages(&client.poll_send().unwrap());
        assert_eq!((first[0].msg_type, first[0].seq), (msg_type::CLIENT_HELLO, 0));
        let hello = if hello_verify {
            let hvr = build_hello_verify_request(vec![7; 32]);
            client
                .feed_recv(
                    &handshake_record(0, &[(msg_type::HELLO_VERIFY_REQUEST, 0, &hvr)]),
                    server_addr(),
                    0,
                )
                .unwrap();
            let second = plaintext_messages(&client.poll_send().unwrap());
            assert_eq!((second[0].msg_type, second[0].seq), (msg_type::CLIENT_HELLO, 1));
            assert_eq!(ClientHello::decode(&second[0].body).unwrap().cookie, vec![7; 32]);
            second.into_iter().next().unwrap()
        } else {
            first.into_iter().next().unwrap()
        };
        let client_random = ClientHello::decode(&hello.body).unwrap().random;
        Self {
            client,
            cert: generate().unwrap(),
            random: [0x24; 32],
            client_random,
            transcript: frame(msg_type::CLIENT_HELLO, hello.seq, &hello.body),
            next_seq: hello.seq,
            ephemeral: None,
        }
    }

    fn seq(&mut self) -> u16 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    fn server_hello(&self) -> Vec<u8> {
        build_server_hello(self.random, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, Some(GCM128))
    }

    fn server_key_exchange(&mut self) -> Vec<u8> {
        let ephemeral = EcdheKeyPair::generate().unwrap();
        let body = build_server_key_exchange(
            &self.cert.key,
            &self.client_random,
            &self.random,
            ephemeral.public_point().to_vec(),
        )
        .unwrap();
        self.ephemeral = Some(ephemeral);
        body
    }

    fn send(&mut self, messages: &[(u8, &[u8])]) -> Result<(), Error> {
        let mut framed = Vec::new();
        for (mtype, body) in messages {
            let seq = self.seq();
            framed.push((*mtype, seq, body.to_vec()));
            self.transcript.extend_from_slice(&frame(*mtype, seq, body));
        }
        let borrowed: Vec<(u8, u16, &[u8])> =
            framed.iter().map(|(t, s, b)| (*t, *s, b.as_slice())).collect();
        let record = handshake_record(u64::from(self.next_seq), &borrowed);
        self.client.feed_recv(&record, server_addr(), 0)
    }
}

fn assert_client_sent_no_key_exchange(client: &mut Connection, description: u8) {
    let sent = client.poll_send().expect("fatal alert queued");
    assert!(plaintext_messages(&sent).is_empty());
    assert_fatal_alert(Some(sent), description);
}

#[test]
fn evil_server_harness_completes_without_hello_verify_or_certificate_request() {
    let mut s = EvilServer::connect(Config::client(), false);
    assert_eq!(s.next_seq, 0);
    let certificate = build_certificate(s.cert.der.clone());
    let sh = s.server_hello();
    let ske = s.server_key_exchange();
    s.send(&[
        (msg_type::SERVER_HELLO, &sh),
        (msg_type::CERTIFICATE, &certificate),
        (msg_type::SERVER_KEY_EXCHANGE, &ske),
        (msg_type::SERVER_HELLO_DONE, &[]),
    ])
    .unwrap();

    let flight = records(&s.client.poll_send().unwrap());
    let contents: Vec<(u8, u16)> = flight.iter().map(|r| (r.content_type, r.epoch)).collect();
    assert_eq!(
        contents,
        [
            (content_type::HANDSHAKE, 0),
            (content_type::CHANGE_CIPHER_SPEC, 0),
            (content_type::HANDSHAKE, 1),
        ],
        "no client Certificate or CertificateVerify without a CertificateRequest"
    );
    let cke_message = &split_messages(&flight[0].fragment)[0];
    assert_eq!((cke_message.msg_type, cke_message.seq), (msg_type::CLIENT_KEY_EXCHANGE, 1));
    s.transcript
        .extend_from_slice(&frame(cke_message.msg_type, cke_message.seq, &cke_message.body));
    let client_point = ClientKeyExchange::decode(&cke_message.body).unwrap().public_point;
    let premaster = s.ephemeral.take().unwrap().agree(&client_point).unwrap();
    let master =
        extended_master_secret(&premaster, &sha256(&s.transcript).unwrap()).unwrap();
    let keys = derive_keys(master.as_slice(), &s.random, &s.client_random).unwrap();

    let client_finished = split_messages(
        &unprotect(&keys.client, 1, flight[2].sequence, content_type::HANDSHAKE, DTLS_1_2, &flight[2].fragment)
            .unwrap(),
    );
    assert_eq!(client_finished[0].seq, 2);
    assert_eq!(
        client_finished[0].body,
        client_finished_verify_data(master.as_slice(), &s.transcript).unwrap()
    );
    s.transcript.extend_from_slice(&frame(
        msg_type::FINISHED,
        client_finished[0].seq,
        &client_finished[0].body,
    ));

    let verify_data = server_finished_verify_data(master.as_slice(), &s.transcript).unwrap();
    let seq = s.seq();
    let mut datagram = ccs_record(90);
    datagram.extend_from_slice(&protected_record(
        &keys.server,
        0,
        content_type::HANDSHAKE,
        &frame(msg_type::FINISHED, seq, &verify_data),
    ));
    s.client.feed_recv(&datagram, server_addr(), 0).unwrap();

    assert!(s.client.is_handshake_done());
    assert_eq!(
        s.client.peer_fingerprint(),
        Some(sha256_fingerprint(&s.cert.der).unwrap())
    );
    assert_eq!(
        s.client.export_keying_material(DTLS_SRTP_LABEL, None, 56).unwrap(),
        export_keying_material(
            master.as_slice(),
            &s.client_random,
            &s.random,
            DTLS_SRTP_LABEL,
            None,
            56
        )
        .unwrap()
    );
}

#[test]
fn client_rejects_a_second_certificate_after_server_key_exchange() {
    let victim = generate().unwrap();
    let mut s = EvilServer::connect(Config::client(), true);
    let own_certificate = build_certificate(s.cert.der.clone());
    let victim_certificate = build_certificate(victim.der.clone());
    let sh = s.server_hello();
    let ske = s.server_key_exchange();
    let err = s
        .send(&[
            (msg_type::SERVER_HELLO, &sh),
            (msg_type::CERTIFICATE, &own_certificate),
            (msg_type::SERVER_KEY_EXCHANGE, &ske),
            (msg_type::CERTIFICATE, &victim_certificate),
            (msg_type::SERVER_HELLO_DONE, &[]),
        ])
        .unwrap_err();
    assert!(matches!(err, Error::UnexpectedMessage(_)), "{err}");
    assert_client_sent_no_key_exchange(&mut s.client, 10);
    assert_unauthenticated(&s.client);
}

#[test]
fn client_rejects_a_swapped_certificate() {
    let victim = generate().unwrap();
    let mut s = EvilServer::connect(Config::client(), true);
    let victim_certificate = build_certificate(victim.der.clone());
    let sh = s.server_hello();
    let ske = s.server_key_exchange();
    let err = s
        .send(&[
            (msg_type::SERVER_HELLO, &sh),
            (msg_type::CERTIFICATE, &victim_certificate),
            (msg_type::SERVER_KEY_EXCHANGE, &ske),
        ])
        .unwrap_err();
    assert!(matches!(err, Error::BadSignature), "{err}");
    assert_client_sent_no_key_exchange(&mut s.client, 51);
    assert_unauthenticated(&s.client);
}

#[test]
fn pinned_client_rejects_the_wrong_certificate_before_server_key_exchange() {
    let victim = generate().unwrap();
    let mut s = EvilServer::connect(
        Config::client().with_expected_peer_fingerprint(sha256_fingerprint(&victim.der).unwrap()),
        true,
    );
    let own_certificate = build_certificate(s.cert.der.clone());
    let sh = s.server_hello();
    let err = s
        .send(&[
            (msg_type::SERVER_HELLO, &sh),
            (msg_type::CERTIFICATE, &own_certificate),
        ])
        .unwrap_err();
    assert!(matches!(err, Error::FingerprintMismatch), "{err}");
    assert_client_sent_no_key_exchange(&mut s.client, 42);
}

#[test]
fn client_rejects_out_of_order_server_messages() {
    let mut s = EvilServer::connect(Config::client(), true);
    let certificate = build_certificate(s.cert.der.clone());
    let sh = s.server_hello();
    let ske = s.server_key_exchange();
    let err = s
        .send(&[
            (msg_type::SERVER_HELLO, &sh),
            (msg_type::SERVER_KEY_EXCHANGE, &ske),
            (msg_type::CERTIFICATE, &certificate),
        ])
        .unwrap_err();
    assert!(matches!(err, Error::UnexpectedMessage(_)), "{err}");
    assert_client_sent_no_key_exchange(&mut s.client, 10);
}

#[test]
fn client_rejects_a_missing_server_key_exchange() {
    let mut s = EvilServer::connect(Config::client(), true);
    let certificate = build_certificate(s.cert.der.clone());
    let sh = s.server_hello();
    let err = s
        .send(&[
            (msg_type::SERVER_HELLO, &sh),
            (msg_type::CERTIFICATE, &certificate),
            (msg_type::SERVER_HELLO_DONE, &[]),
        ])
        .unwrap_err();
    assert!(matches!(err, Error::UnexpectedMessage(_)), "{err}");
    assert_client_sent_no_key_exchange(&mut s.client, 10);
}

#[test]
fn client_rejects_a_duplicate_server_hello_but_ignores_retransmissions() {
    let mut s = EvilServer::connect(Config::client(), true);
    let sh = s.server_hello();
    s.send(&[(msg_type::SERVER_HELLO, &sh)]).unwrap();
    s.client
        .feed_recv(
            &handshake_record(70, &[(msg_type::SERVER_HELLO, 1, &sh)]),
            server_addr(),
            0,
        )
        .unwrap();
    let err = s.send(&[(msg_type::SERVER_HELLO, &sh)]).unwrap_err();
    assert!(matches!(err, Error::UnexpectedMessage(_)), "{err}");
}

#[test]
fn client_rejects_a_hello_verify_request_after_server_hello() {
    let mut s = EvilServer::connect(Config::client(), true);
    let sh = s.server_hello();
    let hvr = build_hello_verify_request(vec![1; 32]);
    let err = s
        .send(&[
            (msg_type::SERVER_HELLO, &sh),
            (msg_type::HELLO_VERIFY_REQUEST, &hvr),
        ])
        .unwrap_err();
    assert!(matches!(err, Error::UnexpectedMessage(_)), "{err}");
}

#[test]
fn client_rejects_a_server_hello_it_did_not_ask_for() {
    let mut s = EvilServer::connect(Config::client(), true);
    let bad = build_server_hello(s.random, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, Some(0x0008));
    let err = s.send(&[(msg_type::SERVER_HELLO, &bad)]).unwrap_err();
    assert!(matches!(err, Error::Negotiation(_)), "{err}");
    assert_client_sent_no_key_exchange(&mut s.client, 40);
}

#[test]
fn client_ignores_late_plaintext_handshake_but_honours_a_handshake_alert() {
    let mut s = EvilServer::connect(Config::client(), true);
    let certificate = build_certificate(s.cert.der.clone());
    let request = build_certificate_request();
    let sh = s.server_hello();
    let ske = s.server_key_exchange();
    s.send(&[
        (msg_type::SERVER_HELLO, &sh),
        (msg_type::CERTIFICATE, &certificate),
        (msg_type::SERVER_KEY_EXCHANGE, &ske),
        (msg_type::CERTIFICATE_REQUEST, &request),
        (msg_type::SERVER_HELLO_DONE, &[]),
    ])
    .unwrap();
    let flight = plaintext_messages(&s.client.poll_send().unwrap());
    let shape: Vec<(u8, u16)> = flight.iter().map(|m| (m.msg_type, m.seq)).collect();
    assert_eq!(
        shape,
        [
            (msg_type::CERTIFICATE, 2),
            (msg_type::CLIENT_KEY_EXCHANGE, 3),
            (msg_type::CERTIFICATE_VERIFY, 4),
        ]
    );
    s.send(&[(msg_type::SERVER_HELLO_DONE, &[])]).unwrap();
    assert!(s.client.poll_send().is_none());
    let err = s
        .client
        .feed_recv(
            &Record::new(content_type::ALERT, 0, 99, vec![2, 40]).encode(),
            server_addr(),
            0,
        )
        .unwrap_err();
    assert!(matches!(err, Error::Alert { level: 2, description: 40 }), "{err}");
    assert!(s.client.poll_send().is_none(), "no alert is sent in reply to an alert");
    assert_unauthenticated(&s.client);
}

#[test]
fn server_answers_at_most_one_hello_per_record() {
    let mut server = Connection::new(Config::server()).unwrap();
    let hellos: Vec<Vec<u8>> = (0..8u8)
        .map(|i| build_client_hello([i; 32], &[], &[GCM128]))
        .collect();
    let messages: Vec<(u8, u16, &[u8])> = hellos
        .iter()
        .map(|hello| (msg_type::CLIENT_HELLO, 0, hello.as_slice()))
        .collect();
    server
        .feed_recv(&handshake_record(0, &messages), client_addr(), 0)
        .unwrap();
    assert_eq!(records(&server.poll_send().unwrap()).len(), 1);
}
