//! The sans-I/O DTLS [`Connection`] state machine.
//!
//! A `Connection` owns no sockets and spawns no threads. The caller drives it:
//! bytes received from the network go in via [`Connection::feed_recv`], bytes to
//! transmit come out via [`Connection::poll_send`], and timeouts are serviced
//! with [`Connection::handle_timeout`]. This is exactly the shape WebRTC needs,
//! where the same UDP socket is shared with STUN and SRTP and demultiplexed by
//! the application.

use std::net::SocketAddr;

use zeroize::Zeroizing;

use crate::cert::fingerprint::sha256_fingerprint;
use crate::cert::parse::{parse_leaf_public_key, PeerPublicKey};
use crate::config::{Config, SrtpProfile};
use crate::crypto::constant_time_eq;
use crate::crypto::ecdhe_p256::EcdheKeyPair;
use crate::crypto::hash::sha256;
use crate::error::{Error, Result};
use crate::exporter::{export_keying_material, ExportedKeyingMaterial};
use crate::extensions::signature_algorithms::ECDSA_SECP256R1_SHA256;
use crate::handshake::client::{self, ClientPhase};
use crate::handshake::flight::Flight;
use crate::handshake::fragment::HandshakeMessage;
use crate::handshake::keyschedule::{
    client_finished_verify_data, derive_keys, extended_master_secret, server_finished_verify_data,
    KeyMaterial,
};
use crate::handshake::messages::{
    msg_type, Certificate, CertificateRequest, CertificateVerify, ClientHello, ClientKeyExchange,
    Finished, HandshakeHeader, HelloVerifyRequest, ServerHello, ServerKeyExchange,
    HANDSHAKE_HEADER_LEN,
};
use crate::handshake::server::{self, ServerPhase};
use crate::handshake::{frame_message, CookieSecret, Reassembler, CHANGE_CIPHER_SPEC_BODY};
use crate::record::ciphertext::{self, AeadKeys};
use crate::record::{content_type, EpochSeq, Record, ReplayWindow, DTLS_1_2};
use crate::role::Role;
use crate::timer::{RetransmitTimer, MAX_RETRANSMISSIONS};

const ALERT_FATAL: u8 = 2;
const CLOSE_NOTIFY: u8 = 0;
const MAX_HELLO_VERIFY_REQUESTS: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Client(ClientPhase),
    Server(ServerPhase),
    Closed,
}

/// A DTLS 1.2 connection endpoint.
pub struct Connection {
    config: Config,
    role: Role,
    state: State,

    local_cert: crate::cert::Certificate,
    local_fingerprint: [u8; 32],
    local_random: [u8; 32],
    client_random: Option<[u8; 32]>,
    server_random: Option<[u8; 32]>,

    cookie_secret: CookieSecret,
    hello_verify_requests: u8,
    last_client_hello: Vec<u8>,
    certificate_requested: bool,
    ephemeral: Option<EcdheKeyPair>,
    peer_eph_point: Option<Vec<u8>>,
    peer_cert_der: Option<Vec<u8>>,
    peer_public_key: Option<PeerPublicKey>,
    peer_fingerprint: Option<[u8; 32]>,

    cipher_suite: Option<u16>,
    srtp_code: Option<u16>,

    transcript: Vec<u8>,
    master_secret: Option<Zeroizing<[u8; 48]>>,
    keys: Option<KeyMaterial>,
    early_finished: Option<HandshakeMessage>,

    next_send_seq: u16,
    write_epoch: u16,
    epoch0_seq: EpochSeq,
    epoch1_seq: EpochSeq,
    peer_epoch: u16,
    replay: ReplayWindow,
    reasm: Reassembler,

    outgoing: Vec<u8>,
    last_flight: Flight,
    timer: RetransmitTimer,
}

impl Connection {
    /// Create a new connection. A client immediately queues its first
    /// `ClientHello`, retrievable via [`Connection::poll_send`].
    ///
    /// # Errors
    ///
    /// Returns an error if certificate generation or RNG access fails.
    pub fn new(mut config: Config) -> Result<Self> {
        let local_cert = match config.certificate.take() {
            Some(certificate) => certificate,
            None => crate::cert::Certificate::generate()?,
        };
        let local_fingerprint = local_cert.fingerprint();
        let mut local_random = [0u8; 32];
        crate::crypto::fill_random(&mut local_random)?;
        let cookie_secret = CookieSecret::generate()?;
        let role = config.role;

        let mut conn = Self {
            config,
            role,
            state: match role {
                Role::Client => State::Client(ClientPhase::WaitServerHello),
                Role::Server => State::Server(ServerPhase::WaitClientHello),
            },
            local_cert,
            local_fingerprint,
            local_random,
            client_random: None,
            server_random: None,
            cookie_secret,
            hello_verify_requests: 0,
            last_client_hello: Vec::new(),
            certificate_requested: false,
            ephemeral: None,
            peer_eph_point: None,
            peer_cert_der: None,
            peer_public_key: None,
            peer_fingerprint: None,
            cipher_suite: None,
            srtp_code: None,
            transcript: Vec::new(),
            master_secret: None,
            keys: None,
            early_finished: None,
            next_send_seq: 0,
            write_epoch: 0,
            epoch0_seq: EpochSeq::new(),
            epoch1_seq: EpochSeq::new(),
            peer_epoch: 0,
            replay: ReplayWindow::new(),
            reasm: Reassembler::new(),
            outgoing: Vec::new(),
            last_flight: Flight::new(),
            timer: RetransmitTimer::new(),
        };

        match role {
            Role::Client => {
                conn.client_random = Some(local_random);
                conn.send_client_hello(&[], 0)?;
            }
            Role::Server => {
                conn.server_random = Some(local_random);
            }
        }
        Ok(conn)
    }

    /// The SHA-256 fingerprint of our own certificate (the SDP
    /// `a=fingerprint` value the peer must validate).
    #[must_use]
    pub fn local_fingerprint(&self) -> [u8; 32] {
        self.local_fingerprint
    }

    /// The SHA-256 fingerprint of the peer's certificate, once the handshake
    /// has completed.
    #[must_use]
    pub fn peer_fingerprint(&self) -> Option<[u8; 32]> {
        if self.is_handshake_done() {
            self.peer_fingerprint
        } else {
            None
        }
    }

    #[allow(missing_docs)]
    pub fn set_expected_peer_fingerprint(&mut self, fingerprint: [u8; 32]) -> Result<()> {
        self.ensure_open()?;
        if let Some(pinned) = self.config.expected_peer_fingerprint {
            return if constant_time_eq(&pinned, &fingerprint) {
                Ok(())
            } else {
                Err(Error::InvalidState("a different peer fingerprint is already pinned"))
            };
        }
        if let Some(actual) = self.peer_fingerprint {
            if !constant_time_eq(&actual, &fingerprint) {
                return Err(self.fail(Error::FingerprintMismatch));
            }
        }
        self.config.expected_peer_fingerprint = Some(fingerprint);
        Ok(())
    }

    /// Whether the handshake has completed successfully.
    #[must_use]
    pub fn is_handshake_done(&self) -> bool {
        matches!(
            self.state,
            State::Client(ClientPhase::Done) | State::Server(ServerPhase::Done)
        )
    }

    /// The negotiated SRTP profile, if any.
    #[must_use]
    pub fn selected_srtp_profile(&self) -> Option<SrtpProfile> {
        if self.is_handshake_done() {
            self.srtp_code.and_then(SrtpProfile::from_code)
        } else {
            None
        }
    }

    /// Take any bytes queued for transmission (one or more records).
    pub fn poll_send(&mut self) -> Option<Vec<u8>> {
        if self.outgoing.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.outgoing))
        }
    }

    /// Export `length` bytes of keying material per RFC 5705.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidState`] if called before the handshake
    /// completes.
    pub fn export_keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        length: usize,
    ) -> Result<ExportedKeyingMaterial> {
        if !self.is_handshake_done() {
            return Err(Error::InvalidState("handshake not complete"));
        }
        let master = self
            .master_secret
            .as_ref()
            .ok_or(Error::InvalidState("master secret not established"))?;
        let client_random = self
            .client_random
            .ok_or(Error::InvalidState("client random unknown"))?;
        let server_random = self
            .server_random
            .ok_or(Error::InvalidState("server random unknown"))?;
        export_keying_material(
            master.as_slice(),
            &client_random,
            &server_random,
            label,
            context,
            length,
        )
    }

    /// Milliseconds until the retransmission timer next fires, or `None`.
    #[must_use]
    pub fn timeout(&self, now_ms: u64) -> Option<u64> {
        self.timer.remaining_ms(now_ms)
    }

    /// Service the retransmission timer; resends the last flight on expiry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] once the flight has been retransmitted
    /// [`MAX_RETRANSMISSIONS`] times without a reply.
    pub fn handle_timeout(&mut self, now_ms: u64) -> Result<()> {
        self.ensure_open()?;
        if self.timer.on_check(now_ms) {
            if self.timer.expirations() > MAX_RETRANSMISSIONS {
                return Err(self.fail(Error::Timeout));
            }
            if let Err(error) = self.retransmit() {
                return Err(self.fail(error));
            }
        }
        Ok(())
    }

    /// Feed a received datagram (which may contain several records).
    ///
    /// # Errors
    ///
    /// Returns an error on handshake failures or a peer alert; malformed,
    /// unauthenticated and unexpected records are discarded.
    pub fn feed_recv(&mut self, datagram: &[u8], peer: SocketAddr, now_ms: u64) -> Result<()> {
        self.ensure_open()?;
        let mut rest = datagram;
        while !rest.is_empty() {
            let Ok((record, consumed)) = Record::decode(rest) else {
                break;
            };
            rest = &rest[consumed..];
            if let Err(error) = self.process_record(&record, peer, now_ms) {
                return Err(self.fail(error));
            }
        }
        Ok(())
    }

    fn ensure_open(&self) -> Result<()> {
        if self.state == State::Closed {
            Err(Error::InvalidState("connection closed"))
        } else {
            Ok(())
        }
    }

    fn fail(&mut self, error: Error) -> Error {
        if self.state != State::Closed {
            if let Some(description) = alert_description(&error) {
                let _ = self.send_record(content_type::ALERT, &[ALERT_FATAL, description], false);
            }
            self.state = State::Closed;
        }
        self.timer.disarm();
        self.last_flight.clear();
        self.reasm.clear();
        self.early_finished = None;
        self.ephemeral = None;
        self.master_secret = None;
        self.keys = None;
        error
    }

    fn my_write_keys(&self) -> Option<&AeadKeys> {
        let km = self.keys.as_ref()?;
        Some(match self.role {
            Role::Client => &km.client,
            Role::Server => &km.server,
        })
    }

    fn peer_write_keys(&self) -> Option<&AeadKeys> {
        let km = self.keys.as_ref()?;
        Some(match self.role {
            Role::Client => &km.server,
            Role::Server => &km.client,
        })
    }

    fn encode_record(&mut self, content_type: u8, epoch: u16, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (sequence, fragment) = if epoch == 0 {
            (self.epoch0_seq.take()?, plaintext.to_vec())
        } else {
            let sequence = self.epoch1_seq.take()?;
            let keys = self
                .my_write_keys()
                .ok_or(Error::InvalidState("no write keys for epoch 1"))?;
            let fragment =
                ciphertext::protect(keys, epoch, sequence, content_type, DTLS_1_2, plaintext)?;
            (sequence, fragment)
        };
        Ok(Record::new(content_type, epoch, sequence, fragment).encode())
    }

    fn send_record(&mut self, content_type: u8, plaintext: &[u8], retain: bool) -> Result<()> {
        let epoch = self.write_epoch;
        let encoded = self.encode_record(content_type, epoch, plaintext)?;
        self.outgoing.extend_from_slice(&encoded);
        if retain {
            self.last_flight.push(content_type, epoch, plaintext.to_vec());
        }
        Ok(())
    }

    fn retransmit(&mut self) -> Result<()> {
        let flight = std::mem::take(&mut self.last_flight);
        let result = flight.records().iter().try_for_each(|record| {
            let encoded = self.encode_record(record.content_type, record.epoch, &record.plaintext)?;
            self.outgoing.extend_from_slice(&encoded);
            Ok(())
        });
        self.last_flight = flight;
        result
    }

    fn take_message_seq(&mut self) -> Result<u16> {
        let message_seq = self.next_send_seq;
        self.next_send_seq = message_seq
            .checked_add(1)
            .ok_or(Error::InvalidState("handshake message_seq exhausted"))?;
        Ok(message_seq)
    }

    fn send_handshake(&mut self, msg_type: u8, body: &[u8]) -> Result<()> {
        let message_seq = self.take_message_seq()?;
        let framed = frame_message(msg_type, message_seq, body);
        self.transcript.extend_from_slice(&framed);
        self.send_record(content_type::HANDSHAKE, &framed, true)
    }

    fn send_change_cipher_spec(&mut self) -> Result<()> {
        self.send_record(content_type::CHANGE_CIPHER_SPEC, &CHANGE_CIPHER_SPEC_BODY, true)?;
        self.write_epoch = 1;
        Ok(())
    }

    fn append_transcript(&mut self, msg_type: u8, message_seq: u16, body: &[u8]) {
        let framed = frame_message(msg_type, message_seq, body);
        self.transcript.extend_from_slice(&framed);
    }

    fn offered_srtp_codes(&self) -> Vec<u16> {
        self.config.srtp_profiles.iter().map(|p| p.code()).collect()
    }

    fn send_client_hello(&mut self, cookie: &[u8], now_ms: u64) -> Result<()> {
        let body = client::build_client_hello(self.local_random, cookie, &self.offered_srtp_codes());
        let message_seq = self.take_message_seq()?;
        let framed = frame_message(msg_type::CLIENT_HELLO, message_seq, &body);
        self.last_flight.clear();
        self.send_record(content_type::HANDSHAKE, &framed, true)?;
        self.last_client_hello = framed;
        self.timer.arm(now_ms);
        Ok(())
    }

    fn accepts_plaintext_handshake(&self) -> bool {
        self.peer_epoch == 0
            && match self.state {
                State::Client(phase) => matches!(
                    phase,
                    ClientPhase::WaitServerHello
                        | ClientPhase::WaitCertificate
                        | ClientPhase::WaitServerKeyExchange
                        | ClientPhase::WaitCertificateRequest
                        | ClientPhase::WaitServerHelloDone
                ),
                State::Server(phase) => matches!(
                    phase,
                    ServerPhase::WaitCertificate
                        | ServerPhase::WaitClientKeyExchange
                        | ServerPhase::WaitCertificateVerify
                ),
                State::Closed => false,
            }
    }

    fn accepts_plaintext_alerts(&self) -> bool {
        self.peer_epoch == 0
            && match self.state {
                State::Client(phase) => phase != ClientPhase::Done,
                State::Server(phase) => {
                    !matches!(phase, ServerPhase::WaitClientHello | ServerPhase::Done)
                }
                State::Closed => false,
            }
    }

    fn awaits_change_cipher_spec(&self) -> bool {
        matches!(
            self.state,
            State::Client(ClientPhase::WaitChangeCipherSpec)
                | State::Server(ServerPhase::WaitChangeCipherSpec)
        )
    }

    fn process_record(&mut self, record: &Record, peer: SocketAddr, now_ms: u64) -> Result<()> {
        match record.epoch {
            0 => self.process_plaintext_record(record, peer, now_ms),
            1 => self.process_protected_record(record, now_ms),
            _ => Ok(()),
        }
    }

    fn process_plaintext_record(
        &mut self,
        record: &Record,
        peer: SocketAddr,
        now_ms: u64,
    ) -> Result<()> {
        if record.version >> 8 != 0xFE {
            return Ok(());
        }
        match record.content_type {
            content_type::HANDSHAKE => {
                if self.state == State::Server(ServerPhase::WaitClientHello) {
                    return self.process_client_hellos(record, peer, now_ms);
                }
                if !self.accepts_plaintext_handshake() {
                    return Ok(());
                }
                let Ok(fragments) = parse_fragments(&record.fragment) else {
                    return Ok(());
                };
                self.process_fragments(0, &fragments, now_ms)
            }
            content_type::CHANGE_CIPHER_SPEC => {
                if record.fragment == CHANGE_CIPHER_SPEC_BODY && self.awaits_change_cipher_spec() {
                    self.accept_change_cipher_spec(now_ms)
                } else {
                    Ok(())
                }
            }
            content_type::ALERT if self.accepts_plaintext_alerts() => {
                match record.fragment.as_slice() {
                    &[level, description] => process_alert(level, description),
                    _ => Ok(()),
                }
            }
            // Application data and any unknown content type are ignored here;
            // the handshake layer never expects them.
            _ => Ok(()),
        }
    }

    fn process_protected_record(&mut self, record: &Record, now_ms: u64) -> Result<()> {
        if record.version != DTLS_1_2 || !self.replay.accepts(record.sequence) {
            return Ok(());
        }
        let Some(keys) = self.peer_write_keys() else {
            return Ok(());
        };
        let Ok(plaintext) = ciphertext::unprotect(
            keys,
            record.epoch,
            record.sequence,
            record.content_type,
            DTLS_1_2,
            &record.fragment,
        ) else {
            return Ok(());
        };
        self.replay.mark(record.sequence);
        match record.content_type {
            content_type::HANDSHAKE => {
                let fragments = parse_fragments(&plaintext)?;
                if self.is_handshake_done() {
                    self.on_retransmitted_final_flight(&fragments)
                } else {
                    self.process_fragments(1, &fragments, now_ms)
                }
            }
            content_type::ALERT => match plaintext.as_slice() {
                &[level, description] => process_alert(level, description),
                _ => Err(Error::Decode("malformed alert".to_owned())),
            },
            _ => Ok(()),
        }
    }

    fn on_retransmitted_final_flight(&mut self, fragments: &[(HandshakeHeader, &[u8])]) -> Result<()> {
        let peer_finished_again = fragments.iter().any(|(header, _)| {
            header.msg_type == msg_type::FINISHED && header.message_seq < self.reasm.next_seq()
        });
        if self.role.is_server() && peer_finished_again {
            self.retransmit()?;
        }
        Ok(())
    }

    fn process_fragments(
        &mut self,
        epoch: u16,
        fragments: &[(HandshakeHeader, &[u8])],
        now_ms: u64,
    ) -> Result<()> {
        for (header, body) in fragments {
            for message in self.reasm.feed(epoch, header, body)? {
                self.on_message(message, now_ms)?;
            }
        }
        Ok(())
    }

    fn accept_change_cipher_spec(&mut self, now_ms: u64) -> Result<()> {
        self.peer_epoch = 1;
        self.state = match self.state {
            State::Client(_) => State::Client(ClientPhase::WaitFinished),
            State::Server(_) => State::Server(ServerPhase::WaitFinished),
            State::Closed => State::Closed,
        };
        match self.early_finished.take() {
            Some(finished) => self.on_message(finished, now_ms),
            None => Ok(()),
        }
    }

    fn on_message(&mut self, message: HandshakeMessage, now_ms: u64) -> Result<()> {
        if message.epoch != 0 {
            return self.on_protected_message(message);
        }
        if message.msg_type == msg_type::FINISHED {
            return Err(Error::UnexpectedMessage(
                "Finished was not protected by the negotiated keys".to_owned(),
            ));
        }
        match self.state {
            State::Client(phase) => self.on_client_message(phase, &message, now_ms),
            State::Server(phase) => self.on_server_message(phase, &message),
            State::Closed => Ok(()),
        }
    }

    fn on_protected_message(&mut self, message: HandshakeMessage) -> Result<()> {
        if message.msg_type != msg_type::FINISHED {
            return Err(Error::UnexpectedMessage(format!(
                "protected handshake type {} where only Finished is valid",
                message.msg_type
            )));
        }
        match self.state {
            State::Client(ClientPhase::WaitFinished) => {
                self.client_finished(message.message_seq, &message.body)
            }
            State::Server(ServerPhase::WaitFinished) => {
                self.server_finished(message.message_seq, &message.body)
            }
            State::Client(ClientPhase::WaitChangeCipherSpec)
            | State::Server(ServerPhase::WaitChangeCipherSpec) => {
                self.early_finished = Some(message);
                Ok(())
            }
            state => Err(Error::UnexpectedMessage(format!(
                "Finished received in state {state:?}"
            ))),
        }
    }

    fn on_client_message(
        &mut self,
        phase: ClientPhase,
        message: &HandshakeMessage,
        now_ms: u64,
    ) -> Result<()> {
        let (seq, body) = (message.message_seq, message.body.as_slice());
        match (phase, message.msg_type) {
            (ClientPhase::WaitServerHello, msg_type::HELLO_VERIFY_REQUEST) => {
                self.client_hello_verify_request(body, now_ms)
            }
            (ClientPhase::WaitServerHello, msg_type::SERVER_HELLO) => {
                self.client_server_hello(seq, body)
            }
            (ClientPhase::WaitCertificate, msg_type::CERTIFICATE) => {
                self.client_certificate(seq, body)
            }
            (ClientPhase::WaitServerKeyExchange, msg_type::SERVER_KEY_EXCHANGE) => {
                self.client_server_key_exchange(seq, body)
            }
            (ClientPhase::WaitCertificateRequest, msg_type::CERTIFICATE_REQUEST) => {
                self.client_certificate_request(seq, body)
            }
            (
                ClientPhase::WaitCertificateRequest | ClientPhase::WaitServerHelloDone,
                msg_type::SERVER_HELLO_DONE,
            ) => self.client_server_hello_done(seq, body, now_ms),
            (phase, mtype) => Err(Error::UnexpectedMessage(format!(
                "client got handshake type {mtype} in phase {phase:?}"
            ))),
        }
    }

    fn client_hello_verify_request(&mut self, body: &[u8], now_ms: u64) -> Result<()> {
        let hvr = HelloVerifyRequest::decode(body)?;
        if hvr.cookie.is_empty() {
            return Err(Error::UnexpectedMessage(
                "HelloVerifyRequest carries an empty cookie".to_owned(),
            ));
        }
        self.hello_verify_requests += 1;
        if self.hello_verify_requests > MAX_HELLO_VERIFY_REQUESTS {
            return Err(Error::UnexpectedMessage(
                "too many HelloVerifyRequests".to_owned(),
            ));
        }
        self.send_client_hello(&hvr.cookie, now_ms)
    }

    fn client_server_hello(&mut self, seq: u16, body: &[u8]) -> Result<()> {
        let sh = ServerHello::decode(body)?;
        let srtp_code = client::check_server_hello(&sh, &self.offered_srtp_codes())?;
        self.transcript.clone_from(&self.last_client_hello);
        self.append_transcript(msg_type::SERVER_HELLO, seq, body);
        self.server_random = Some(sh.random);
        self.cipher_suite = Some(sh.cipher_suite);
        self.srtp_code = srtp_code;
        self.state = State::Client(ClientPhase::WaitCertificate);
        Ok(())
    }

    fn accept_peer_certificate(&mut self, body: &[u8]) -> Result<()> {
        if self.peer_public_key.is_some() || self.peer_fingerprint.is_some() {
            return Err(Error::UnexpectedMessage(
                "peer certificate already received".to_owned(),
            ));
        }
        let leaf = Certificate::decode(body)?
            .certificates
            .into_iter()
            .next()
            .ok_or(Error::Negotiation("peer certificate"))?;
        let fingerprint = sha256_fingerprint(&leaf)?;
        if let Some(expected) = self.config.expected_peer_fingerprint {
            if !constant_time_eq(&expected, &fingerprint) {
                return Err(Error::FingerprintMismatch);
            }
        }
        self.peer_public_key = Some(parse_leaf_public_key(&leaf)?);
        self.peer_fingerprint = Some(fingerprint);
        self.peer_cert_der = Some(leaf);
        Ok(())
    }

    fn client_certificate(&mut self, seq: u16, body: &[u8]) -> Result<()> {
        self.accept_peer_certificate(body)?;
        self.append_transcript(msg_type::CERTIFICATE, seq, body);
        self.state = State::Client(ClientPhase::WaitServerKeyExchange);
        Ok(())
    }

    fn client_server_key_exchange(&mut self, seq: u16, body: &[u8]) -> Result<()> {
        let ske = ServerKeyExchange::decode(body)?;
        let peer_key = self
            .peer_public_key
            .as_ref()
            .ok_or(Error::InvalidState("no peer certificate before SKE"))?;
        let leaf = self
            .peer_cert_der
            .as_ref()
            .ok_or(Error::InvalidState("no peer certificate before SKE"))?;
        let client_random = self
            .client_random
            .ok_or(Error::InvalidState("no client random before SKE"))?;
        let server_random = self
            .server_random
            .ok_or(Error::InvalidState("no ServerHello before SKE"))?;
        let cipher_suite = self
            .cipher_suite
            .ok_or(Error::InvalidState("no ServerHello before SKE"))?;
        client::verify_server_key_exchange(
            peer_key,
            leaf,
            &client_random,
            &server_random,
            cipher_suite,
            &ske,
        )?;
        self.append_transcript(msg_type::SERVER_KEY_EXCHANGE, seq, body);
        self.peer_eph_point = Some(ske.public_point);
        self.state = State::Client(ClientPhase::WaitCertificateRequest);
        Ok(())
    }

    fn client_certificate_request(&mut self, seq: u16, body: &[u8]) -> Result<()> {
        client::check_certificate_request(&CertificateRequest::decode(body)?)?;
        self.append_transcript(msg_type::CERTIFICATE_REQUEST, seq, body);
        self.certificate_requested = true;
        self.state = State::Client(ClientPhase::WaitServerHelloDone);
        Ok(())
    }

    fn client_server_hello_done(&mut self, seq: u16, body: &[u8], now_ms: u64) -> Result<()> {
        if !body.is_empty() {
            return Err(Error::Decode("ServerHelloDone carries data".to_owned()));
        }
        self.append_transcript(msg_type::SERVER_HELLO_DONE, seq, body);
        self.finish_client_flight(now_ms)
    }

    fn finish_client_flight(&mut self, now_ms: u64) -> Result<()> {
        self.last_flight.clear();
        let server_random = self
            .server_random
            .ok_or(Error::InvalidState("no ServerHello before ServerHelloDone"))?;
        let client_random = self
            .client_random
            .ok_or(Error::InvalidState("no client random before ServerHelloDone"))?;
        let peer_point = self
            .peer_eph_point
            .clone()
            .ok_or(Error::InvalidState("no server ECDHE point"))?;
        let ephemeral = EcdheKeyPair::generate()?;
        let client_point = ephemeral.public_point().to_vec();
        let premaster = ephemeral.agree(&peer_point)?;

        if self.certificate_requested {
            // Client Certificate for mutual authentication.
            let cert = server::build_certificate(self.local_cert.der().to_vec());
            self.send_handshake(msg_type::CERTIFICATE, &cert)?;
        }

        // ClientKeyExchange.
        let cke = client::build_client_key_exchange(client_point);
        self.send_handshake(msg_type::CLIENT_KEY_EXCHANGE, &cke)?;

        // The extended master secret is derived over the transcript through
        // ClientKeyExchange (RFC 7627).
        let session_hash = sha256(&self.transcript)?;
        let master = extended_master_secret(&premaster, &session_hash)?;
        self.keys = Some(derive_keys(master.as_slice(), &server_random, &client_random)?);

        if self.certificate_requested {
            // CertificateVerify: sign the transcript so far
            // (ClientHello..ClientKeyExchange) with our certificate's private key.
            let signature = self.local_cert.key().sign_der(&self.transcript)?;
            let cert_verify = CertificateVerify {
                signature_algorithm: ECDSA_SECP256R1_SHA256,
                signature,
            }
            .encode();
            self.send_handshake(msg_type::CERTIFICATE_VERIFY, &cert_verify)?;
        }

        // Finished over the transcript through CertificateVerify.
        let verify_data = client_finished_verify_data(master.as_slice(), &self.transcript)?;
        self.master_secret = Some(master);
        self.send_change_cipher_spec()?;
        let finished = Finished { verify_data }.encode();
        self.send_handshake(msg_type::FINISHED, &finished)?;

        self.state = State::Client(ClientPhase::WaitChangeCipherSpec);
        self.timer.arm(now_ms);
        Ok(())
    }

    fn client_finished(&mut self, seq: u16, body: &[u8]) -> Result<()> {
        let finished = Finished::decode(body)?;
        let master = self
            .master_secret
            .as_ref()
            .ok_or(Error::InvalidState("no master secret before Finished"))?;
        let expected = server_finished_verify_data(master.as_slice(), &self.transcript)?;
        if !constant_time_eq(&finished.verify_data, &expected) {
            return Err(Error::BadFinished);
        }
        self.append_transcript(msg_type::FINISHED, seq, body);
        self.state = State::Client(ClientPhase::Done);
        self.timer.disarm();
        self.last_flight.clear();
        self.reasm.clear();
        Ok(())
    }

    fn process_client_hellos(&mut self, record: &Record, peer: SocketAddr, now_ms: u64) -> Result<()> {
        let Ok(fragments) = parse_fragments(&record.fragment) else {
            return Ok(());
        };
        for (index, (header, body)) in fragments.iter().enumerate() {
            let unfragmented = header.fragment_offset == 0 && header.fragment_length == header.length;
            if header.msg_type != msg_type::CLIENT_HELLO || !unfragmented {
                continue;
            }
            let Ok(hello) = ClientHello::decode(body) else {
                continue;
            };
            if !hello.cookie.is_empty() && self.cookie_secret.verify(peer, &hello)? {
                self.accept_client_hello(record.sequence, header.message_seq, &hello, body, now_ms)?;
                return self.process_fragments(0, &fragments[index + 1..], now_ms);
            }
            let cookie = self.cookie_secret.compute(peer, &hello)?;
            let hvr = server::build_hello_verify_request(cookie);
            let framed = frame_message(msg_type::HELLO_VERIFY_REQUEST, header.message_seq, &hvr);
            let encoded = Record::new(content_type::HANDSHAKE, 0, record.sequence, framed).encode();
            self.outgoing.extend_from_slice(&encoded);
            break;
        }
        Ok(())
    }

    fn accept_client_hello(
        &mut self,
        record_sequence: u64,
        message_seq: u16,
        hello: &ClientHello,
        body: &[u8],
        now_ms: u64,
    ) -> Result<()> {
        let choice = server::check_client_hello(hello, &self.offered_srtp_codes())?;
        let next_receive = message_seq
            .checked_add(1)
            .ok_or(Error::Decode("ClientHello message_seq exhausted".to_owned()))?;
        self.reasm = Reassembler::starting_at(next_receive);
        self.next_send_seq = message_seq;
        self.epoch0_seq = EpochSeq::starting_at(record_sequence);
        self.transcript.clear();
        self.append_transcript(msg_type::CLIENT_HELLO, message_seq, body);
        self.client_random = Some(hello.random);
        self.cipher_suite = Some(choice.cipher_suite);
        self.srtp_code = choice.srtp_profile;
        self.send_server_flight(choice.cipher_suite, now_ms)
    }

    fn send_server_flight(&mut self, cipher_suite: u16, now_ms: u64) -> Result<()> {
        self.last_flight.clear();
        let server_random = self.local_random;
        let client_random = self
            .client_random
            .ok_or(Error::InvalidState("no client random before ServerHello"))?;

        let sh = server::build_server_hello(server_random, cipher_suite, self.srtp_code);
        self.send_handshake(msg_type::SERVER_HELLO, &sh)?;

        let cert = server::build_certificate(self.local_cert.der().to_vec());
        self.send_handshake(msg_type::CERTIFICATE, &cert)?;

        let ephemeral = EcdheKeyPair::generate()?;
        let point = ephemeral.public_point().to_vec();
        let ske = server::build_server_key_exchange(
            self.local_cert.key(),
            &client_random,
            &server_random,
            point,
        )?;
        self.ephemeral = Some(ephemeral);
        self.send_handshake(msg_type::SERVER_KEY_EXCHANGE, &ske)?;

        // CertificateRequest — WebRTC requires mutual auth.
        let cert_req = server::build_certificate_request();
        self.send_handshake(msg_type::CERTIFICATE_REQUEST, &cert_req)?;

        self.send_handshake(msg_type::SERVER_HELLO_DONE, &[])?;

        self.state = State::Server(ServerPhase::WaitCertificate);
        self.timer.arm(now_ms);
        Ok(())
    }

    fn on_server_message(&mut self, phase: ServerPhase, message: &HandshakeMessage) -> Result<()> {
        let (seq, body) = (message.message_seq, message.body.as_slice());
        match (phase, message.msg_type) {
            (ServerPhase::WaitCertificate, msg_type::CERTIFICATE) => {
                self.accept_peer_certificate(body)?;
                self.append_transcript(msg_type::CERTIFICATE, seq, body);
                self.state = State::Server(ServerPhase::WaitClientKeyExchange);
                Ok(())
            }
            (ServerPhase::WaitClientKeyExchange, msg_type::CLIENT_KEY_EXCHANGE) => {
                self.server_client_key_exchange(seq, body)
            }
            (ServerPhase::WaitCertificateVerify, msg_type::CERTIFICATE_VERIFY) => {
                self.server_certificate_verify(seq, body)
            }
            (phase, mtype) => Err(Error::UnexpectedMessage(format!(
                "server got handshake type {mtype} in phase {phase:?}"
            ))),
        }
    }

    fn server_client_key_exchange(&mut self, seq: u16, body: &[u8]) -> Result<()> {
        let cke = ClientKeyExchange::decode(body)?;
        self.append_transcript(msg_type::CLIENT_KEY_EXCHANGE, seq, body);
        let ephemeral = self
            .ephemeral
            .take()
            .ok_or(Error::InvalidState("no server ECDHE key"))?;
        let premaster = ephemeral.agree(&cke.public_point)?;
        let session_hash = sha256(&self.transcript)?;
        let master = extended_master_secret(&premaster, &session_hash)?;
        let client_random = self
            .client_random
            .ok_or(Error::InvalidState("no client random before ClientKeyExchange"))?;
        self.keys = Some(derive_keys(master.as_slice(), &self.local_random, &client_random)?);
        self.master_secret = Some(master);
        self.state = State::Server(ServerPhase::WaitCertificateVerify);
        Ok(())
    }

    fn server_certificate_verify(&mut self, seq: u16, body: &[u8]) -> Result<()> {
        let cv = CertificateVerify::decode(body)?;
        let peer_key = self
            .peer_public_key
            .as_ref()
            .ok_or(Error::InvalidState("no client certificate before CertificateVerify"))?;
        let leaf = self
            .peer_cert_der
            .as_ref()
            .ok_or(Error::InvalidState("no client certificate before CertificateVerify"))?;
        client::verify_certificate_verify(
            peer_key,
            leaf,
            &self.transcript,
            cv.signature_algorithm,
            &cv.signature,
        )?;
        self.append_transcript(msg_type::CERTIFICATE_VERIFY, seq, body);
        self.state = State::Server(ServerPhase::WaitChangeCipherSpec);
        Ok(())
    }

    fn server_finished(&mut self, seq: u16, body: &[u8]) -> Result<()> {
        let finished = Finished::decode(body)?;
        let master = self
            .master_secret
            .clone()
            .ok_or(Error::InvalidState("no master secret before Finished"))?;
        let expected = client_finished_verify_data(master.as_slice(), &self.transcript)?;
        if !constant_time_eq(&finished.verify_data, &expected) {
            return Err(Error::BadFinished);
        }
        self.append_transcript(msg_type::FINISHED, seq, body);

        self.last_flight.clear();
        let verify_data = server_finished_verify_data(master.as_slice(), &self.transcript)?;
        self.send_change_cipher_spec()?;
        let finished = Finished { verify_data }.encode();
        self.send_handshake(msg_type::FINISHED, &finished)?;

        self.state = State::Server(ServerPhase::Done);
        self.timer.disarm();
        self.reasm.clear();
        Ok(())
    }
}

fn parse_fragments(plain: &[u8]) -> Result<Vec<(HandshakeHeader, &[u8])>> {
    let mut fragments = Vec::new();
    let mut rest = plain;
    while !rest.is_empty() {
        let header = HandshakeHeader::decode(rest)?;
        let end = HANDSHAKE_HEADER_LEN + header.fragment_length as usize;
        let body = rest
            .get(HANDSHAKE_HEADER_LEN..end)
            .ok_or(Error::Truncated("handshake fragment body"))?;
        fragments.push((header, body));
        rest = &rest[end..];
    }
    if fragments.is_empty() {
        return Err(Error::Decode("empty handshake record".to_owned()));
    }
    Ok(fragments)
}

fn process_alert(level: u8, description: u8) -> Result<()> {
    if level == ALERT_FATAL || description == CLOSE_NOTIFY {
        Err(Error::Alert { level, description })
    } else {
        Ok(())
    }
}

fn alert_description(error: &Error) -> Option<u8> {
    match error {
        Error::Alert { .. } | Error::Timeout | Error::InvalidArgument(_) => None,
        Error::UnexpectedMessage(_) => Some(10),
        Error::BadRecordMac => Some(20),
        Error::Negotiation(_) => Some(40),
        Error::FingerprintMismatch => Some(42),
        Error::Truncated(_) | Error::Decode(_) => Some(50),
        Error::BadFinished | Error::BadSignature => Some(51),
        Error::InvalidState(_) | Error::Crypto(_) | Error::Security(_) => Some(80),
    }
}
