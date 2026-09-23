//! The sans-I/O DTLS [`Connection`] state machine.
//!
//! A `Connection` owns no sockets and spawns no threads. The caller drives it:
//! bytes received from the network go in via [`Connection::feed_recv`], bytes to
//! transmit come out via [`Connection::poll_send`], and timeouts are serviced
//! with [`Connection::handle_timeout`]. This is exactly the shape WebRTC needs,
//! where the same UDP socket is shared with STUN and SRTP and demultiplexed by
//! the application.

use crate::cert::fingerprint::sha256_fingerprint;
use crate::cert::parse::parse_leaf_public_key;
use crate::cert::{generate, SelfSignedCertificate};
use crate::config::{Config, SrtpProfile};
use crate::crypto::ecdhe_p256::EcdheKeyPair;
use crate::crypto::hash::sha256;
use crate::error::{Error, Result};
use crate::crypto::constant_time_eq;
use crate::exporter::{export_keying_material, ExportedKeyingMaterial};
use crate::extensions::{find, use_srtp};
use crate::handshake::client::{self, ClientPhase};
use crate::handshake::keyschedule::{
    client_finished_verify_data, derive_keys, extended_master_secret, server_finished_verify_data,
    KeyMaterial,
};
use crate::handshake::messages::{
    msg_type, Certificate, CertificateVerify, ClientHello, ClientKeyExchange, Finished,
    HandshakeHeader, HelloVerifyRequest, ServerHello, ServerKeyExchange, HANDSHAKE_HEADER_LEN,
};
use crate::handshake::server::{self, ServerPhase};
use crate::handshake::{frame_message, CookieSecret, Reassembler};
use crate::extensions::signature_algorithms::ECDSA_SECP256R1_SHA256;
use crate::record::ciphertext::{self, AeadKeys};
use crate::record::plaintext::HEADER_LEN;
use crate::record::{content_type, EpochSeq, Record, DTLS_1_2};
use crate::role::Role;
use zeroize::Zeroizing;

/// A peer identity bound into the stateless cookie. For the in-process loopback
/// profile both endpoints use the same constant; a server fronting many peers
/// would substitute the remote transport address.
const PEER_ID: &[u8] = b"dtls-rs-loopback-peer";

/// A DTLS 1.2 connection endpoint.
pub struct Connection {
    config: Config,
    role: Role,

    local_cert: SelfSignedCertificate,
    local_fingerprint: [u8; 32],
    local_random: [u8; 32],
    client_random: Option<[u8; 32]>,
    server_random: Option<[u8; 32]>,

    cookie_secret: CookieSecret,
    ephemeral: Option<EcdheKeyPair>,
    peer_eph_point: Option<Vec<u8>>,
    peer_cert_der: Option<Vec<u8>>,
    peer_public_key: Option<crate::cert::parse::PeerPublicKey>,
    peer_fingerprint: Option<[u8; 32]>,

    cipher_suite: Option<u16>,
    srtp_code: Option<u16>,

    transcript: Vec<u8>,
    master_secret: Option<Zeroizing<[u8; 48]>>,
    keys: Option<KeyMaterial>,

    write_epoch: u16,
    epoch0_seq: EpochSeq,
    epoch1_seq: EpochSeq,
    peer_epoch: u16,
    reasm: Reassembler,

    outgoing: Vec<u8>,
    last_flight: crate::handshake::flight::Flight,
    timer: crate::timer::RetransmitTimer,

    done: bool,
    client_phase: ClientPhase,
    server_phase: ServerPhase,
}

impl Connection {
    /// Create a new connection. A client immediately queues its first
    /// `ClientHello`, retrievable via [`Connection::poll_send`].
    ///
    /// # Errors
    ///
    /// Returns an error if certificate generation or RNG access fails.
    pub fn new(config: Config) -> Result<Self> {
        let local_cert = generate()?;
        let local_fingerprint = sha256_fingerprint(&local_cert.der)?;
        let mut local_random = [0u8; 32];
        crate::crypto::fill_random(&mut local_random)?;
        let cookie_secret = CookieSecret::generate()?;
        let role = config.role;

        let mut conn = Self {
            config,
            role,
            local_cert,
            local_fingerprint,
            local_random,
            client_random: None,
            server_random: None,
            cookie_secret,
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
            write_epoch: 0,
            epoch0_seq: EpochSeq::new(),
            epoch1_seq: EpochSeq::new(),
            peer_epoch: 0,
            reasm: Reassembler::new(),
            outgoing: Vec::new(),
            last_flight: crate::handshake::flight::Flight::new(),
            timer: crate::timer::RetransmitTimer::new(),
            done: false,
            client_phase: ClientPhase::Start,
            server_phase: ServerPhase::WaitClientHello,
        };

        match role {
            Role::Client => {
                conn.client_random = Some(local_random);
                conn.start_client();
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

    /// The SHA-256 fingerprint of the peer's certificate, once received.
    #[must_use]
    pub fn peer_fingerprint(&self) -> Option<[u8; 32]> {
        self.peer_fingerprint
    }

    /// Whether the handshake has completed successfully.
    #[must_use]
    pub fn is_handshake_done(&self) -> bool {
        self.done
    }

    /// The negotiated SRTP profile, if any.
    #[must_use]
    pub fn selected_srtp_profile(&self) -> Option<SrtpProfile> {
        self.srtp_code.and_then(SrtpProfile::from_code)
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
    /// Returns [`Error::InvalidState`] if called before the handshake derives a
    /// master secret.
    pub fn export_keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        length: usize,
    ) -> Result<ExportedKeyingMaterial> {
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
    /// Currently infallible, but returns `Result` for forward compatibility.
    pub fn handle_timeout(&mut self, now_ms: u64) -> Result<()> {
        if self.timer.on_check(now_ms) {
            self.outgoing.extend_from_slice(&self.last_flight.to_datagram());
        }
        Ok(())
    }

    /// Feed a received datagram (which may contain several records).
    ///
    /// # Errors
    ///
    /// Returns an error on malformed records or handshake failures.
    pub fn feed_recv(&mut self, datagram: &[u8], now_ms: u64) -> Result<()> {
        let mut pos = 0;
        while datagram.len() - pos >= HEADER_LEN {
            let (record, consumed) = Record::decode(&datagram[pos..])?;
            pos += consumed;
            self.process_record(&record, now_ms)?;
        }
        Ok(())
    }

    fn start_client(&mut self) {
        self.last_flight.clear();
        let srtp_codes: Vec<u16> = self.config.srtp_profiles.iter().map(|p| p.code()).collect();
        let body = client::build_client_hello(self.local_random, &[], &srtp_codes);
        // cookieless ClientHello is excluded from the transcript
        self.send_handshake(msg_type::CLIENT_HELLO, 0, &body, false)
            .expect("epoch 0 send is infallible");
        self.client_phase = ClientPhase::WaitHelloVerify;
        self.timer.arm(0);
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

    fn send_record(&mut self, content_type: u8, plaintext: Vec<u8>) -> Result<()> {
        let epoch = self.write_epoch;
        let sequence = if epoch == 0 {
            self.epoch0_seq.take()
        } else {
            self.epoch1_seq.take()
        };
        let fragment = if epoch == 0 {
            plaintext
        } else {
            let keys = self
                .my_write_keys()
                .ok_or(Error::InvalidState("no write keys for epoch 1"))?;
            ciphertext::protect(keys, epoch, sequence, content_type, DTLS_1_2, &plaintext)?
        };
        let encoded = Record::new(content_type, epoch, sequence, fragment).encode();
        self.outgoing.extend_from_slice(&encoded);
        self.last_flight.push(encoded);
        Ok(())
    }

    fn send_handshake(
        &mut self,
        msg_type: u8,
        message_seq: u16,
        body: &[u8],
        include_in_transcript: bool,
    ) -> Result<()> {
        let framed = frame_message(msg_type, message_seq, body);
        if include_in_transcript {
            self.transcript.extend_from_slice(&framed);
        }
        self.send_record(content_type::HANDSHAKE, framed)
    }

    fn send_change_cipher_spec(&mut self) -> Result<()> {
        self.send_record(content_type::CHANGE_CIPHER_SPEC, vec![1])?;
        self.write_epoch = 1;
        Ok(())
    }

    fn append_transcript(&mut self, msg_type: u8, message_seq: u16, body: &[u8]) {
        let framed = frame_message(msg_type, message_seq, body);
        self.transcript.extend_from_slice(&framed);
    }

    fn process_record(&mut self, record: &Record, now_ms: u64) -> Result<()> {
        match record.content_type {
            content_type::HANDSHAKE => {
                let plain = if record.epoch == 0 {
                    record.fragment.clone()
                } else {
                    let keys = self
                        .peer_write_keys()
                        .ok_or(Error::InvalidState("no read keys for epoch 1"))?;
                    ciphertext::unprotect(
                        keys,
                        record.epoch,
                        record.sequence,
                        content_type::HANDSHAKE,
                        DTLS_1_2,
                        &record.fragment,
                    )?
                };
                let header = HandshakeHeader::decode(&plain)?;
                let end = HANDSHAKE_HEADER_LEN + header.fragment_length as usize;
                let body = plain
                    .get(HANDSHAKE_HEADER_LEN..end)
                    .ok_or(Error::Truncated("handshake fragment body"))?
                    .to_vec();
                let delivered = self.reasm.feed(&header, &body)?;
                for (mtype, seq, mbody) in delivered {
                    self.on_handshake(mtype, seq, &mbody, now_ms)?;
                }
            }
            content_type::CHANGE_CIPHER_SPEC => {
                self.peer_epoch = 1;
            }
            content_type::ALERT => {
                let level = record.fragment.first().copied().unwrap_or(2);
                return Err(Error::Alert(level));
            }
            // Application data and any unknown content type are ignored here;
            // the handshake layer never expects them.
            _ => {}
        }
        Ok(())
    }

    fn on_handshake(&mut self, mtype: u8, seq: u16, body: &[u8], now_ms: u64) -> Result<()> {
        match self.role {
            Role::Client => self.on_handshake_client(mtype, seq, body, now_ms),
            Role::Server => self.on_handshake_server(mtype, seq, body, now_ms),
        }
    }

    fn on_handshake_client(
        &mut self,
        mtype: u8,
        seq: u16,
        body: &[u8],
        now_ms: u64,
    ) -> Result<()> {
        match self.client_phase {
            ClientPhase::WaitHelloVerify if mtype == msg_type::HELLO_VERIFY_REQUEST => {
                let hvr = HelloVerifyRequest::decode(body)?;
                self.last_flight.clear();
                let srtp_codes: Vec<u16> =
                    self.config.srtp_profiles.iter().map(|p| p.code()).collect();
                let ch = client::build_client_hello(self.local_random, &hvr.cookie, &srtp_codes);
                self.send_handshake(msg_type::CLIENT_HELLO, 1, &ch, true)?;
                self.client_phase = ClientPhase::WaitServerFlight;
                self.timer.arm(now_ms);
                Ok(())
            }
            ClientPhase::WaitServerFlight => self.client_server_flight(mtype, seq, body, now_ms),
            ClientPhase::WaitServerFinished if mtype == msg_type::FINISHED => {
                let master = self
                    .master_secret
                    .as_ref()
                    .ok_or(Error::InvalidState("no master secret before Finished"))?;
                let expected = server_finished_verify_data(master.as_slice(), &self.transcript)?;
                if !constant_time_eq(body, &expected) {
                    return Err(Error::BadFinished);
                }
                self.append_transcript(msg_type::FINISHED, seq, body);
                self.done = true;
                self.client_phase = ClientPhase::Done;
                self.timer.disarm();
                Ok(())
            }
            _ => Err(Error::UnexpectedMessage(format!(
                "client got handshake type {mtype} in phase {:?}",
                self.client_phase
            ))),
        }
    }

    fn client_server_flight(
        &mut self,
        mtype: u8,
        _seq: u16,
        body: &[u8],
        now_ms: u64,
    ) -> Result<()> {
        match mtype {
            msg_type::SERVER_HELLO => {
                self.append_transcript(mtype, 1, body);
                let sh = ServerHello::decode(body)?;
                self.server_random = Some(sh.random);
                self.cipher_suite = Some(sh.cipher_suite);
                self.srtp_code = client::selected_srtp(&sh.extensions);
                Ok(())
            }
            msg_type::CERTIFICATE => {
                self.append_transcript(mtype, 2, body);
                let certificate = Certificate::decode(body)?;
                let leaf = certificate
                    .certificates
                    .into_iter()
                    .next()
                    .ok_or(Error::Decode("empty certificate list".to_owned()))?;
                let fingerprint = sha256_fingerprint(&leaf)?;
                if let Some(expected) = self.config.expected_peer_fingerprint {
                    if expected != fingerprint {
                        return Err(Error::FingerprintMismatch);
                    }
                }
                self.peer_public_key = Some(parse_leaf_public_key(&leaf)?);
                self.peer_fingerprint = Some(fingerprint);
                self.peer_cert_der = Some(leaf);
                Ok(())
            }
            msg_type::SERVER_KEY_EXCHANGE => {
                self.append_transcript(mtype, 3, body);
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
                client::verify_server_key_exchange(
                    peer_key,
                    leaf,
                    &client_random,
                    &server_random,
                    &ske,
                )?;
                self.peer_eph_point = Some(ske.public_point);
                Ok(())
            }
            msg_type::CERTIFICATE_REQUEST => {
                self.append_transcript(mtype, 4, body);
                Ok(())
            }
            msg_type::SERVER_HELLO_DONE => {
                self.append_transcript(mtype, 5, body);
                self.finish_client_flight(now_ms)
            }
            _ => Err(Error::UnexpectedMessage(format!(
                "client got handshake type {mtype} during server flight"
            ))),
        }
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

        // Client Certificate (message_seq 2) for mutual authentication.
        let cert = server::build_certificate(self.local_cert.der.clone());
        self.send_handshake(msg_type::CERTIFICATE, 2, &cert, true)?;

        // ClientKeyExchange (message_seq 3).
        let cke = client::build_client_key_exchange(client_point);
        self.send_handshake(msg_type::CLIENT_KEY_EXCHANGE, 3, &cke, true)?;

        // The extended master secret is derived over the transcript through
        // ClientKeyExchange (RFC 7627).
        let session_hash = sha256(&self.transcript)?;
        let master = extended_master_secret(&premaster, &session_hash)?;
        self.keys = Some(derive_keys(master.as_slice(), &server_random, &client_random)?);

        // CertificateVerify (message_seq 4): sign the transcript so far
        // (ClientHello..ClientKeyExchange) with our certificate's private key.
        let signature = self.local_cert.key.sign_der(&self.transcript)?;
        let cert_verify = CertificateVerify {
            signature_algorithm: ECDSA_SECP256R1_SHA256,
            signature,
        }
        .encode();
        self.send_handshake(msg_type::CERTIFICATE_VERIFY, 4, &cert_verify, true)?;

        // Finished (message_seq 5) over the transcript through CertificateVerify.
        let verify_data = client_finished_verify_data(master.as_slice(), &self.transcript)?;
        self.master_secret = Some(master);
        self.send_change_cipher_spec()?;
        let finished = Finished { verify_data }.encode();
        self.send_handshake(msg_type::FINISHED, 5, &finished, true)?;

        self.client_phase = ClientPhase::WaitServerFinished;
        self.timer.arm(now_ms);
        Ok(())
    }

    fn on_handshake_server(
        &mut self,
        mtype: u8,
        seq: u16,
        body: &[u8],
        now_ms: u64,
    ) -> Result<()> {
        match self.server_phase {
            ServerPhase::WaitClientHello if mtype == msg_type::CLIENT_HELLO => {
                let ch = ClientHello::decode(body)?;
                self.last_flight.clear();
                let cookie = self.cookie_secret.compute(PEER_ID, &ch.random)?;
                let hvr = server::build_hello_verify_request(cookie);
                self.send_handshake(msg_type::HELLO_VERIFY_REQUEST, 0, &hvr, false)?;
                self.server_phase = ServerPhase::WaitClientHelloWithCookie;
                self.timer.arm(now_ms);
                Ok(())
            }
            ServerPhase::WaitClientHelloWithCookie if mtype == msg_type::CLIENT_HELLO => {
                let ch = ClientHello::decode(body)?;
                if !self
                    .cookie_secret
                    .verify(PEER_ID, &ch.random, &ch.cookie)?
                {
                    return Err(Error::UnexpectedMessage("invalid DTLS cookie".to_owned()));
                }
                self.append_transcript(msg_type::CLIENT_HELLO, seq, body);
                self.client_random = Some(ch.random);

                let cipher_suite = server::negotiate_cipher_suite(&ch.cipher_suites)
                    .ok_or(Error::Negotiation("cipher suite"))?;
                self.cipher_suite = Some(cipher_suite);

                let offered = find(&ch.extensions, crate::extensions::ext_type::USE_SRTP)
                    .map(|ext| use_srtp::parse_profiles(&ext.data))
                    .transpose()?
                    .unwrap_or_default();
                let preferred: Vec<u16> =
                    self.config.srtp_profiles.iter().map(|p| p.code()).collect();
                self.srtp_code = server::negotiate_srtp(&offered, &preferred);

                self.send_server_flight(cipher_suite, now_ms)
            }
            ServerPhase::WaitClientFinished => self.server_client_finish(mtype, seq, body),
            _ => Err(Error::UnexpectedMessage(format!(
                "server got handshake type {mtype} in phase {:?}",
                self.server_phase
            ))),
        }
    }

    fn send_server_flight(&mut self, cipher_suite: u16, now_ms: u64) -> Result<()> {
        self.last_flight.clear();
        let server_random = self.local_random;
        let client_random = self.client_random.expect("client random set");

        let sh = server::build_server_hello(server_random, cipher_suite, self.srtp_code);
        self.send_handshake(msg_type::SERVER_HELLO, 1, &sh, true)?;

        let cert = server::build_certificate(self.local_cert.der.clone());
        self.send_handshake(msg_type::CERTIFICATE, 2, &cert, true)?;

        let ephemeral = EcdheKeyPair::generate()?;
        let point = ephemeral.public_point().to_vec();
        let ske = server::build_server_key_exchange(
            &self.local_cert.key,
            &client_random,
            &server_random,
            point,
        )?;
        self.ephemeral = Some(ephemeral);
        self.send_handshake(msg_type::SERVER_KEY_EXCHANGE, 3, &ske, true)?;

        // CertificateRequest (message_seq 4) — WebRTC requires mutual auth.
        let cert_req = server::build_certificate_request();
        self.send_handshake(msg_type::CERTIFICATE_REQUEST, 4, &cert_req, true)?;

        self.send_handshake(msg_type::SERVER_HELLO_DONE, 5, &[], true)?;

        self.server_phase = ServerPhase::WaitClientFinished;
        self.timer.arm(now_ms);
        Ok(())
    }

    fn server_client_finish(&mut self, mtype: u8, seq: u16, body: &[u8]) -> Result<()> {
        match mtype {
            msg_type::CERTIFICATE => {
                self.append_transcript(mtype, seq, body);
                let certificate = Certificate::decode(body)?;
                let leaf = certificate
                    .certificates
                    .into_iter()
                    .next()
                    .ok_or(Error::Decode("empty client certificate list".to_owned()))?;
                let fingerprint = sha256_fingerprint(&leaf)?;
                if let Some(expected) = self.config.expected_peer_fingerprint {
                    if expected != fingerprint {
                        return Err(Error::FingerprintMismatch);
                    }
                }
                self.peer_public_key = Some(parse_leaf_public_key(&leaf)?);
                self.peer_fingerprint = Some(fingerprint);
                self.peer_cert_der = Some(leaf);
                Ok(())
            }
            msg_type::CLIENT_KEY_EXCHANGE => {
                self.append_transcript(mtype, seq, body);
                let cke = ClientKeyExchange::decode(body)?;
                let ephemeral = self
                    .ephemeral
                    .take()
                    .ok_or(Error::InvalidState("no server ECDHE key"))?;
                let premaster = ephemeral.agree(&cke.public_point)?;
                let session_hash = sha256(&self.transcript)?;
                let master = extended_master_secret(&premaster, &session_hash)?;
                let server_random = self.local_random;
                let client_random = self
                    .client_random
                    .ok_or(Error::InvalidState("no client random before ClientKeyExchange"))?;
                self.keys = Some(derive_keys(master.as_slice(), &server_random, &client_random)?);
                self.master_secret = Some(master);
                Ok(())
            }
            msg_type::CERTIFICATE_VERIFY => {
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
                self.append_transcript(mtype, seq, body);
                Ok(())
            }
            msg_type::FINISHED => {
                let master = self
                    .master_secret
                    .clone()
                    .ok_or(Error::InvalidState("no master secret before Finished"))?;
                let expected = client_finished_verify_data(master.as_slice(), &self.transcript)?;
                if !constant_time_eq(body, &expected) {
                    return Err(Error::BadFinished);
                }
                self.append_transcript(msg_type::FINISHED, seq, body);

                self.last_flight.clear();
                let verify_data = server_finished_verify_data(master.as_slice(), &self.transcript)?;
                self.send_change_cipher_spec()?;
                let finished = Finished { verify_data }.encode();
                self.send_handshake(msg_type::FINISHED, 6, &finished, true)?;

                self.done = true;
                self.server_phase = ServerPhase::Done;
                self.timer.disarm();
                Ok(())
            }
            _ => Err(Error::UnexpectedMessage(format!(
                "server got handshake type {mtype} awaiting client Finished"
            ))),
        }
    }
}
