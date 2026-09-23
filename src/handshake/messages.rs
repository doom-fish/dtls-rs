//! Handshake message structures and their DTLS wire codecs.
//!
//! Each handshake message body is encoded/decoded here; the 12-byte DTLS
//! handshake header (`msg_type, length, message_seq, fragment_offset,
//! fragment_length`) is handled by [`HandshakeHeader`]. For transcript hashing
//! the message is always reconstructed as a single unfragmented record
//! (`fragment_offset = 0`, `fragment_length = length`).

use crate::error::{Error, Result};
use crate::extensions::{decode_block, encode_block, Extension};
use crate::handshake::keyschedule::VERIFY_DATA_LEN;
use crate::record::DTLS_1_2;

/// Handshake message type code points.
pub mod msg_type {
    /// `client_hello(1)`.
    pub const CLIENT_HELLO: u8 = 1;
    /// `server_hello(2)`.
    pub const SERVER_HELLO: u8 = 2;
    /// `hello_verify_request(3)`.
    pub const HELLO_VERIFY_REQUEST: u8 = 3;
    /// `certificate(11)`.
    pub const CERTIFICATE: u8 = 11;
    /// `server_key_exchange(12)`.
    pub const SERVER_KEY_EXCHANGE: u8 = 12;
    /// `certificate_request(13)`.
    pub const CERTIFICATE_REQUEST: u8 = 13;
    /// `server_hello_done(14)`.
    pub const SERVER_HELLO_DONE: u8 = 14;
    /// `certificate_verify(15)`.
    pub const CERTIFICATE_VERIFY: u8 = 15;
    /// `client_key_exchange(16)`.
    pub const CLIENT_KEY_EXCHANGE: u8 = 16;
    /// `finished(20)`.
    pub const FINISHED: u8 = 20;
}

/// Length of the DTLS handshake header in bytes.
pub const HANDSHAKE_HEADER_LEN: usize = 12;

/// A parsed DTLS handshake header.
#[derive(Debug, Clone, Copy)]
pub struct HandshakeHeader {
    /// Handshake message type.
    pub msg_type: u8,
    /// Total length of the reassembled message body.
    pub length: u32,
    /// Per-sender message sequence number.
    pub message_seq: u16,
    /// Offset of this fragment within the body.
    pub fragment_offset: u32,
    /// Length of this fragment.
    pub fragment_length: u32,
}

impl HandshakeHeader {
    /// Decode a handshake header from the front of `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if fewer than 12 bytes are available.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HANDSHAKE_HEADER_LEN {
            return Err(Error::Truncated("handshake header"));
        }
        Ok(Self {
            msg_type: buf[0],
            length: u24(&buf[1..4]),
            message_seq: u16::from_be_bytes([buf[4], buf[5]]),
            fragment_offset: u24(&buf[6..9]),
            fragment_length: u24(&buf[9..12]),
        })
    }

    /// Encode the header into 12 bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; HANDSHAKE_HEADER_LEN] {
        let mut out = [0u8; HANDSHAKE_HEADER_LEN];
        out[0] = self.msg_type;
        out[1..4].copy_from_slice(&u24_bytes(self.length));
        out[4..6].copy_from_slice(&self.message_seq.to_be_bytes());
        out[6..9].copy_from_slice(&u24_bytes(self.fragment_offset));
        out[9..12].copy_from_slice(&u24_bytes(self.fragment_length));
        out
    }
}

/// Build the canonical unfragmented framed handshake message (header + body)
/// used both on the wire (when it fits one record) and for the transcript hash.
#[must_use]
pub fn frame(msg_type: u8, message_seq: u16, body: &[u8]) -> Vec<u8> {
    let header = HandshakeHeader {
        msg_type,
        length: body.len() as u32,
        message_seq,
        fragment_offset: 0,
        fragment_length: body.len() as u32,
    };
    let mut out = Vec::with_capacity(HANDSHAKE_HEADER_LEN + body.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(body);
    out
}

fn u24(bytes: &[u8]) -> u32 {
    (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2])
}

fn u24_bytes(value: u32) -> [u8; 3] {
    [(value >> 16) as u8, (value >> 8) as u8, value as u8]
}

/// A minimal forward cursor over a byte slice.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8]> {
        let slice = self
            .buf
            .get(self.pos..self.pos + n)
            .ok_or(Error::Truncated(what))?;
        self.pos += n;
        Ok(slice)
    }

    fn u8(&mut self, what: &'static str) -> Result<u8> {
        Ok(self.take(1, what)?[0])
    }

    fn u16(&mut self, what: &'static str) -> Result<u16> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self, what: &'static str) -> Result<u32> {
        let b = self.take(3, what)?;
        Ok(u24(b))
    }

    fn finish(&self, what: &'static str) -> Result<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Error::Decode(format!("trailing bytes after {what}")))
        }
    }

    /// Read a vector whose length prefix is `len_bytes` wide.
    fn vector(&mut self, len_bytes: usize, what: &'static str) -> Result<&'a [u8]> {
        let len = match len_bytes {
            1 => usize::from(self.u8(what)?),
            2 => usize::from(self.u16(what)?),
            3 => self.u24(what)? as usize,
            _ => unreachable!("unsupported vector length width"),
        };
        self.take(len, what)
    }
}

/// `ClientHello` handshake message.
#[derive(Debug, Clone)]
pub struct ClientHello {
    #[allow(missing_docs)]
    pub version: u16,
    /// 32-byte client random.
    pub random: [u8; 32],
    /// Session id (empty for a fresh handshake).
    pub session_id: Vec<u8>,
    /// DTLS cookie (empty in the first flight).
    pub cookie: Vec<u8>,
    /// Offered cipher suites.
    pub cipher_suites: Vec<u16>,
    /// Offered compression methods (always `[0]`).
    pub compression_methods: Vec<u8>,
    /// Hello extensions.
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    /// Encode the message body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.random);
        out.push(self.session_id.len() as u8);
        out.extend_from_slice(&self.session_id);
        out.push(self.cookie.len() as u8);
        out.extend_from_slice(&self.cookie);
        out.extend_from_slice(&((self.cipher_suites.len() * 2) as u16).to_be_bytes());
        for suite in &self.cipher_suites {
            out.extend_from_slice(&suite.to_be_bytes());
        }
        out.push(self.compression_methods.len() as u8);
        out.extend_from_slice(&self.compression_methods);
        out.extend_from_slice(&encode_block(&self.extensions));
        out
    }

    /// Decode the message body.
    ///
    /// # Errors
    ///
    /// Returns an error on truncated or malformed input.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(body);
        let version = c.u16("client_hello version")?;
        let random_slice = c.take(32, "client_hello random")?;
        let mut random = [0u8; 32];
        random.copy_from_slice(random_slice);
        let session_id = c.vector(1, "session_id")?.to_vec();
        let cookie = c.vector(1, "cookie")?.to_vec();
        let suites_raw = c.vector(2, "cipher_suites")?;
        if suites_raw.len() % 2 != 0 {
            return Err(Error::Decode("odd cipher_suites length".to_owned()));
        }
        let cipher_suites = suites_raw
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();
        let compression_methods = c.vector(1, "compression_methods")?.to_vec();
        let extensions = decode_block(c.take(c.remaining(), "extensions")?)?;
        Ok(Self {
            version,
            random,
            session_id,
            cookie,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }
}

/// `HelloVerifyRequest` handshake message.
#[derive(Debug, Clone)]
pub struct HelloVerifyRequest {
    /// Stateless cookie the client must echo.
    pub cookie: Vec<u8>,
}

impl HelloVerifyRequest {
    /// Encode the message body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.cookie.len());
        out.extend_from_slice(&DTLS_1_2.to_be_bytes());
        out.push(self.cookie.len() as u8);
        out.extend_from_slice(&self.cookie);
        out
    }

    /// Decode the message body.
    ///
    /// # Errors
    ///
    /// Returns an error on truncated input.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(body);
        let _version = c.u16("hvr version")?;
        let cookie = c.vector(1, "hvr cookie")?.to_vec();
        c.finish("hello_verify_request")?;
        Ok(Self { cookie })
    }
}

/// `ServerHello` handshake message.
#[derive(Debug, Clone)]
pub struct ServerHello {
    #[allow(missing_docs)]
    pub version: u16,
    /// 32-byte server random.
    pub random: [u8; 32],
    /// Session id (empty).
    pub session_id: Vec<u8>,
    /// Selected cipher suite.
    pub cipher_suite: u16,
    /// Selected compression method (always 0).
    pub compression_method: u8,
    /// Server extensions.
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    /// Encode the message body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.random);
        out.push(self.session_id.len() as u8);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.cipher_suite.to_be_bytes());
        out.push(self.compression_method);
        out.extend_from_slice(&encode_block(&self.extensions));
        out
    }

    /// Decode the message body.
    ///
    /// # Errors
    ///
    /// Returns an error on truncated or malformed input.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(body);
        let version = c.u16("server_hello version")?;
        let random_slice = c.take(32, "server_hello random")?;
        let mut random = [0u8; 32];
        random.copy_from_slice(random_slice);
        let session_id = c.vector(1, "session_id")?.to_vec();
        let cipher_suite = c.u16("cipher_suite")?;
        let compression_method = c.u8("compression_method")?;
        let extensions = decode_block(c.take(c.remaining(), "extensions")?)?;
        Ok(Self {
            version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        })
    }
}

/// `Certificate` handshake message (a list of DER certificates).
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The certificate chain, leaf first, each DER-encoded.
    pub certificates: Vec<Vec<u8>>,
}

impl Certificate {
    /// Encode the message body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut list = Vec::new();
        for cert in &self.certificates {
            list.extend_from_slice(&u24_bytes(cert.len() as u32));
            list.extend_from_slice(cert);
        }
        let mut out = Vec::with_capacity(3 + list.len());
        out.extend_from_slice(&u24_bytes(list.len() as u32));
        out.extend_from_slice(&list);
        out
    }

    /// Decode the message body.
    ///
    /// # Errors
    ///
    /// Returns an error on truncated or malformed input.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(body);
        let list = c.vector(3, "certificate_list")?;
        c.finish("certificate_list")?;
        let mut inner = Cursor::new(list);
        let mut certificates = Vec::new();
        while inner.remaining() > 0 {
            let certificate = inner.vector(3, "certificate")?;
            if certificate.is_empty() {
                return Err(Error::Decode("empty certificate entry".to_owned()));
            }
            certificates.push(certificate.to_vec());
        }
        Ok(Self { certificates })
    }
}

/// `ServerKeyExchange` for ECDHE (named curve) with a signature.
#[derive(Debug, Clone)]
pub struct ServerKeyExchange {
    /// Named curve code point (P-256 = `0x0017`).
    pub named_curve: u16,
    /// The server's ephemeral public point (`0x04 || X || Y`).
    pub public_point: Vec<u8>,
    /// The `SignatureAndHashAlgorithm` code point.
    pub signature_algorithm: u16,
    /// The signature over the ECDHE params.
    pub signature: Vec<u8>,
}

impl ServerKeyExchange {
    /// The signed portion: `client_random || server_random || ECParameters`.
    /// Here we encode only the `ECParameters` (`curve_type, named_curve,
    /// public`); the caller prepends the randoms.
    #[must_use]
    pub fn signed_params(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(3); // curve_type = named_curve
        out.extend_from_slice(&self.named_curve.to_be_bytes());
        out.push(self.public_point.len() as u8);
        out.extend_from_slice(&self.public_point);
        out
    }

    /// Encode the message body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.signed_params();
        out.extend_from_slice(&self.signature_algorithm.to_be_bytes());
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decode the message body.
    ///
    /// # Errors
    ///
    /// Returns an error on truncated or malformed input.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(body);
        let curve_type = c.u8("curve_type")?;
        if curve_type != 3 {
            return Err(Error::Negotiation("only named_curve ECParameters supported"));
        }
        let named_curve = c.u16("named_curve")?;
        let public_point = c.vector(1, "ecdh public")?.to_vec();
        let signature_algorithm = c.u16("signature_algorithm")?;
        let signature = c.vector(2, "signature")?.to_vec();
        c.finish("server_key_exchange")?;
        Ok(Self {
            named_curve,
            public_point,
            signature_algorithm,
            signature,
        })
    }
}

/// `ClientKeyExchange` for ECDHE (the client's ephemeral public point).
#[derive(Debug, Clone)]
pub struct ClientKeyExchange {
    /// The client's ephemeral public point (`0x04 || X || Y`).
    pub public_point: Vec<u8>,
}

impl ClientKeyExchange {
    /// Encode the message body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.public_point.len());
        out.push(self.public_point.len() as u8);
        out.extend_from_slice(&self.public_point);
        out
    }

    /// Decode the message body.
    ///
    /// # Errors
    ///
    /// Returns an error on truncated input.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(body);
        let public_point = c.vector(1, "ecdh Yc")?.to_vec();
        c.finish("client_key_exchange")?;
        Ok(Self { public_point })
    }
}

/// `CertificateVerify` handshake message.
#[derive(Debug, Clone)]
pub struct CertificateVerify {
    /// The `SignatureAndHashAlgorithm` code point.
    pub signature_algorithm: u16,
    /// The signature over the transcript.
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    /// Encode the message body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.signature.len());
        out.extend_from_slice(&self.signature_algorithm.to_be_bytes());
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decode the message body.
    ///
    /// # Errors
    ///
    /// Returns an error on truncated input.
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(body);
        let signature_algorithm = c.u16("signature_algorithm")?;
        let signature = c.vector(2, "signature")?.to_vec();
        c.finish("certificate_verify")?;
        Ok(Self {
            signature_algorithm,
            signature,
        })
    }
}

#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequest {
    pub certificate_types: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub certificate_authorities: Vec<u8>,
}

impl CertificateRequest {
    #[allow(missing_docs)]
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.certificate_types.len() as u8);
        out.extend_from_slice(&self.certificate_types);
        out.extend_from_slice(&((self.signature_algorithms.len() * 2) as u16).to_be_bytes());
        for algorithm in &self.signature_algorithms {
            out.extend_from_slice(&algorithm.to_be_bytes());
        }
        out.extend_from_slice(&(self.certificate_authorities.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.certificate_authorities);
        out
    }

    #[allow(missing_docs)]
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(body);
        let certificate_types = c.vector(1, "certificate_types")?.to_vec();
        let algorithms = c.vector(2, "supported_signature_algorithms")?;
        if algorithms.len() % 2 != 0 {
            return Err(Error::Decode("odd supported_signature_algorithms length".to_owned()));
        }
        let signature_algorithms = algorithms
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();
        let certificate_authorities = c.vector(2, "certificate_authorities")?.to_vec();
        c.finish("certificate_request")?;
        Ok(Self {
            certificate_types,
            signature_algorithms,
            certificate_authorities,
        })
    }
}

/// `Finished` handshake message.
#[derive(Debug, Clone)]
pub struct Finished {
    /// The 12-byte verify data.
    pub verify_data: Vec<u8>,
}

impl Finished {
    /// Encode the message body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.verify_data.clone()
    }

    /// Decode the message body.
    pub fn decode(body: &[u8]) -> Result<Self> {
        if body.len() != VERIFY_DATA_LEN {
            return Err(Error::Decode(format!(
                "Finished verify_data must be {VERIFY_DATA_LEN} bytes, got {}",
                body.len()
            )));
        }
        Ok(Self {
            verify_data: body.to_vec(),
        })
    }
}
