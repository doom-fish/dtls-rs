//! Client-role handshake phases and message builders.
//!
//! The mutation-heavy orchestration lives in [`crate::connection`]; this module
//! provides the client's phase enum plus pure helpers that construct outgoing
//! message bodies and validate the server's flight.

use crate::crypto::ecdsa_verify::verify_ecdsa_p256;
use crate::crypto::rsa_verify::{verify_rsa, RsaScheme};
use crate::cert::parse::PeerPublicKey;
use crate::error::{Error, Result};
use crate::extensions::{
    ec_point_formats, ext_type, extended_master_secret, find, renegotiation_info,
    signature_algorithms, supported_groups, use_srtp, Extension,
};
use crate::handshake::messages::{
    CertificateRequest, ClientHello, ClientKeyExchange, ServerHello, ServerKeyExchange,
};
use crate::handshake::{
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
};
use crate::record::DTLS_1_2;

const ECDSA_SIGN: u8 = 64;

/// Client handshake progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientPhase {
    /// About to send the initial cookieless `ClientHello`.
    Start,
    /// Awaiting `HelloVerifyRequest`.
    WaitHelloVerify,
    /// Awaiting the server's `ServerHello..ServerHelloDone` flight.
    WaitServerFlight,
    /// Awaiting the server's `ChangeCipherSpec` + `Finished`.
    WaitServerFinished,
    /// Handshake complete.
    Done,
}

/// Build the `ClientHello` body offering the WebRTC cipher suites and the SRTP
/// profiles encoded by `srtp_codes`.
#[must_use]
pub fn build_client_hello(random: [u8; 32], cookie: &[u8], srtp_codes: &[u16]) -> Vec<u8> {
    let mut extensions = vec![
        supported_groups::build(&[supported_groups::SECP256R1]),
        ec_point_formats::build(&[ec_point_formats::UNCOMPRESSED]),
        signature_algorithms::build(&[
            signature_algorithms::ECDSA_SECP256R1_SHA256,
            signature_algorithms::RSA_PSS_RSAE_SHA256,
            signature_algorithms::RSA_PKCS1_SHA256,
        ]),
    ];
    if !srtp_codes.is_empty() {
        extensions.push(use_srtp::build(srtp_codes));
    }
    extensions.push(extended_master_secret::build());
    extensions.push(renegotiation_info::build());
    ClientHello {
        version: DTLS_1_2,
        random,
        session_id: Vec::new(),
        cookie: cookie.to_vec(),
        cipher_suites: vec![
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ],
        compression_methods: vec![0],
        extensions,
    }
    .encode()
}

/// Build the `ClientKeyExchange` body carrying the client's ephemeral point.
#[must_use]
pub fn build_client_key_exchange(public_point: Vec<u8>) -> Vec<u8> {
    ClientKeyExchange { public_point }.encode()
}

/// Verify the server's `ServerKeyExchange` signature against its certificate's
/// public key.
///
/// The signed message is `client_random || server_random || ECParameters`.
///
/// # Errors
///
/// Returns [`Error::BadSignature`] on verification failure or
/// [`Error::Negotiation`] for an unsupported signature algorithm.
pub fn verify_server_key_exchange(
    peer_key: &PeerPublicKey,
    leaf_cert_der: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    cipher_suite: u16,
    ske: &ServerKeyExchange,
) -> Result<()> {
    if ske.named_curve != supported_groups::SECP256R1 {
        return Err(Error::Negotiation("ECDHE curve"));
    }
    let mut message = Vec::with_capacity(64 + ske.public_point.len() + 4);
    message.extend_from_slice(client_random);
    message.extend_from_slice(server_random);
    message.extend_from_slice(&ske.signed_params());

    match (peer_key, cipher_suite) {
        (PeerPublicKey::EcdsaP256 { point }, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) => {
            if ske.signature_algorithm != signature_algorithms::ECDSA_SECP256R1_SHA256 {
                return Err(Error::Negotiation("ServerKeyExchange signature algorithm"));
            }
            verify_ecdsa_p256(point, &message, &ske.signature)
        }
        (PeerPublicKey::Rsa, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) => {
            let scheme = rsa_scheme(ske.signature_algorithm)?;
            verify_rsa(leaf_cert_der, scheme, &message, &ske.signature)
        }
        _ => Err(Error::Negotiation("server certificate type for the cipher suite")),
    }
}

fn rsa_scheme(signature_algorithm: u16) -> Result<RsaScheme> {
    match signature_algorithm {
        signature_algorithms::RSA_PKCS1_SHA256 => Ok(RsaScheme::Pkcs1Sha256),
        signature_algorithms::RSA_PSS_RSAE_SHA256 => Ok(RsaScheme::PssSha256),
        _ => Err(Error::Negotiation("unsupported RSA signature algorithm")),
    }
}

/// Verify a peer's `CertificateVerify` signature, computed over the handshake
/// transcript (`ClientHello` through `ClientKeyExchange`).
///
/// # Errors
///
/// Returns [`Error::BadSignature`] on verification failure or
/// [`Error::Negotiation`] for an unsupported signature algorithm.
pub fn verify_certificate_verify(
    peer_key: &PeerPublicKey,
    leaf_cert_der: &[u8],
    transcript: &[u8],
    signature_algorithm: u16,
    signature: &[u8],
) -> Result<()> {
    match peer_key {
        PeerPublicKey::EcdsaP256 { point } => {
            if signature_algorithm != signature_algorithms::ECDSA_SECP256R1_SHA256 {
                return Err(Error::Negotiation("CertificateVerify signature algorithm"));
            }
            verify_ecdsa_p256(point, transcript, signature)
        }
        PeerPublicKey::Rsa => {
            let scheme = rsa_scheme(signature_algorithm)?;
            verify_rsa(leaf_cert_der, scheme, transcript, signature)
        }
    }
}

#[allow(missing_docs)]
pub fn check_server_hello(server_hello: &ServerHello, offered_srtp: &[u16]) -> Result<Option<u16>> {
    if server_hello.version != DTLS_1_2 {
        return Err(Error::Negotiation("protocol version"));
    }
    if server_hello.compression_method != 0 {
        return Err(Error::Negotiation("compression method"));
    }
    if server_hello.cipher_suite != TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        && server_hello.cipher_suite != TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    {
        return Err(Error::Negotiation("cipher suite"));
    }
    for extension in &server_hello.extensions {
        let offered = match extension.extension_type {
            ext_type::USE_SRTP => !offered_srtp.is_empty(),
            ext_type::SUPPORTED_GROUPS
            | ext_type::EC_POINT_FORMATS
            | ext_type::SIGNATURE_ALGORITHMS
            | ext_type::EXTENDED_MASTER_SECRET
            | ext_type::RENEGOTIATION_INFO => true,
            _ => false,
        };
        if !offered {
            return Err(Error::UnexpectedMessage(format!(
                "ServerHello carries unsolicited extension {}",
                extension.extension_type
            )));
        }
    }
    let ems = find(&server_hello.extensions, ext_type::EXTENDED_MASTER_SECRET)
        .ok_or(Error::Negotiation("extended_master_secret support"))?;
    if !ems.data.is_empty() {
        return Err(Error::Decode("extended_master_secret carries data".to_owned()));
    }
    check_initial_renegotiation_info(&server_hello.extensions)?;
    if let Some(formats) = find(&server_hello.extensions, ext_type::EC_POINT_FORMATS) {
        if !ec_point_formats::parse(&formats.data)?.contains(&ec_point_formats::UNCOMPRESSED) {
            return Err(Error::Negotiation("EC point format"));
        }
    }
    let Some(srtp) = find(&server_hello.extensions, ext_type::USE_SRTP) else {
        return Ok(None);
    };
    let selected = use_srtp::parse(&srtp.data)?;
    match selected.profiles.as_slice() {
        [profile] if offered_srtp.contains(profile) && selected.mki.is_empty() => Ok(Some(*profile)),
        [_] if !selected.mki.is_empty() => Err(Error::UnexpectedMessage(
            "ServerHello use_srtp carries an MKI the client did not offer".to_owned(),
        )),
        [_] => Err(Error::Negotiation("SRTP protection profile")),
        _ => Err(Error::Decode(
            "ServerHello use_srtp must select exactly one profile".to_owned(),
        )),
    }
}

#[allow(missing_docs)]
pub fn check_initial_renegotiation_info(extensions: &[Extension]) -> Result<()> {
    match find(extensions, ext_type::RENEGOTIATION_INFO) {
        Some(extension) if extension.data != [0] => Err(Error::UnexpectedMessage(
            "renegotiation_info is not empty in an initial handshake".to_owned(),
        )),
        _ => Ok(()),
    }
}

#[allow(missing_docs)]
pub fn check_certificate_request(request: &CertificateRequest) -> Result<()> {
    if !request.certificate_types.contains(&ECDSA_SIGN)
        || !request
            .signature_algorithms
            .contains(&signature_algorithms::ECDSA_SECP256R1_SHA256)
    {
        return Err(Error::Negotiation("client certificate type"));
    }
    Ok(())
}
