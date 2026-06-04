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
    ec_point_formats, extended_master_secret, renegotiation_info, signature_algorithms,
    supported_groups, use_srtp, Extension,
};
use crate::handshake::messages::{ClientHello, ClientKeyExchange, ServerKeyExchange};
use crate::handshake::{
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
};

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
    let extensions = vec![
        supported_groups::build(&[supported_groups::SECP256R1]),
        ec_point_formats::build(&[ec_point_formats::UNCOMPRESSED]),
        signature_algorithms::build(&[
            signature_algorithms::ECDSA_SECP256R1_SHA256,
            signature_algorithms::RSA_PSS_RSAE_SHA256,
            signature_algorithms::RSA_PKCS1_SHA256,
        ]),
        use_srtp::build(srtp_codes),
        extended_master_secret::build(),
        renegotiation_info::build(),
    ];
    ClientHello {
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
    ske: &ServerKeyExchange,
) -> Result<()> {
    let mut message = Vec::with_capacity(64 + ske.public_point.len() + 4);
    message.extend_from_slice(client_random);
    message.extend_from_slice(server_random);
    message.extend_from_slice(&ske.signed_params());

    match peer_key {
        PeerPublicKey::EcdsaP256 { point } => {
            verify_ecdsa_p256(point, &message, &ske.signature)
        }
        PeerPublicKey::Rsa => {
            let scheme = match ske.signature_algorithm {
                signature_algorithms::RSA_PKCS1_SHA256 => RsaScheme::Pkcs1Sha256,
                signature_algorithms::RSA_PSS_RSAE_SHA256 => RsaScheme::PssSha256,
                _ => return Err(Error::Negotiation("unsupported RSA signature algorithm")),
            };
            verify_rsa(leaf_cert_der, scheme, &message, &ske.signature)
        }
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
        PeerPublicKey::EcdsaP256 { point } => verify_ecdsa_p256(point, transcript, signature),
        PeerPublicKey::Rsa => {
            let scheme = match signature_algorithm {
                signature_algorithms::RSA_PKCS1_SHA256 => RsaScheme::Pkcs1Sha256,
                signature_algorithms::RSA_PSS_RSAE_SHA256 => RsaScheme::PssSha256,
                _ => return Err(Error::Negotiation("unsupported RSA signature algorithm")),
            };
            verify_rsa(leaf_cert_der, scheme, transcript, signature)
        }
    }
}

/// Locate the `use_srtp` extension in the server hello and return the selected
/// profile code, if any.
#[must_use]
pub fn selected_srtp(extensions: &[Extension]) -> Option<u16> {
    let ext = crate::extensions::find(extensions, crate::extensions::ext_type::USE_SRTP)?;
    use_srtp::parse_profiles(&ext.data).ok()?.first().copied()
}
