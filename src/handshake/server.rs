//! Server-role handshake phases and message builders.

use crate::crypto::ecdsa_sign::EcdsaSigningKey;
use crate::error::Result;
use crate::extensions::{
    ec_point_formats, extended_master_secret, renegotiation_info, use_srtp, Extension,
};
use crate::handshake::messages::{
    Certificate, HelloVerifyRequest, ServerHello, ServerKeyExchange,
};
use crate::handshake::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
use crate::extensions::signature_algorithms;
use crate::extensions::signature_algorithms::ECDSA_SECP256R1_SHA256;

/// Server handshake progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerPhase {
    /// Awaiting the initial cookieless `ClientHello` (will answer with `HVR`).
    WaitClientHello,
    /// Awaiting the cookie-bearing `ClientHello`.
    WaitClientHelloWithCookie,
    /// Awaiting the client's `ClientKeyExchange` + `Finished` flight.
    WaitClientFinished,
    /// Handshake complete.
    Done,
}

/// Build the `HelloVerifyRequest` body for `cookie`.
#[must_use]
pub fn build_hello_verify_request(cookie: Vec<u8>) -> Vec<u8> {
    HelloVerifyRequest { cookie }.encode()
}

/// Build the `ServerHello` body, echoing the negotiated SRTP profile.
#[must_use]
pub fn build_server_hello(random: [u8; 32], cipher_suite: u16, srtp_code: Option<u16>) -> Vec<u8> {
    let mut extensions: Vec<Extension> = Vec::new();
    if let Some(code) = srtp_code {
        extensions.push(use_srtp::build(&[code]));
    }
    extensions.push(ec_point_formats::build(&[ec_point_formats::UNCOMPRESSED]));
    extensions.push(extended_master_secret::build());
    extensions.push(renegotiation_info::build());
    ServerHello {
        random,
        session_id: Vec::new(),
        cipher_suite,
        compression_method: 0,
        extensions,
    }
    .encode()
}

/// Build the `Certificate` body for a single leaf certificate.
#[must_use]
pub fn build_certificate(leaf_der: Vec<u8>) -> Vec<u8> {
    Certificate {
        certificates: vec![leaf_der],
    }
    .encode()
}

/// Build a `CertificateRequest` body asking the client for an ECDSA (or RSA)
/// certificate. WebRTC peers always authenticate mutually, so the server always
/// requests a client certificate.
#[must_use]
pub fn build_certificate_request() -> Vec<u8> {
    // certificate_types: ecdsa_sign(64), rsa_sign(1).
    let cert_types: [u8; 2] = [64, 1];
    // supported_signature_algorithms.
    let sig_algs = [
        ECDSA_SECP256R1_SHA256,
        signature_algorithms::RSA_PSS_RSAE_SHA256,
        signature_algorithms::RSA_PKCS1_SHA256,
    ];
    let mut out = Vec::with_capacity(1 + cert_types.len() + 2 + sig_algs.len() * 2 + 2);
    out.push(cert_types.len() as u8);
    out.extend_from_slice(&cert_types);
    out.extend_from_slice(&((sig_algs.len() * 2) as u16).to_be_bytes());
    for alg in sig_algs {
        out.extend_from_slice(&alg.to_be_bytes());
    }
    // certificate_authorities: empty.
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

/// Build and sign the `ServerKeyExchange` body for the server's ephemeral P-256
/// point.
///
/// The signature (ECDSA P-256 / SHA-256) covers
/// `client_random || server_random || ECParameters`.
///
/// # Errors
///
/// Returns an error if signing fails.
pub fn build_server_key_exchange(
    signing_key: &EcdsaSigningKey,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    ephemeral_point: Vec<u8>,
) -> Result<Vec<u8>> {
    let ske = ServerKeyExchange {
        named_curve: crate::extensions::supported_groups::SECP256R1,
        public_point: ephemeral_point,
        signature_algorithm: ECDSA_SECP256R1_SHA256,
        signature: Vec::new(),
    };
    let mut message = Vec::with_capacity(64 + 4 + ske.public_point.len());
    message.extend_from_slice(client_random);
    message.extend_from_slice(server_random);
    message.extend_from_slice(&ske.signed_params());
    let signature = signing_key.sign_der(&message)?;
    Ok(ServerKeyExchange {
        signature,
        ..ske
    }
    .encode())
}

/// Choose an SRTP profile present in both the client's offer and our preference
/// list.
#[must_use]
pub fn negotiate_srtp(offered: &[u16], preferred: &[u16]) -> Option<u16> {
    preferred
        .iter()
        .copied()
        .find(|code| offered.contains(code))
}

/// Choose a cipher suite present in the client's offer that we support.
#[must_use]
pub fn negotiate_cipher_suite(offered: &[u16]) -> Option<u16> {
    use crate::handshake::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    [
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ]
    .into_iter()
    .find(|suite| offered.contains(suite))
}
