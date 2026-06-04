//! Generate a self-signed P-256 certificate and print its SDP fingerprint.
//!
//! Run with: `cargo run --example 01_self_signed_cert`

use dtls::cert::parse::PeerPublicKey;
use dtls::cert::{format_colon_hex, generate, parse_leaf_public_key, sha256_fingerprint};

fn main() -> dtls::Result<()> {
    let cert = generate()?;
    println!("certificate DER: {} bytes", cert.der.len());

    let fingerprint = sha256_fingerprint(&cert.der)?;
    println!("a=fingerprint:sha-256 {}", format_colon_hex(&fingerprint));

    match parse_leaf_public_key(&cert.der)? {
        PeerPublicKey::EcdsaP256 { point } => {
            println!("public key: ECDSA P-256, {} byte point", point.len());
        }
        PeerPublicKey::Rsa => println!("public key: RSA"),
    }

    Ok(())
}
