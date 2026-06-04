//! Minimal peer-certificate inspection.
//!
//! We never validate a certificate chain. We only need to learn, from the leaf
//! certificate, which public-key algorithm the peer signs with (so we route to
//! CryptoKit ECDSA or Security.framework RSA) and, for ECDSA, the uncompressed
//! point used to verify `ServerKeyExchange` / `CertificateVerify`.

use crate::asn1::{DerReader, Element};
use crate::error::{Error, Result};

/// The peer's leaf public-key kind and material.
#[derive(Debug, Clone)]
pub enum PeerPublicKey {
    /// An ECDSA-P256 key, with its uncompressed point (`0x04 || X || Y`).
    EcdsaP256 {
        /// The uncompressed EC point bytes (`0x04 || X || Y`).
        point: Vec<u8>,
    },
    /// An RSA key. Verification goes through Security.framework using the full
    /// certificate DER, so no parsed material is kept here.
    Rsa,
}

// OID byte encodings (the contents after tag+len) for quick comparison.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

const TAG_CONTEXT_0: u8 = 0xA0;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OID: u8 = 0x06;

/// Parse the leaf certificate DER and extract its public-key kind.
///
/// # Errors
///
/// Returns [`Error::Decode`] if the structure does not match an X.509
/// certificate carrying a recognised key algorithm.
pub fn parse_leaf_public_key(cert_der: &[u8]) -> Result<PeerPublicKey> {
    let mut reader = DerReader::new(cert_der);
    let certificate = reader.read()?; // Certificate ::= SEQUENCE
    let cert_fields = certificate.children()?;
    let tbs = cert_fields
        .first()
        .ok_or_else(|| Error::Decode("certificate missing tbsCertificate".to_owned()))?;
    let tbs_fields = tbs.children()?;

    // Skip the optional [0] version, then serial, signature, issuer, validity,
    // subject. SubjectPublicKeyInfo is the next SEQUENCE after subject.
    let mut index = 0;
    if tbs_fields
        .first()
        .is_some_and(|element| element.tag == TAG_CONTEXT_0)
    {
        index += 1; // version
    }
    // serialNumber, signature, issuer, validity, subject => 5 elements
    index += 5;
    // sanity: serialNumber should be an INTEGER at the version-adjusted slot.
    let _ = TAG_INTEGER;
    let spki = tbs_fields
        .get(index)
        .ok_or_else(|| Error::Decode("certificate missing SubjectPublicKeyInfo".to_owned()))?;

    parse_spki(spki)
}

fn parse_spki(spki: &Element<'_>) -> Result<PeerPublicKey> {
    let spki_fields = spki.children()?;
    let algorithm = spki_fields
        .first()
        .ok_or_else(|| Error::Decode("SPKI missing AlgorithmIdentifier".to_owned()))?;
    let alg_fields = algorithm.children()?;
    let oid = alg_fields
        .iter()
        .find(|element| element.tag == TAG_OID)
        .ok_or_else(|| Error::Decode("AlgorithmIdentifier missing OID".to_owned()))?;

    if oid.contents == OID_EC_PUBLIC_KEY {
        let bit_string = spki_fields
            .get(1)
            .filter(|element| element.tag == TAG_BIT_STRING)
            .ok_or_else(|| Error::Decode("EC SPKI missing subjectPublicKey".to_owned()))?;
        // BIT STRING contents = unused-bits(1) || point
        let point = bit_string
            .contents
            .get(1..)
            .ok_or(Error::Truncated("EC public point"))?;
        if point.first() != Some(&0x04) || point.len() != 65 {
            return Err(Error::Decode(
                "EC public key is not an uncompressed P-256 point".to_owned(),
            ));
        }
        Ok(PeerPublicKey::EcdsaP256 {
            point: point.to_vec(),
        })
    } else if oid.contents == OID_RSA_ENCRYPTION {
        Ok(PeerPublicKey::Rsa)
    } else {
        Err(Error::Decode("unsupported peer public-key algorithm".to_owned()))
    }
}
