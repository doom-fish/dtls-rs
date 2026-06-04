//! Hand-rolled self-signed ECDSA-P256 X.509 v3 certificate generation.
//!
//! WebRTC peers never validate a certificate chain; the only thing that matters
//! is that the certificate's DER hashes to the `a=fingerprint` advertised in the
//! SDP. We therefore emit the smallest valid certificate that carries our
//! ephemeral ECDSA-P256 public key and is self-signed with the matching private
//! key. The subject/issuer is the constant `CN=doomfish`.

use crate::asn1;
use crate::crypto::ecdsa_sign::EcdsaSigningKey;
use crate::crypto::random_bytes;
use crate::error::Result;

use std::time::{SystemTime, UNIX_EPOCH};

/// OID `1.2.840.10045.4.3.2` — `ecdsa-with-SHA256`.
const OID_ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
/// OID `1.2.840.10045.2.1` — `id-ecPublicKey`.
const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
/// OID `1.2.840.10045.3.1.7` — `prime256v1` / `secp256r1`.
const OID_SECP256R1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
/// OID `2.5.4.3` — `commonName`.
const OID_COMMON_NAME: &[u64] = &[2, 5, 4, 3];

/// A generated certificate together with the key that signed it.
pub struct SelfSignedCertificate {
    /// The signing/identity key (also the certificate's public key).
    pub key: EcdsaSigningKey,
    /// The DER-encoded certificate.
    pub der: Vec<u8>,
}

/// Generate a fresh ECDSA-P256 self-signed certificate.
///
/// # Errors
///
/// Returns an error if key generation, randomness, or signing fails.
pub fn generate() -> Result<SelfSignedCertificate> {
    let key = EcdsaSigningKey::generate()?;
    let der = build_certificate(&key)?;
    Ok(SelfSignedCertificate { key, der })
}

fn build_certificate(key: &EcdsaSigningKey) -> Result<Vec<u8>> {
    let sig_alg = asn1::sequence(&[asn1::oid(OID_ECDSA_WITH_SHA256)]);

    // version [0] EXPLICIT INTEGER 2 (v3)
    let version = asn1::explicit(0, &asn1::integer_u64(2));

    // serialNumber: random, positive
    let serial_bytes = random_bytes(16)?;
    let serial = asn1::integer_unsigned(&serial_bytes);

    // Name = SEQUENCE OF RDN(SET OF ATV) with a single CN=doomfish
    let name = asn1::sequence(&[asn1::set(&[asn1::sequence(&[
        asn1::oid(OID_COMMON_NAME),
        asn1::printable_string("doomfish"),
    ])])]);

    // Validity: now-1day .. now+365days
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let not_before = asn1::utc_time(&format_utc_time(now.saturating_sub(86_400)));
    let not_after = asn1::utc_time(&format_utc_time(now + 365 * 86_400));
    let validity = asn1::sequence(&[not_before, not_after]);

    // SubjectPublicKeyInfo
    let spki = asn1::sequence(&[
        asn1::sequence(&[asn1::oid(OID_EC_PUBLIC_KEY), asn1::oid(OID_SECP256R1)]),
        asn1::bit_string(key.public_point()),
    ]);

    let tbs = asn1::sequence(&[
        version,
        serial,
        sig_alg.clone(),
        name.clone(), // issuer
        validity,
        name, // subject
        spki,
    ]);

    let signature = key.sign_der(&tbs)?;

    let certificate = asn1::sequence(&[tbs, sig_alg, asn1::bit_string(&signature)]);
    Ok(certificate)
}

/// Format a Unix timestamp as a `YYMMDDHHMMSSZ` `UTCTime` string.
///
/// Valid for years 1950–2049, which covers every certificate this crate emits.
fn format_utc_time(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    let (year, month, day) = civil_from_days(days);
    let yy = year % 100;
    format!("{yy:02}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z")
}

/// Convert a count of days since the Unix epoch to `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
