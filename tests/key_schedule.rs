//! Extended master secret derivation, key expansion, and the RFC 5705 exporter.

use dtls::crypto::prf::prf_sha256;
use dtls::exporter::{export_keying_material, DTLS_SRTP_LABEL};
use dtls::handshake::keyschedule::{
    derive_keys, extended_master_secret, KEY_BLOCK_LEN, VERIFY_DATA_LEN,
};

#[test]
fn extended_master_secret_matches_prf_definition() {
    let premaster = [0x42u8; 32];
    let session_hash = [0x7fu8; 32];
    let ms = extended_master_secret(&premaster, &session_hash).unwrap();
    assert_eq!(ms.len(), 48);
    // RFC 7627: master_secret = PRF(pms, "extended master secret", session_hash)[:48].
    let want = prf_sha256(&premaster, b"extended master secret", &session_hash, 48).unwrap();
    assert_eq!(&ms[..], &want[..]);
}

#[test]
fn key_expansion_splits_the_key_block() {
    let ms = [0x24u8; 48];
    let server_random = [0x01u8; 32];
    let client_random = [0x02u8; 32];
    let km = derive_keys(&ms, &server_random, &client_random).unwrap();

    let mut seed = Vec::new();
    seed.extend_from_slice(&server_random);
    seed.extend_from_slice(&client_random);
    let block = prf_sha256(&ms, b"key expansion", &seed, KEY_BLOCK_LEN).unwrap();

    assert_eq!(&km.client.key[..], &block[0..16]);
    assert_eq!(&km.server.key[..], &block[16..32]);
    assert_eq!(&km.client.salt[..], &block[32..36]);
    assert_eq!(&km.server.salt[..], &block[36..40]);
}

#[test]
fn verify_data_length_is_twelve() {
    assert_eq!(VERIFY_DATA_LEN, 12);
}

#[test]
fn exporter_matches_prf_with_dtls_srtp_label() {
    let ms = [0x55u8; 48];
    let client_random = [0xa1u8; 32];
    let server_random = [0xb2u8; 32];
    let out = export_keying_material(
        &ms,
        &client_random,
        &server_random,
        DTLS_SRTP_LABEL,
        None,
        60,
    )
    .unwrap();
    assert_eq!(out.len(), 60);

    // RFC 5705 with no context: seed = client_random || server_random.
    let mut seed = Vec::new();
    seed.extend_from_slice(&client_random);
    seed.extend_from_slice(&server_random);
    let want = prf_sha256(&ms, DTLS_SRTP_LABEL, &seed, 60).unwrap();
    assert_eq!(&out[..], want.as_slice());
}

#[test]
fn exporter_context_is_length_prefixed() {
    let ms = [0x66u8; 48];
    let client_random = [0xc3u8; 32];
    let server_random = [0xd4u8; 32];
    let context = b"ctx";
    let out = export_keying_material(
        &ms,
        &client_random,
        &server_random,
        DTLS_SRTP_LABEL,
        Some(context),
        16,
    )
    .unwrap();

    let mut seed = Vec::new();
    seed.extend_from_slice(&client_random);
    seed.extend_from_slice(&server_random);
    seed.extend_from_slice(&(context.len() as u16).to_be_bytes());
    seed.extend_from_slice(context);
    let want = prf_sha256(&ms, DTLS_SRTP_LABEL, &seed, 16).unwrap();
    assert_eq!(&out[..], want.as_slice());
}

#[test]
fn exporter_rejects_oversized_context() {
    let context = vec![0u8; usize::from(u16::MAX) + 1];
    let err = export_keying_material(
        &[0x11u8; 48],
        &[0x22u8; 32],
        &[0x33u8; 32],
        DTLS_SRTP_LABEL,
        Some(&context),
        16,
    )
    .unwrap_err();
    assert!(matches!(err, dtls::Error::InvalidArgument(_)));
}
