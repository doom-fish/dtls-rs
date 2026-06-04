//! Known-answer test for the TLS 1.2 PRF (SHA-256), using the official IETF
//! test vector (TLS mailing list, "Test vectors for TLS 1.2 PRF").

use dtls::crypto::prf::prf_sha256;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn tls12_prf_sha256_known_answer() {
    let secret = hex("9bbe436ba940f017b17652849a71db35");
    let seed = hex("a0ba9f936cda311827a6f796ffd5198c");
    let want = hex(
        "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a\
         6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab\
         4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701\
         87347b66",
    );
    let got = prf_sha256(&secret, b"test label", &seed, 100).unwrap();
    assert_eq!(got, want);
}
