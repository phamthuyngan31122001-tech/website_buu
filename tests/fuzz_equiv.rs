/// Property-based equivalents of the cargo-fuzz targets.
///
/// cargo-fuzz (libFuzzer) requires Linux/macOS; these tests replicate the same
/// security-critical code paths using `proptest` so they run on Windows MSVC.
use proptest::prelude::*;
use website_buu::hybird::{
    decrypt_document, decrypt_transport_payload, encrypt_document, load_or_create_kem_pair,
};

// ── shared keypair (generated once per test process) ──────────────────────────

fn keypair() -> (String, String) {
    let dir = std::env::temp_dir().join("website_buu_proptest_keys");
    let master_key = website_buu::crypto::MasterKey([7_u8; 32]);
    load_or_create_kem_pair(&dir, &master_key).expect("generate hybrid keypair")
}

// ── fuzz_target_1 equivalent: arbitrary bytes must never panic ────────────────

proptest! {
    #[test]
    fn decrypt_document_never_panics(
        private_key in ".*",
        kem_ct      in ".*",
        nonce       in ".*",
        payload     in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        // Must return Ok or Err — never panic.
        let _ = decrypt_document(&private_key, &kem_ct, &nonce, &payload);
    }
}

// ── fuzz_target_roundtrip equivalent: encrypt→decrypt must be identity ────────

proptest! {
    #[test]
    fn hybrid_encrypt_decrypt_roundtrip(
        plaintext in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let (public_key, private_key) = keypair();
        let (kem_ct, nonce, encrypted) = encrypt_document(&public_key, &plaintext)
            .expect("encrypt_document should not fail on valid key");
        let decrypted = decrypt_document(&private_key, &kem_ct, &nonce, &encrypted)
            .expect("decrypt_document should succeed after valid encryption");
        prop_assert_eq!(decrypted, plaintext);
    }
}

// ── fuzz_target_transport equivalent: arbitrary input must never panic ─────────

proptest! {
    #[test]
    fn decrypt_transport_payload_never_panics(
        sync_key   in ".*",
        nonce      in ".*",
        ciphertext in ".*",
    ) {
        // Must return Ok or Err — never panic.
        let _ = decrypt_transport_payload(&sync_key, &nonce, &ciphertext);
    }
}

// ── edge-case corpus (mirrors seed corpus used by libFuzzer) ──────────────────

#[test]
fn decrypt_document_edge_cases() {
    let long_key = "A".repeat(1024);
    let cases: &[(&str, &str, &str, &[u8])] = &[
        ("", "", "", b""),
        ("bad-key", "bad-kem", "bad-nonce", b"\x00\xff\xfe"),
        (long_key.as_str(), "", "", b"data"),
    ];
    for (pk, kem, nonce, payload) in cases {
        // None of these should panic.
        let _ = decrypt_document(pk, kem, nonce, payload);
    }
}

#[test]
fn decrypt_transport_edge_cases() {
    let cases: &[(&str, &str, &str)] = &[
        ("", "", ""),
        ("not-base64!", "also-bad", "ciphertext"),
        (&"k".repeat(512), &"n".repeat(32), &"c".repeat(512)),
    ];
    for (k, n, c) in cases {
        let _ = decrypt_transport_payload(k, n, c);
    }
}
