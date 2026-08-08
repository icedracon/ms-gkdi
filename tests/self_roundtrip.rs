//! **Synthetic** round-trips — see `README.md`. These prove the parsers and the L2 walk
//! agree with themselves on data this crate generated. They do **not** prove agreement with
//! a live Server 2022 DC or Microsoft's reference `dpapi-ng.py`; the KAT harness described
//! in the README is the gate for a proper 0.1.0 release.

use ms_gkdi::gkdi::{
    compute_l2_key, kdf_context, GroupKeyEnvelope, KdfParameters, KeyIdentifier, RootKeyId,
};
use ms_gkdi::kdf::{kdf, kds_service_label, HashAlg};
use ms_gkdi::GkdiError;

const ROOT: RootKeyId = RootKeyId([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
]);

fn key_identifier(l0: i32, l1: i32, l2: i32) -> KeyIdentifier {
    KeyIdentifier {
        version: 1,
        flags: 0,
        l0,
        l1,
        l2,
        root_key_id: ROOT,
        kdf_algorithm: "SP800_108_CTR_HMAC".into(),
        kdf_parameters: KdfParameters {
            hash: HashAlg::Sha512,
        }
        .to_bytes(),
        secret_algorithm: "DH".into(),
        secret_parameters: vec![0xaa; 8],
        private_key_length: 512,
        public_key_length: 2048,
        domain_name: "testlab.local".into(),
        forest_name: "testlab.local".into(),
    }
}

// ── structures ────────────────────────────────────────────────────────────────

#[test]
fn kdf_parameters_round_trip_synthetic() {
    for hash in [
        HashAlg::Sha1,
        HashAlg::Sha256,
        HashAlg::Sha384,
        HashAlg::Sha512,
    ] {
        let p = KdfParameters { hash };
        assert_eq!(KdfParameters::parse(&p.to_bytes()).unwrap(), p);
    }
}

#[test]
fn key_identifier_round_trips_synthetic() {
    let k = key_identifier(361, 7, 19);
    let bytes = k.to_bytes();
    let back = KeyIdentifier::parse(&bytes).unwrap();
    assert_eq!(back, k);
    assert_eq!(back.to_bytes(), bytes);
    assert_eq!(back.hash().unwrap(), HashAlg::Sha512);
    assert!(!back.is_public_key());
}

#[test]
fn key_identifier_rejects_foreign_bytes_synthetic() {
    let mut bytes = key_identifier(1, 1, 1).to_bytes();
    bytes[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // clobber the KDSK magic
    assert!(matches!(
        KeyIdentifier::parse(&bytes),
        Err(GkdiError::BadMagic { .. })
    ));
}

#[test]
fn truncation_anywhere_is_an_error_not_a_panic_synthetic() {
    let bytes = key_identifier(1, 2, 3).to_bytes();
    for cut in 0..bytes.len() {
        let _ = KeyIdentifier::parse(&bytes[..cut]);
    }
}

#[test]
fn root_key_id_renders_as_a_guid_synthetic() {
    assert_eq!(ROOT.to_string(), "04030201-0605-0807-090a-0b0c0d0e0f10");
}

// ── the key tree ──────────────────────────────────────────────────────────────

fn envelope(l0: i32, l1: i32, l2: i32, l1_key: Vec<u8>, l2_key: Vec<u8>) -> GroupKeyEnvelope {
    GroupKeyEnvelope {
        version: 1,
        flags: 0,
        l0,
        l1,
        l2,
        root_key_id: ROOT,
        kdf_algorithm: "SP800_108_CTR_HMAC".into(),
        kdf_parameters: KdfParameters {
            hash: HashAlg::Sha512,
        }
        .to_bytes(),
        secret_algorithm: String::new(),
        secret_parameters: Vec::new(),
        private_key_length: 512,
        public_key_length: 2048,
        domain_name: "testlab.local".into(),
        forest_name: "testlab.local".into(),
        l1_key,
        l2_key,
    }
}

#[test]
fn the_exact_node_needs_no_derivation_synthetic() {
    let l2 = vec![0x11; 64];
    let env = envelope(361, 7, 19, vec![0x22; 64], l2.clone());
    assert_eq!(compute_l2_key(&env, 7, 19).unwrap(), l2);
}

#[test]
fn stepping_down_the_l2_chain_matches_the_kdf_synthetic() {
    let seed = vec![0x11; 64];
    let env = envelope(361, 7, 19, vec![0x22; 64], seed.clone());

    let want = kdf(
        HashAlg::Sha512,
        &seed,
        &kds_service_label(),
        &kdf_context(ROOT, 361, 7, 18),
        64,
    );
    assert_eq!(compute_l2_key(&env, 7, 18).unwrap(), want);

    // Two steps down is the same chain applied twice.
    let want2 = kdf(
        HashAlg::Sha512,
        &want,
        &kds_service_label(),
        &kdf_context(ROOT, 361, 7, 17),
        64,
    );
    assert_eq!(compute_l2_key(&env, 7, 17).unwrap(), want2);
}

#[test]
fn the_tree_is_one_way_synthetic() {
    // A key for L2=19 cannot produce the key for L2=20; deriving "up" must not silently
    // return the seed we started from.
    let env = envelope(361, 7, 19, vec![0x22; 64], vec![0x11; 64]);
    let up = compute_l2_key(&env, 7, 20).unwrap();
    assert_ne!(up, vec![0x11; 64]);
    // Going up re-seeds from L1, so it must differ from any downward step too.
    assert_ne!(up, compute_l2_key(&env, 7, 18).unwrap());
}

#[test]
fn a_different_l1_branch_reseeds_from_the_l1_key_synthetic() {
    let env = envelope(361, 7, 19, vec![0x22; 64], vec![0x11; 64]);
    let other = compute_l2_key(&env, 5, 19).unwrap();
    assert_ne!(other, compute_l2_key(&env, 7, 19).unwrap());
}

#[test]
fn a_later_node_without_an_l1_key_is_refused_not_looped_synthetic() {
    // Regression: walking "up" the L2 chain has to re-seed from L1. With no L1 key there is
    // nothing to re-seed from, and the old code spun forever decrementing past zero.
    let env = envelope(361, 7, 19, Vec::new(), vec![0x11; 64]);
    assert!(matches!(
        compute_l2_key(&env, 7, 20),
        Err(GkdiError::MissingSeedKey("L1"))
    ));
}

#[test]
fn out_of_range_indices_are_rejected_synthetic() {
    let env = envelope(361, 7, 19, vec![0x22; 64], vec![0x11; 64]);
    assert!(matches!(
        compute_l2_key(&env, 32, 0),
        Err(GkdiError::BadTreeIndex { .. })
    ));
    assert!(matches!(
        compute_l2_key(&env, 0, -1),
        Err(GkdiError::BadTreeIndex { .. })
    ));
}

#[test]
fn kdf_output_is_deterministic_and_the_requested_length_synthetic() {
    for len in [16usize, 32, 64, 100] {
        let a = kdf(HashAlg::Sha256, b"secret", b"label", b"context", len);
        let b = kdf(HashAlg::Sha256, b"secret", b"label", b"context", len);
        assert_eq!(a, b);
        assert_eq!(a.len(), len);
    }
    // Length is bound into the derivation, so a longer request is not a prefix extension.
    let short = kdf(HashAlg::Sha256, b"secret", b"label", b"ctx", 32);
    let long = kdf(HashAlg::Sha256, b"secret", b"label", b"ctx", 64);
    assert_ne!(&long[..32], &short[..]);
}
