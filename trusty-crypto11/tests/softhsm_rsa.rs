//! SoftHSM RSA parity tests (ignored without config).

#[path = "common/mod.rs"]
mod common;

use sha2::{Digest, Sha256};
use trusty_crypto11::{DigestAlgorithm, KeyPurpose, PrivateKey, RsaSignScheme};

#[test]
#[ignore = "requires SoftHSM config at TRUSTY_SOFTHSM_CONFIG or /tmp/trusty11/softhsm_unittest.json"]
fn rsa_generate_sign_find_destroy() {
    let Some(lib) = common::open_lib() else {
        return;
    };

    let key =
        lib.generate_rsa_key("rust-rsa-test", 2048, KeyPurpose::Signing).expect("generate rsa");
    let digest = Sha256::digest(b"hello trusty-crypto11");
    let sig = match &key.key {
        PrivateKey::Rsa(k) => k
            .sign(&digest, &RsaSignScheme::Pkcs1v15 { hash: DigestAlgorithm::Sha256 })
            .expect("sign"),
        PrivateKey::Ecdsa(_) => panic!("expected RSA"),
    };
    assert!(!sig.is_empty());

    let found = lib.find_key_pair(&key.id, "", None).expect("find by id");
    assert!(matches!(found, PrivateKey::Rsa(_)));

    let found_label = lib.find_key_pair("", &key.label, None).expect("find by label");
    assert!(matches!(found_label, PrivateKey::Rsa(_)));

    lib.destroy_key_pair_on_slot(lib.current_slot_id(), &key.id).expect("destroy");
}
