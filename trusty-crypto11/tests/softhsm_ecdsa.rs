//! SoftHSM ECDSA integration tests (ignored without config).

#[path = "common/mod.rs"]
mod common;

use sha2::{Digest, Sha256};
use trusty_crypto11::{NamedCurve, PrivateKey};

#[test]
fn ecdsa_p256_generate_sign_find() {
    let Some(lib) = common::open_lib() else {
        return;
    };

    let key = lib.generate_ecdsa_key("rust-ecdsa-test", NamedCurve::P256).expect("generate ecdsa");
    let digest = Sha256::digest(b"ecdsa message");
    let sig = match &key.key {
        PrivateKey::Ecdsa(k) => k.sign(&digest).expect("sign"),
        PrivateKey::Rsa(_) => panic!("expected ECDSA"),
    };
    assert!(!sig.is_empty());
    // DER SEQUENCE tag
    assert_eq!(sig[0], 0x30);

    let found = lib.find_key_pair(&key.id, "", None).expect("find");
    assert!(matches!(found, PrivateKey::Ecdsa(_)));

    lib.destroy_key_pair_on_slot(lib.current_slot_id(), &key.id).expect("destroy");
}
