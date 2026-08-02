//! SoftHSM util / provider enumeration tests (ignored without config).

#[path = "common/mod.rs"]
mod common;

use trusty_crypto11::{KeyPurpose, NamedCurve};

#[test]
#[ignore = "requires SoftHSM config at TRUSTY_SOFTHSM_CONFIG or /tmp/trusty11/softhsm_unittest.json"]
fn tokens_enum_keys_destroy() {
    let Some(lib) = common::open_lib() else {
        return;
    };

    let tokens = lib.tokens_info().expect("tokens_info");
    assert!(!tokens.is_empty());

    let current = lib.enum_tokens(true).expect("enum current");
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].slot_id, lib.current_slot_id());

    let key = lib.generate_rsa_key("rust-util-key", 2048, KeyPurpose::Signing).expect("generate");
    let keys = lib.enum_keys(lib.current_slot_id(), "rust-util").expect("enum_keys");
    assert!(keys.iter().any(|k| k.id == key.id));

    let info = lib.key_info(lib.current_slot_id(), &key.id, true).expect("key_info");
    assert_eq!(info.id, key.id);
    assert!(info.public_key.contains("BEGIN PUBLIC KEY"));

    let uri = lib.export_key(&key.id).expect("export");
    assert!(uri.starts_with("pkcs11:"));

    lib.destroy_key_pair_on_slot(lib.current_slot_id(), &key.id).expect("destroy");

    // ECDSA smoke for util suite completeness
    let ec = lib.generate_ecdsa_key("rust-util-ec", NamedCurve::P256).expect("ecdsa");
    lib.destroy_key_pair_on_slot(lib.current_slot_id(), &ec.id).expect("destroy ec");
}
