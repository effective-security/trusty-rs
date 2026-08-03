//! Integration: load inmem via an explicit ProviderRegistry.

use trusty_cryptoprov::{KeyPurpose, NamedCurve, ProviderRegistry};

#[test]
fn load_empty_default_inmem() {
    let mut registry = ProviderRegistry::new();
    registry.register("inmem", trusty_cryptoprov_inmem::loader()).unwrap();
    let crypto = registry.load("", &[]).unwrap();
    assert_eq!(crypto.default_provider().manufacturer(), "inmem");

    let p = crypto.default_provider();
    let key = p.generate_rsa_key("itest", 2048, KeyPurpose::Signing).unwrap();
    assert_eq!(key.label(), Some("itest"));
    let id = key.key_id().unwrap().to_string();
    let _ = p.get_key(&id).unwrap();

    let ec = p.generate_ecdsa_key("ec", NamedCurve::P384).unwrap();
    assert_eq!(ec.label(), Some("ec"));
}
