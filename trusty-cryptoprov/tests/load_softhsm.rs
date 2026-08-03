//! SoftHSM load smoke (runs only when config file is present).

use std::path::Path;
use trusty_cryptoprov::ProviderRegistry;

fn softhsm_config() -> Option<String> {
    if let Ok(p) = std::env::var("TRUSTY_SOFTHSM_CONFIG")
        && Path::new(&p).exists()
    {
        return Some(p);
    }
    for default in ["/tmp/trusty11/softhsm_unittest.json"] {
        if Path::new(default).exists() {
            return Some(default.to_string());
        }
    }
    None
}

#[test]
fn load_softhsm_when_available() {
    let Some(cfg) = softhsm_config() else {
        eprintln!("skipping SoftHSM test: config not found");
        return;
    };
    let mut registry = ProviderRegistry::new();
    registry.register("pkcs11", trusty_cryptoprov_pkcs11::loader()).unwrap();
    let p = registry.load_provider(&cfg).expect("load SoftHSM");
    assert_eq!(p.manufacturer(), "SoftHSM");
    assert!(p.as_key_manager().is_some());
}
