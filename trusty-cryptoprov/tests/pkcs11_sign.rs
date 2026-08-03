//! SoftHSM PKCS#11 sign via cryptoprov facade (ignored without token).

use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};
use trusty_cryptoprov::{
    CryptoExt, DigestAlgorithm, KeyPurpose, NamedCurve, ProviderRegistry, RsaSignScheme,
};

fn pkcs11_registry() -> ProviderRegistry {
    let mut registry = ProviderRegistry::new();
    registry.register("pkcs11", trusty_cryptoprov_pkcs11::loader()).unwrap();
    registry
}

fn softhsm_config() -> Option<String> {
    if let Ok(p) = std::env::var("TRUSTY_SOFTHSM_CONFIG")
        && Path::new(&p).exists()
    {
        return Some(p);
    }
    let default: &str = "/tmp/trusty11/softhsm_unittest.json";
    if Path::new(default).exists() {
        return Some(default.to_string());
    }

    None
}

/// SoftHSM keeps process-global PKCS#11 state and a shared on-disk token DB.
/// Serialize these tests so parallel cargo-test workers do not race init/use/destroy.
fn softhsm_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn pkcs11_rsa_generate_sign() {
    let _guard = softhsm_test_lock();
    let Some(cfg) = softhsm_config() else {
        eprintln!("skip: SoftHSM config missing");
        return;
    };
    let p = pkcs11_registry().load_provider(&cfg).expect("load SoftHSM");

    let key =
        p.generate_rsa_key("cryptoprov-rsa-sign", 2048, KeyPurpose::Signing).expect("generate RSA");

    let digest = Sha256::digest(b"hello trusty-cryptoprov");
    let sig = key
        .sign_rsa(&digest, &RsaSignScheme::Pkcs1v15 { hash: DigestAlgorithm::Sha256 })
        .expect("sign_rsa");
    assert!(!sig.is_empty());

    let id = key.key_id().expect("PKCS#11 key has an id").to_string();
    let (_uri, pem) = p.export_key(&id).expect("export");
    assert!(pem.is_empty(), "PKCS#11 export returns URI only");

    if let Some(km) = p.as_key_manager() {
        km.destroy_key_pair_on_slot(km.current_slot_id(), &id).expect("destroy");
    }
}

#[test]
fn pkcs11_ecdsa_generate_sign() {
    let _guard = softhsm_test_lock();
    let Some(cfg) = softhsm_config() else {
        eprintln!("skip: SoftHSM config missing");
        return;
    };
    let p = pkcs11_registry().load_provider(&cfg).expect("load SoftHSM");

    let key = p.generate_ecdsa_key("cryptoprov-ec-sign", NamedCurve::P256).expect("generate ECDSA");

    let digest = Sha256::digest(b"hello ecdsa cryptoprov");
    let sig = key.sign_ecdsa(&digest).expect("sign_ecdsa");
    assert!(!sig.is_empty());

    let id = key.key_id().expect("PKCS#11 key has an id").to_string();
    if let Some(km) = p.as_key_manager() {
        km.destroy_key_pair_on_slot(km.current_slot_id(), &id).expect("destroy");
    }
}

#[test]
fn pkcs11_export_uri_load_private_key() {
    let _guard = softhsm_test_lock();
    let Some(cfg) = softhsm_config() else {
        eprintln!("skip: SoftHSM config missing");
        return;
    };
    let crypto = pkcs11_registry().load(&cfg, &[]).expect("load crypto set");
    let p = crypto.default_provider();

    let key = p.generate_rsa_key("cryptoprov-uri", 2048, KeyPurpose::Signing).expect("generate");
    let id = key.key_id().expect("PKCS#11 key has an id").to_string();
    let (uri, _) = p.export_key(&id).expect("export");
    assert!(uri.starts_with("pkcs11:"), "got {uri}");

    let (prov, loaded) = crypto.load_private_key(uri.as_bytes()).expect("LoadPrivateKey URI");
    assert!(prov.is_some());
    let digest = Sha256::digest(b"via uri");
    let sig = loaded
        .sign_rsa(&digest, &RsaSignScheme::Pkcs1v15 { hash: DigestAlgorithm::Sha256 })
        .expect("sign via loaded URI key");
    assert!(!sig.is_empty());

    if let Some(km) = p.as_key_manager() {
        km.destroy_key_pair_on_slot(km.current_slot_id(), &id).expect("destroy");
    }
}
