# trusty-cryptoprov

Facade crate for Trusty crypto providers: PKCS#11 HSMs, in-memory software
keys, PEM / PKCS#11 URI loading, TLS key material, and AES-GCM helpers.

Traits, common types, errors, and [`ProviderRegistry`] live in
[`trusty-cryptoprov-core`](../trusty-cryptoprov-core/) and are re-exported here.
Provider implementations are optional Cargo features.

## Features

| Feature | Crate | Status |
|---------|-------|--------|
| `inmem` | [`trusty-cryptoprov-inmem`](../trusty-cryptoprov-inmem/) | Software RSA/ECDSA |
| `pkcs11` | [`trusty-cryptoprov-pkcs11`](../trusty-cryptoprov-pkcs11/) | PKCS#11 via [`trusty-crypto11`](../trusty-crypto11/) |
| `aws-kms` | [`trusty-cryptoprov-aws-kms`](../trusty-cryptoprov-aws-kms/) | Stub (`NotImplemented`) |
| `gcp-kms` | [`trusty-cryptoprov-gcp-kms`](../trusty-cryptoprov-gcp-kms/) | Stub (`NotImplemented`) |

Default features are empty — enable only what your binary needs.

## Startup

There is no process-global provider registry. Register loaders at your
application's composition root:

```rust,no_run
use trusty_cryptoprov::ProviderRegistry;

let mut registry = ProviderRegistry::new();
#[cfg(feature = "pkcs11")]
registry.register("pkcs11", trusty_cryptoprov_pkcs11::loader())?;
#[cfg(feature = "inmem")]
registry.register("inmem", trusty_cryptoprov_inmem::loader())?;
let crypto = registry.load("", &[])?; // empty path → default inmem
# Ok::<(), trusty_cryptoprov::Error>(())
```

`kind` in token config selects the loader (`"pkcs11"`, `"inmem"`, …).
`manufacturer` / `model` identify the loaded provider for lookup via
[`Crypto::find_provider`](https://docs.rs/trusty-cryptoprov).

## Generate and use an in-memory key

```rust,no_run
# #[cfg(feature = "inmem")]
# {
use trusty_cryptoprov::{KeyPurpose, NamedCurve, ProviderRegistry};

let mut registry = ProviderRegistry::new();
registry.register("inmem", trusty_cryptoprov_inmem::loader())?;
let crypto = registry.load("", &[])?;
let p = crypto.default_provider();

let rsa = p.generate_rsa_key("signing-key", 2048, KeyPurpose::Signing)?;
let id = rsa.key_id().unwrap().to_string();
let _signer = p.get_key(&id)?;

let ec = p.generate_ecdsa_key("ec-key", NamedCurve::P256)?;
assert_eq!(ec.label(), Some("ec-key"));
# }
# Ok::<(), trusty_cryptoprov::Error>(())
```

## Load a PEM private key

Requires feature `inmem`:

```rust,no_run
# #[cfg(feature = "inmem")]
# {
use trusty_cryptoprov::{CryptoExt, ProviderRegistry};

let mut registry = ProviderRegistry::new();
registry.register("inmem", trusty_cryptoprov_inmem::loader())?;
let crypto = registry.load("", &[])?;

let pem = std::fs::read("testdata/test-key.pem")?;
let (provider, signer) = crypto.load_private_key(&pem)?;
assert!(provider.is_none()); // PEM keys are not token-backed
let _ = signer;
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```

## PKCS#11 (SoftHSM)

```rust,no_run
# #[cfg(feature = "pkcs11")]
# {
use trusty_cryptoprov::ProviderRegistry;

let mut registry = ProviderRegistry::new();
registry.register("pkcs11", trusty_cryptoprov_pkcs11::loader())?;
let crypto = registry.load("/path/to/softhsm.json", &[])?;
let p = crypto.default_provider();
assert!(p.as_key_manager().is_some());
# }
# Ok::<(), trusty_cryptoprov::Error>(())
```

Example token config (JSON field names as in [`FileTokenConfig`](../trusty-cryptoprov-core/)):

```json
{
  "kind": "pkcs11",
  "manufacturer": "SoftHSM",
  "model": "SoftHSM v2",
  "path": "/usr/lib/softhsm/libsofthsm2.so",
  "token_label": "MyToken",
  "pin": "file:/path/to/pin.txt"
}
```

## TLS key pair

```rust,no_run
# #[cfg(feature = "inmem")]
# {
use trusty_cryptoprov::{CryptoExt, ProviderRegistry};

let mut registry = ProviderRegistry::new();
registry.register("inmem", trusty_cryptoprov_inmem::loader())?;
let crypto = registry.load("", &[])?;
let material = crypto.load_tls_key_pair("cert.pem", "key.pem")?;
let _leaf = &material.leaf_parsed;
let _chain = &material.cert_chain_der;
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```

## AES-GCM

```rust,no_run
use trusty_cryptoprov::{gcm_decrypt, gcm_encrypt};

let key = [0u8; 32]; // 16, 24, or 32 bytes
let ciphertext = gcm_encrypt(b"secret", &key)?;
let plaintext = gcm_decrypt(&ciphertext, &key)?;
assert_eq!(plaintext, b"secret");
# Ok::<(), trusty_cryptoprov::Error>(())
```

Ciphertext layout is `nonce (12 bytes) || ciphertext+tag`.

## Architecture notes

- **`ProviderRegistry`** routes by config `kind` to a `ProviderLoader`.
- **`Crypto`** holds the default provider plus optional extras keyed by
  `(manufacturer, model)`.
- **`CryptoExt`** adds facade helpers (`load_private_key`, TLS) as a trait
  because inherent methods cannot be added to `Crypto` from this crate.
- Register provider loaders from the sub-crates (`trusty_cryptoprov_inmem::loader`,
  etc.); the facade re-exports provider *types* but not the `loader()` functions.

## License

MIT
