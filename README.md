# trusty-rs

Rust crypto provider stack for PKCS#11 HSMs (SoftHSM and hardware tokens),
software RSA/ECDSA keys, and related helpers (PEM/URI loading, TLS key
material, AES-GCM).

## Crates

| Crate | Role |
|-------|------|
| [`trusty-cryptoprov`](./trusty-cryptoprov/) | Facade: re-exports core types, feature-gates providers, PEM/URI/TLS/GCM helpers |
| [`trusty-cryptoprov-core`](./trusty-cryptoprov-core/) | Provider traits, registry, config, errors (no PKCS#11/cloud SDKs) |
| [`trusty-cryptoprov-inmem`](./trusty-cryptoprov-inmem/) | Software RSA/ECDSA provider |
| [`trusty-cryptoprov-pkcs11`](./trusty-cryptoprov-pkcs11/) | PKCS#11 provider wrapping `trusty-crypto11` |
| [`trusty-crypto11`](./trusty-crypto11/) | Low-level PKCS#11 adapter (`cryptoki`) |
| [`trusty-cryptoprov-aws-kms`](./trusty-cryptoprov-aws-kms/) | AWS KMS stub (`NotImplemented`) |
| [`trusty-cryptoprov-gcp-kms`](./trusty-cryptoprov-gcp-kms/) | GCP KMS stub (`NotImplemented`) |

```text
trusty-cryptoprov (facade)
├── trusty-cryptoprov-core
├── trusty-cryptoprov-inmem      [feature: inmem]
├── trusty-cryptoprov-pkcs11     [feature: pkcs11]
│   └── trusty-crypto11
├── trusty-cryptoprov-aws-kms    [feature: aws-kms]
└── trusty-cryptoprov-gcp-kms    [feature: gcp-kms]
```

## Quick start

Add the facade and enable the providers you need:

```toml
[dependencies]
trusty-cryptoprov = { path = "trusty-cryptoprov", features = ["inmem", "pkcs11"] }
```

```rust,no_run
use trusty_cryptoprov::{KeyPurpose, ProviderRegistry};

fn main() -> Result<(), trusty_cryptoprov::Error> {
    let mut registry = ProviderRegistry::new();
    registry.register("inmem", trusty_cryptoprov_inmem::loader())?;
    let crypto = registry.load("", &[])?;

    let key = crypto
        .default_provider()
        .generate_rsa_key("app-key", 2048, KeyPurpose::Signing)?;
    let _id = key.key_id().expect("generated key has an id");
    Ok(())
}
```

For SoftHSM/PKCS#11, register `"pkcs11"` and pass a token config path to
`registry.load` / `load_provider`. See [`trusty-crypto11`](./trusty-crypto11/)
and [`trusty-cryptoprov-pkcs11`](./trusty-cryptoprov-pkcs11/).

## SoftHSM for integration tests

```bash
make hsmconfig
# writes /tmp/trusty11/softhsm_unittest.json
export TRUSTY_SOFTHSM_CONFIG=/tmp/trusty11/softhsm_unittest.json
cargo test -p trusty-crypto11 -- --ignored
cargo test -p trusty-cryptoprov --features pkcs11
```

## License

MIT — see [LICENSE](./LICENSE).
