# trusty-cryptoprov-inmem

Software RSA/ECDSA signing provider for Trusty.

Depends on [`trusty-cryptoprov-core`](../trusty-cryptoprov-core/) plus the
`rsa` / `p256` / `p384` / `p521` crates — no PKCS#11 or cloud KMS SDK.
Re-exported by [`trusty-cryptoprov`](../trusty-cryptoprov/) when feature
`inmem` is enabled.

## When to use

- Unit tests and local development without an HSM
- PEM-based signing keys in application code
- Default provider when no token config path is supplied

For production HSM-backed keys, use
[`trusty-cryptoprov-pkcs11`](../trusty-cryptoprov-pkcs11/).

## Register

```rust,no_run
use trusty_cryptoprov_core::ProviderRegistry;

let mut registry = ProviderRegistry::new();
registry.register("inmem", trusty_cryptoprov_inmem::loader())?;
let crypto = registry.load("", &[])?;
# Ok::<(), trusty_cryptoprov_core::Error>(())
```

[`PROVIDER_NAME`](https://docs.rs/trusty-cryptoprov-inmem) is `"inmem"`.

## Generate keys

```rust,no_run
use trusty_cryptoprov_core::{KeyGenerator, KeyPurpose, NamedCurve};
use trusty_cryptoprov_inmem::InmemProvider;

let provider = InmemProvider::new();
let rsa = provider.generate_rsa_key("label", 2048, KeyPurpose::Signing)?;
let id = rsa.key_id().unwrap().to_string();
let (_uri, pem) = provider.export_key(&id)?;
assert!(!pem.is_empty()); // PEM-encoded private key

let ec = provider.generate_ecdsa_key("ec", NamedCurve::P256)?;
assert_eq!(ec.label(), Some("ec"));
# Ok::<(), trusty_cryptoprov_core::Error>(())
```

## Parse PEM without a provider

```rust,no_run
use trusty_cryptoprov_inmem::parse_private_key_pem;

let signer = parse_private_key_pem(br"-----BEGIN PRIVATE KEY-----
...")?;
let _ = signer;
# Ok::<(), trusty_cryptoprov_core::Error>(())
```

Encrypted PEM is not supported in v1 (`Error::EncryptedPemUnsupported`).

## Limits

- Does **not** implement [`KeyManager`](../trusty-cryptoprov-core/) (no token
  enumeration)
- NIST P-224 is not supported for software ECDSA (use PKCS#11 if required)
- ECDSA signatures are ASN.1 DER-encoded `R`/`S`

## License

MIT
