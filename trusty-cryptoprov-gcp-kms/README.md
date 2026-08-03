# trusty-cryptoprov-gcp-kms

GCP Cloud KMS signing provider for
[`trusty-cryptoprov-core`](../trusty-cryptoprov-core/), ported from
`go-source/cryptoprov/gcpkmscrypto`. Backed by `google-cloud-kms-v1`, the
official Google Cloud Rust client.

`trusty-cryptoprov-core`'s `Provider`/`KeyGenerator`/`Signer` traits are
synchronous; `google-cloud-kms-v1` is async. [`GcpKmsProvider`] owns a small
internal Tokio runtime and bridges every call with `block_on`, so callers
never see `async`.

Enable via feature `gcp-kms` on [`trusty-cryptoprov`](../trusty-cryptoprov/).

## Register

```rust,no_run
use trusty_cryptoprov_core::ProviderRegistry;

let mut registry = ProviderRegistry::new();
registry.register("gcp-kms", trusty_cryptoprov_gcp_kms::loader())?;
# Ok::<(), trusty_cryptoprov_core::Error>(())
```

Credentials come from Application Default Credentials. `Keyring=`/`Endpoint=`
entries in the config's `attributes` string select the key ring resource
name and (optionally) a non-default KMS endpoint.

Example config shape:

```json
{
  "kind": "gcp-kms",
  "manufacturer": "gcp-kms",
  "model": "",
  "attributes": "Keyring=projects/my-project/locations/us/keyRings/my-ring"
}
```

## Types

| Type | Role |
|------|------|
| [`GcpKmsProvider`](https://docs.rs/trusty-cryptoprov-gcp-kms) | `Provider` + `KeyManager` backed by GCP Cloud KMS |
| [`GcpKmsSigner`](https://docs.rs/trusty-cryptoprov-gcp-kms) | `Signer` that calls KMS `AsymmetricSign` for every operation |
| `loader()` | `ProviderLoader` for `"gcp-kms"` |

## Notes

- RSA key generation supports 2048/3072/4096-bit PKCS#1 keys (matching the Go
  provider); ECDSA supports P-256/P-384 (GCP KMS has no P-521 or P-224
  asymmetric-sign algorithm). Keys created outside this crate as RSA-PSS are
  still readable via `get_key`/`key_info`.
- Generated keys use `ProtectionLevel::Hsm`, matching the Go provider.
- `export_key`/`FindKeyPairOnSlot` mirror the Go provider: `export_key`
  returns a `pkcs11:` URI (KMS never returns private key bytes);
  `find_key_pair_on_slot` is unsupported by GCP KMS.
- Unit tests cover the pure logic (attribute parsing, key-id derivation,
  algorithm mapping); there is no mocked-network integration test in this
  crate, so exercising real `CreateCryptoKey`/`AsymmetricSign` calls requires
  GCP credentials and a key ring.

## License

MIT
