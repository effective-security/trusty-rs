# trusty-cryptoprov-aws-kms

AWS KMS signing provider for
[`trusty-cryptoprov-core`](../trusty-cryptoprov-core/), ported from
`go-source/cryptoprov/awskmscrypto`. Backed by `aws-sdk-kms` / `aws-config`.

`trusty-cryptoprov-core`'s `Provider`/`KeyGenerator`/`Signer` traits are
synchronous; the AWS SDK is async. [`AwsKmsProvider`] owns a small internal
Tokio runtime and bridges every call with `block_on`, so callers never see
`async`.

Enable via feature `aws-kms` on [`trusty-cryptoprov`](../trusty-cryptoprov/).

## Register

```rust,no_run
use trusty_cryptoprov_core::ProviderRegistry;

let mut registry = ProviderRegistry::new();
registry.register("aws-kms", trusty_cryptoprov_aws_kms::loader())?;
# Ok::<(), trusty_cryptoprov_core::Error>(())
```

Credentials and region come from the standard AWS SDK default chain (env
vars, shared config/credentials files, IMDS, ...), optionally overridden by
`Region=`/`Endpoint=` entries in the config's `attributes` string.

Example config shape:

```json
{
  "kind": "aws-kms",
  "manufacturer": "aws-kms",
  "model": "",
  "attributes": "Region=us-east-1,Endpoint=http://localhost:4566"
}
```

## Types

| Type | Role |
|------|------|
| [`AwsKmsProvider`](https://docs.rs/trusty-cryptoprov-aws-kms) | `Provider` + `KeyManager` backed by AWS KMS |
| [`AwsKmsSigner`](https://docs.rs/trusty-cryptoprov-aws-kms) | `Signer` that calls KMS `Sign` for every operation |
| `loader()` | `ProviderLoader` for `"aws-kms"` |

## Notes

- RSA key generation supports 2048/3072/4096 bits; ECDSA supports P-256/384/521
  (AWS KMS has no P-224 key spec).
- `export_key`/`FindKeyPairOnSlot` mirror the Go provider: `export_key`
  returns a `pkcs11:` URI (KMS never returns private key bytes);
  `find_key_pair_on_slot` is unsupported by AWS KMS.
- Unit tests cover the pure logic (attribute parsing, alias sanitization,
  key-spec/algorithm mapping); there is no mocked-network integration test
  in this crate, so exercising real `CreateKey`/`Sign` calls requires AWS
  credentials (or a KMS-compatible endpoint via the `Endpoint` attribute).

## License

MIT
