# trusty-cryptoprov-aws-kms

**Stub provider** — every key operation returns
[`Error::NotImplemented`](../trusty-cryptoprov-core/).

Depends only on [`trusty-cryptoprov-core`](../trusty-cryptoprov-core/) (no
`aws-sdk-kms` yet). Exists so application and config plumbing for kind
`"aws-kms"` can be written and tested ahead of a real integration.

Enable via feature `aws-kms` on [`trusty-cryptoprov`](../trusty-cryptoprov/).

## Register

```rust,no_run
use trusty_cryptoprov_core::{KeyPurpose, ProviderRegistry};

let mut registry = ProviderRegistry::new();
registry.register("aws-kms", trusty_cryptoprov_aws_kms::loader())?;

// Config must set kind to "aws-kms". All generate/get/export calls fail with
// Error::NotImplemented until a real AWS KMS backend is implemented.
let _ = KeyPurpose::Signing;
# Ok::<(), trusty_cryptoprov_core::Error>(())
```

Example config shape:

```json
{
  "kind": "aws-kms",
  "manufacturer": "aws-kms",
  "model": "",
  "attributes": "region=us-east-1"
}
```

## Types

| Type | Role |
|------|------|
| [`AwsKmsProvider`](https://docs.rs/trusty-cryptoprov-aws-kms) | Stub `Provider` |
| [`AwsKmsConfig`](https://docs.rs/trusty-cryptoprov-aws-kms) | Placeholder (`region`, `key_id`) — not yet wired to `TokenConfig` |
| `loader()` | `ProviderLoader` for `"aws-kms"` |

## License

MIT
