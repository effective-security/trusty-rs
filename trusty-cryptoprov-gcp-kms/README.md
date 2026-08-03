# trusty-cryptoprov-gcp-kms

**Stub provider** — every key operation returns
[`Error::NotImplemented`](../trusty-cryptoprov-core/).

Depends only on [`trusty-cryptoprov-core`](../trusty-cryptoprov-core/) (no
GCP KMS client yet). Exists so application and config plumbing for kind
`"gcp-kms"` can be written and tested ahead of a real integration.

Enable via feature `gcp-kms` on [`trusty-cryptoprov`](../trusty-cryptoprov/).

## Register

```rust,no_run
use trusty_cryptoprov_core::{KeyPurpose, ProviderRegistry};

let mut registry = ProviderRegistry::new();
registry.register("gcp-kms", trusty_cryptoprov_gcp_kms::loader())?;

// Config must set kind to "gcp-kms". All generate/get/export calls fail with
// Error::NotImplemented until a real GCP KMS backend is implemented.
let _ = KeyPurpose::Signing;
# Ok::<(), trusty_cryptoprov_core::Error>(())
```

Example config shape:

```json
{
  "kind": "gcp-kms",
  "manufacturer": "gcp-kms",
  "model": "",
  "attributes": "project=my-project"
}
```

## Types

| Type | Role |
|------|------|
| [`GcpKmsProvider`](https://docs.rs/trusty-cryptoprov-gcp-kms) | Stub `Provider` |
| [`GcpKmsConfig`](https://docs.rs/trusty-cryptoprov-gcp-kms) | Placeholder (`project`, `key_name`) — not yet wired to `TokenConfig` |
| `loader()` | `ProviderLoader` for `"gcp-kms"` |

## License

MIT
