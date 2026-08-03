# trusty-cryptoprov-core

Provider-agnostic traits, types, token config loading, and errors for the
Trusty crypto provider stack.

This crate has **no** PKCS#11 or cloud KMS SDK dependencies. Provider crates
implement its traits; the [`trusty-cryptoprov`](../trusty-cryptoprov/) facade
re-exports these types behind Cargo features.

## Key types

| Type | Purpose |
|------|---------|
| [`ProviderRegistry`](https://docs.rs/trusty-cryptoprov-core) | Register loaders by `kind` (`"pkcs11"`, `"inmem"`, …) |
| [`Crypto`](https://docs.rs/trusty-cryptoprov-core) | Multi-provider lookup by `(manufacturer, model)` |
| [`Provider`](https://docs.rs/trusty-cryptoprov-core) / [`KeyGenerator`](https://docs.rs/trusty-cryptoprov-core) | Generate, get, and export keys |
| [`KeyManager`](https://docs.rs/trusty-cryptoprov-core) | Optional token/key enumeration (PKCS#11) |
| [`Signer`](https://docs.rs/trusty-cryptoprov-core) | Object-safe signing |
| [`TokenConfig`](https://docs.rs/trusty-cryptoprov-core) / [`FileTokenConfig`](https://docs.rs/trusty-cryptoprov-core) | Token config accessors and serde shape |
| [`Error`](https://docs.rs/trusty-cryptoprov-core) | Shared error type |

## `kind` vs `manufacturer`

- **`kind`** — registry routing key: which loader builds the provider.
- **`manufacturer` / `model`** — backend identity used by `Crypto::find_provider`
  (for example the PKCS#11 token manufacturer string).

## Load token config

JSON and YAML are supported. A PIN value starting with `file:` is resolved to
the file contents (trailing `\r`/`\n` trimmed):

```rust,no_run
use trusty_cryptoprov_core::{TokenConfig, load_token_config};

let cfg = load_token_config("token.json")?;
assert_eq!(cfg.kind(), "pkcs11");
# Ok::<(), trusty_cryptoprov_core::Error>(())
```

Example JSON:

```json
{
  "kind": "pkcs11",
  "manufacturer": "SoftHSM",
  "model": "SoftHSM v2",
  "path": "/usr/lib/softhsm/libsofthsm2.so",
  "token_serial": "",
  "token_label": "MyToken",
  "pin": "file:pin.txt",
  "attributes": ""
}
```

## Register and load a provider

```rust,no_run
use trusty_cryptoprov_core::ProviderRegistry;
use std::sync::Arc;

// `loader` comes from a provider crate, e.g. trusty_cryptoprov_inmem::loader()
fn example(loader: trusty_cryptoprov_core::ProviderLoader) -> trusty_cryptoprov_core::Result<()> {
    let mut registry = ProviderRegistry::new();
    registry.register("inmem", loader)?;
    let crypto = registry.load("", &[])?;
    let _ = crypto.default_provider();
    Ok(())
}
```

## Sync helpers

The [`sync`](src/sync.rs) module provides small utilities for sharing
provider state across threads without forcing every provider to invent its
own locking pattern.

## License

MIT
