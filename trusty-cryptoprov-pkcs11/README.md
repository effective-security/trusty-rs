# trusty-cryptoprov-pkcs11

PKCS#11 HSM provider for Trusty, wrapping [`trusty-crypto11`](../trusty-crypto11/).

Implements [`Provider`](../trusty-cryptoprov-core/), [`KeyGenerator`](../trusty-cryptoprov-core/),
and [`KeyManager`](../trusty-cryptoprov-core/) on top of SoftHSM or hardware
tokens. Enable via feature `pkcs11` on
[`trusty-cryptoprov`](../trusty-cryptoprov/).

## Token config

```json
{
  "kind": "pkcs11",
  "manufacturer": "SoftHSM",
  "model": "SoftHSM v2",
  "path": "/usr/lib/softhsm/libsofthsm2.so",
  "token_label": "MyToken",
  "token_serial": "",
  "pin": "file:/path/to/pin.txt",
  "attributes": ""
}
```

`pin` may be a literal PIN or `file:` plus a path (contents are loaded and
trailing newlines trimmed). For SoftHSM setup helpers, see the workspace
`make hsmconfig` target and [`trusty-crypto11`](../trusty-crypto11/).

## Register and load

```rust,no_run
use trusty_cryptoprov_core::ProviderRegistry;

let mut registry = ProviderRegistry::new();
registry.register("pkcs11", trusty_cryptoprov_pkcs11::loader())?;
let crypto = registry.load("softhsm.json", &[])?;
let provider = crypto.default_provider();
assert!(provider.as_key_manager().is_some());
# Ok::<(), trusty_cryptoprov_core::Error>(())
```

Or load a single provider:

```rust,no_run
use trusty_cryptoprov_core::ProviderRegistry;

let mut registry = ProviderRegistry::new();
registry.register("pkcs11", trusty_cryptoprov_pkcs11::loader())?;
let provider = registry.load_provider("softhsm.json")?;
# Ok::<(), trusty_cryptoprov_core::Error>(())
```

## Key management

```rust,no_run
# use trusty_cryptoprov_core::{KeyManager, KeyPurpose, Provider, ProviderRegistry};
# let mut registry = ProviderRegistry::new();
# registry.register("pkcs11", trusty_cryptoprov_pkcs11::loader())?;
# let crypto = registry.load("softhsm.json", &[])?;
let provider = crypto.default_provider();
let km = provider.as_key_manager().expect("pkcs11");
let tokens = km.enum_tokens(false)?;
let keys = km.enum_keys(tokens[0].slot_id, "")?;
# let _ = (KeyPurpose::Signing, keys);
# Ok::<(), trusty_cryptoprov_core::Error>(())
```

## PKCS#11 private-key URI

```rust,no_run
use trusty_cryptoprov_pkcs11::parse_private_key_uri;

let uri = parse_private_key_uri(
    "pkcs11:manufacturer=SoftHSM;model=SoftHSM%20v2;serial=01;id=%01%02;type=private",
)?;
assert_eq!(uri.manufacturer(), "SoftHSM");
# Ok::<(), trusty_cryptoprov_core::Error>(())
```

With the facade's `CryptoExt::load_private_key`, a `pkcs11:` URI string
resolves to the matching registered provider and a [`Pkcs11Signer`].

## Types

| Type | Role |
|------|------|
| [`Pkcs11Provider`](https://docs.rs/trusty-cryptoprov-pkcs11) | `Provider` + `KeyManager` |
| [`Pkcs11Signer`](https://docs.rs/trusty-cryptoprov-pkcs11) | Token-backed `Signer` |
| [`PrivateKeyUri`](https://docs.rs/trusty-cryptoprov-pkcs11) | Parsed `pkcs11:` URI |
| `loader()` | `ProviderLoader` for `"pkcs11"` |

## License

MIT
