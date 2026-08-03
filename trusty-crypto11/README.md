# trusty-crypto11

PKCS#11 HSM adapter for SoftHSM and hardware tokens, built on
[`cryptoki`](https://crates.io/crates/cryptoki).

Provides token config loading, pooled read/write sessions, RSA/ECDSA key
lifecycle (generate, find, sign, decrypt, destroy), hardware RNG, and
token/key enumeration. Higher-level registration with Trusty uses
[`trusty-cryptoprov-pkcs11`](../trusty-cryptoprov-pkcs11/).

## Requirements

- A PKCS#11 shared library (for example SoftHSM 2: `libsofthsm2.so`)
- An initialized token with a known label and/or serial, plus a PIN

## Configuration

JSON accepts PascalCase or snake_case field names; YAML typically uses
snake_case. PIN may be a literal or `file:/path/to/pin` (file contents are
loaded; trailing `\r`/`\n` are trimmed).

### Example (`softhsm.json`)

```json
{
  "Manufacturer": "SoftHSM",
  "Model": "SoftHSM v2",
  "Path": "/usr/lib/softhsm/libsofthsm2.so",
  "TokenLabel": "trusty11_unittest",
  "Pin": "file:/home/user/softhsm2/pin.txt"
}
```

Equivalent snake_case:

```json
{
  "manufacturer": "SoftHSM",
  "model": "SoftHSM v2",
  "path": "/usr/lib/softhsm/libsofthsm2.so",
  "token_label": "trusty11_unittest",
  "pin": "1234"
}
```

Workspace helper to create a SoftHSM token and config:

```bash
make hsmconfig
# → /tmp/trusty11/softhsm_unittest.json
```

## Quick start

### Open from a config file

```rust,no_run
use trusty_crypto11::Pkcs11Lib;

let lib = Pkcs11Lib::from_config_file("softhsm.json")?;
# Ok::<(), trusty_crypto11::Error>(())
```

### Generate RSA, sign, find, destroy

```rust,no_run
use sha2::{Digest, Sha256};
use trusty_crypto11::{DigestAlgorithm, KeyPurpose, Pkcs11Lib, PrivateKey, RsaSignScheme};

let lib = Pkcs11Lib::from_config_file("softhsm.json")?;
let key = lib.generate_rsa_key("my-key", 2048, KeyPurpose::Signing)?;

let digest = Sha256::digest(b"message");
let sig = match &key.key {
    PrivateKey::Rsa(k) => k.sign(
        &digest,
        &RsaSignScheme::Pkcs1v15 {
            hash: DigestAlgorithm::Sha256,
        },
    )?,
    PrivateKey::Ecdsa(_) => unreachable!(),
};
assert!(!sig.is_empty());

let found = lib.get_key(&key.id)?;
let uri = lib.export_key(&key.id)?; // PKCS#11 URI only (keys are non-extractable)
let _ = (found, uri);

lib.destroy_key_pair_on_slot(lib.current_slot_id(), &key.id)?;
# Ok::<(), trusty_crypto11::Error>(())
```

Signing APIs take a **pre-computed digest**, not the raw message.

### Generate ECDSA (P-256) and sign

```rust,no_run
use sha2::{Digest, Sha256};
use trusty_crypto11::{NamedCurve, Pkcs11Lib, PrivateKey};

let lib = Pkcs11Lib::from_config_file("softhsm.json")?;
let key = lib.generate_ecdsa_key("ec-key", NamedCurve::P256)?;
let digest = Sha256::digest(b"message");
let der_sig = match &key.key {
    PrivateKey::Ecdsa(k) => k.sign(&digest)?,
    PrivateKey::Rsa(_) => unreachable!(),
};
assert!(!der_sig.is_empty()); // ASN.1 DER SEQUENCE of R and S
# Ok::<(), trusty_crypto11::Error>(())
```

### Enumerate tokens and keys

```rust,no_run
use trusty_crypto11::Pkcs11Lib;

let lib = Pkcs11Lib::from_config_file("softhsm.json")?;
let tokens = lib.enum_tokens(false)?;
let keys = lib.enum_keys(lib.current_slot_id(), "my-")?;
let info = lib.key_info(lib.current_slot_id(), &keys[0].id, true)?;
// info.public_key may contain PEM when include_public is true
let _ = (tokens, info);
# Ok::<(), trusty_crypto11::Error>(())
```

### Hardware RNG

```rust,no_run
use trusty_crypto11::Pkcs11Lib;

let lib = Pkcs11Lib::from_config_file("softhsm.json")?;
let mut buf = [0u8; 32];
lib.gen_random(&mut buf)?;
# Ok::<(), trusty_crypto11::Error>(())
```

### Lifecycle (`close` / `Drop`)

`Pkcs11Lib` is `Clone`. PKCS#11 `C_Finalize` is process-wide; `close()` only
finalizes when this handle is the last live clone. Otherwise it returns
`Err(self)` unchanged. Dropping the last clone always finalizes safely, so
calling `close()` is optional.

```rust,no_run
use trusty_crypto11::Pkcs11Lib;

let lib = Pkcs11Lib::from_config_file("softhsm.json")?;
let _ = lib.close();
# Ok::<(), trusty_crypto11::Error>(())
```

## Supported crypto

| Area | Details |
|------|---------|
| RSA | ≥ 2048 bits; PKCS#1 v1.5 and PSS sign; PKCS#1 v1.5 and OAEP decrypt |
| ECDSA | P-224, P-256, P-384, P-521; signatures returned as DER |
| Digests | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 |

Private keys generated through this crate are **non-extractable**;
[`export_key`](https://docs.rs/trusty-crypto11) returns a PKCS#11 URI only.

## Error handling

Fallible APIs return [`trusty_crypto11::Result`](https://docs.rs/trusty-crypto11).
See [`Error`](https://docs.rs/trusty-crypto11) for variants (`TokenNotFound`,
`KeyNotFound`, `Closed`, PKCS#11 failures, config/I/O, …).

## SoftHSM integration tests

Tests are skipped unless a config is available:

```bash
export TRUSTY_SOFTHSM_CONFIG=/tmp/trusty11/softhsm_unittest.json
# or rely on the default path written by `make hsmconfig`
cargo test -p trusty-crypto11 -- --ignored
```

## License

MIT
