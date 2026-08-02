# trusty-crypto11

PKCS#11 HSM adapter.

Loads SoftHSM/HSM token configs,
pools RW sessions per slot, and exposes RSA/ECDSA key lifecycle, sign/decrypt, RNG, and
enumeration APIs suitable for later `trusty-cryptoprov` registration.

SoftHSM integration tests are `#[ignore]` unless
`TRUSTY_SOFTHSM_CONFIG` or `/tmp/trusty11/softhsm_unittest.json` is present.
