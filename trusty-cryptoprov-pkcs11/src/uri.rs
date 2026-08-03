//! PKCS#11 URI parsing (token config and private-key URIs).

use secrecy::SecretString;
use std::fs;
use trusty_cryptoprov_core::{Error, FileTokenConfig, Result};
use url::Url;

/// Parsed PKCS#11 private-key URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKeyUri {
    /// Token manufacturer.
    pub manufacturer: String,
    /// Model.
    pub model: String,
    /// Token serial (required).
    pub token_serial: String,
    /// Token label.
    pub token_label: String,
    /// Key ID (required).
    pub id: String,
}

impl PrivateKeyUri {
    /// Token manufacturer.
    #[must_use]
    pub fn manufacturer(&self) -> &str {
        &self.manufacturer
    }
    /// Model.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }
    /// Token serial.
    #[must_use]
    pub fn token_serial(&self) -> &str {
        &self.token_serial
    }
    /// Token label.
    #[must_use]
    pub fn token_label(&self) -> &str {
        &self.token_label
    }
    /// Key ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Parse a PKCS#11 URI into token configuration.
///
/// Opaque attributes use `;` separators, rewritten to `&` then query-parsed.
/// Scheme must be `pkcs11`. Optional `pin-source` with `file:` scheme loads PIN.
///
/// # Errors
///
/// Returns [`Error::InvalidUri`] (or wrapped parse errors) on failure.
pub fn parse_token_uri(uri: &str) -> Result<FileTokenConfig> {
    let u = Url::parse(uri).map_err(|e| Error::Config(format!("invalid URI: {uri}: {e}")))?;
    if u.scheme() != "pkcs11" {
        return Err(Error::InvalidUri.context(uri.to_string()));
    }

    let opaque = opaque_part(&u);
    let attrs = parse_pkcs11_attrs(&opaque);

    let mut c = FileTokenConfig::default();
    set_if_present(&attrs, "manufacturer", &mut c.manufacturer);
    set_if_present(&attrs, "model", &mut c.model);
    set_if_present(&attrs, "module-name", &mut c.path);
    set_if_present(&attrs, "module-path", &mut c.path);
    set_if_present(&attrs, "token", &mut c.token_label);
    set_if_present(&attrs, "serial", &mut c.token_serial);

    let mut pin_value = String::new();
    set_if_present(&attrs, "pin-value", &mut pin_value);
    if !pin_value.is_empty() {
        c.pin = SecretString::from(pin_value);
    }

    let mut pin_source_uri = String::new();
    set_if_present(&attrs, "pin-source", &mut pin_source_uri);
    if pin_source_uri.is_empty() {
        trim_manufacturer_model(&mut c);
        return Ok(c);
    }

    let pin_uri = Url::parse(&pin_source_uri).ok();
    let pin_path = pin_uri.as_ref().and_then(|p| {
        if p.scheme() != "file" {
            return None;
        }
        let path = p.path();
        if path.is_empty() { None } else { Some(path.to_string()) }
    });

    let Some(pin_path) = pin_path else {
        return Err(Error::InvalidUri.context(uri.to_string()));
    };

    let pin = fs::read(&pin_path).map_err(|_| Error::InvalidUri.context(uri.to_string()))?;
    c.pin = SecretString::from(String::from_utf8_lossy(&pin).trim());
    trim_manufacturer_model(&mut c);
    Ok(c)
}

/// Parse a PKCS#11 URI for a private-key object.
///
/// Requires `type=private`, non-empty `serial` and `id`.
///
/// # Errors
///
/// Returns [`Error::InvalidUri`] or [`Error::InvalidPrivateKeyUri`].
pub fn parse_private_key_uri(uri: &str) -> Result<PrivateKeyUri> {
    let u = Url::parse(uri).map_err(|e| Error::Config(format!("invalid URI: {uri}: {e}")))?;
    if u.scheme() != "pkcs11" {
        return Err(Error::InvalidUri.context(uri.to_string()));
    }

    let opaque = opaque_part(&u);
    let attrs = parse_pkcs11_attrs(&opaque);

    let mut c = PrivateKeyUri {
        manufacturer: String::new(),
        model: String::new(),
        token_serial: String::new(),
        token_label: String::new(),
        id: String::new(),
    };
    set_if_present(&attrs, "manufacturer", &mut c.manufacturer);
    set_if_present(&attrs, "model", &mut c.model);
    set_if_present(&attrs, "token", &mut c.token_label);
    set_if_present(&attrs, "serial", &mut c.token_serial);
    set_if_present(&attrs, "id", &mut c.id);

    let mut objtype = String::new();
    set_if_present(&attrs, "type", &mut objtype);
    if objtype != "private" || c.token_serial.is_empty() || c.id.is_empty() {
        return Err(Error::InvalidPrivateKeyUri.context(uri.to_string()));
    }

    c.manufacturer = trim_nul_and_space(&c.manufacturer);
    c.model = c.model.trim().to_string();
    Ok(c)
}

fn opaque_part(u: &Url) -> String {
    // Rust `url`: cannot-be-a-base URLs store the opaque part in `path()`.
    if u.cannot_be_a_base() {
        u.path().to_string()
    } else if !u.path().is_empty() {
        u.path().trim_start_matches('/').to_string()
    } else {
        String::new()
    }
}

fn parse_pkcs11_attrs(opaque: &str) -> Vec<(String, String)> {
    // `;` → `&` then percent-decode as `application/x-www-form-urlencoded` pairs.
    let rewritten = opaque.replace(';', "&");
    url::form_urlencoded::parse(rewritten.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn set_if_present(attrs: &[(String, String)], key: &str, target: &mut String) {
    if let Some((_, v)) = attrs.iter().find(|(k, _)| k == key)
        && !v.is_empty()
    {
        *target = v.clone();
    }
}

fn trim_nul_and_space(s: &str) -> String {
    s.trim_end_matches('\0').trim().to_string()
}

fn trim_manufacturer_model(c: &mut FileTokenConfig) {
    c.manufacturer = trim_nul_and_space(&c.manufacturer);
    c.model = c.model.trim().to_string();
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusty_cryptoprov_core::TokenConfig;

    #[test]
    fn parse_token_uri_happy() {
        let c = parse_token_uri(
            "pkcs11:manufacturer=testprov;model=inmem;serial=20764350726;token=inmemoryRSA",
        )
        .unwrap();
        assert_eq!(c.manufacturer(), "testprov");
        assert_eq!(c.model(), "inmem");
        assert_eq!(c.token_serial(), "20764350726");
        assert_eq!(c.token_label(), "inmemoryRSA");
    }

    #[test]
    fn parse_private_key_uri_happy() {
        let uri = parse_private_key_uri(
            "pkcs11:manufacturer=testprov;model=inmem;serial=20764350726;token=inmemoryRSA;id=123;type=private",
        )
        .unwrap();
        assert_eq!(uri.id(), "123");
        assert_eq!(uri.manufacturer(), "testprov");
        assert_eq!(uri.model(), "inmem");
        assert_eq!(uri.token_serial(), "20764350726");
        assert_eq!(uri.token_label(), "inmemoryRSA");
    }

    #[test]
    fn parse_private_key_uri_requires_fields() {
        let err = parse_private_key_uri(
            "pkcs11:manufacturer=testprov;model=inmem;serial=20764350726;token=inmemoryRSA;id=123",
        )
        .unwrap_err();
        assert!(matches!(err.root_cause(), Error::InvalidPrivateKeyUri));
    }

    #[test]
    fn wrong_scheme() {
        assert!(matches!(
            parse_token_uri("https://example.com").unwrap_err().root_cause(),
            Error::InvalidUri
        ));
    }
}
