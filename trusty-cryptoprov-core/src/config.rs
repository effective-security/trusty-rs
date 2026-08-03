//! Token configuration load (JSON/YAML) and `file:` PIN resolution.

use crate::error::{Error, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::debug;
use zeroize::Zeroize;

/// Canonical token configuration accessors.
pub trait TokenConfig: Send + Sync {
    /// Provider *kind* — the [`crate::registry::ProviderRegistry`] routing
    /// key (`"pkcs11"`, `"inmem"`, `"aws-kms"`, ...). Distinct from
    /// [`Self::manufacturer`]: `kind` says which provider crate builds this
    /// config into a `Provider`; `manufacturer` is that provider's own
    /// backend/token identity (for example the HSM manufacturer string).
    fn kind(&self) -> &str;
    /// Manufacturer name (real token/backend identity — e.g. reported by a
    /// PKCS#11 token, or embedded in a `pkcs11:` URI's `manufacturer=`
    /// attribute — not a routing key; see [`Self::kind`]).
    fn manufacturer(&self) -> &str;
    /// Device / provider model.
    fn model(&self) -> &str;
    /// Full path to PKCS#11 library, or unused for inmem.
    fn path(&self) -> &str;
    /// Token serial number.
    fn token_serial(&self) -> &str;
    /// Token label.
    fn token_label(&self) -> &str;
    /// PIN / secret (`file:` already resolved when loaded from disk).
    fn pin(&self) -> &SecretString;
    /// Comma-separated `key=value` attributes.
    fn attributes(&self) -> &str;
}

/// Serde shape shared by JSON and YAML config files (same field names in
/// both — no PascalCase/snake_case aliasing).
///
/// Fields are `pub`: the [`TokenConfig`] trait is the recommended accessor
/// for provider implementations that only need to *read* config (so a
/// third-party provider crate isn't coupled to this concrete shape), but
/// tests and callers that build configs programmatically (rather than by
/// deserializing a file) can construct this struct directly.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct FileTokenConfig {
    /// Provider kind (registry routing key). See [`TokenConfig::kind`].
    #[serde(default)]
    pub kind: String,
    /// Manufacturer (real token/backend identity). See
    /// [`TokenConfig::manufacturer`].
    #[serde(default)]
    pub manufacturer: String,
    /// Device / provider model string.
    #[serde(default)]
    pub model: String,
    /// Path to the PKCS#11 shared library (unused for inmem / KMS stubs).
    #[serde(default)]
    pub path: String,
    /// Token serial number used when selecting a PKCS#11 slot.
    #[serde(default)]
    pub token_serial: String,
    /// Token label used when selecting a PKCS#11 slot.
    #[serde(default)]
    pub token_label: String,
    /// PIN or passphrase; may start with `file:` before load-time resolution.
    #[serde(default)]
    pub pin: SecretString,
    /// Comma-separated `key=value` attributes for provider-specific options.
    #[serde(default)]
    pub attributes: String,
}

impl TokenConfig for FileTokenConfig {
    fn kind(&self) -> &str {
        &self.kind
    }
    fn manufacturer(&self) -> &str {
        &self.manufacturer
    }
    fn model(&self) -> &str {
        &self.model
    }
    fn path(&self) -> &str {
        &self.path
    }
    fn token_serial(&self) -> &str {
        &self.token_serial
    }
    fn token_label(&self) -> &str {
        &self.token_label
    }
    fn pin(&self) -> &SecretString {
        &self.pin
    }
    fn attributes(&self) -> &str {
        &self.attributes
    }
}

/// Load token config from a path, or return a synthetic inmem config.
///
/// - `""` or `"inmem"` → `{ kind: "inmem", manufacturer: "inmem" }` (no file read).
/// - `.json` suffix → JSON decode.
/// - any other suffix → YAML decode.
///
/// If `pin` starts with `file:`, the prefix is stripped and the remainder is
/// resolved against `""`, CWD, then the config file's directory.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file (or PIN file) cannot be read, or
/// [`Error::Config`] if JSON/YAML cannot be parsed.
pub fn load_token_config(filename: &str) -> Result<FileTokenConfig> {
    if filename.is_empty() || filename == "inmem" {
        return Ok(FileTokenConfig {
            kind: "inmem".to_string(),
            manufacturer: "inmem".to_string(),
            ..Default::default()
        });
    }

    let path = Path::new(filename);
    let data = fs::read_to_string(path)?;
    let mut cfg: FileTokenConfig = if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("json"))
    {
        serde_json::from_str(&data)
            .map_err(|e| Error::Config(format!("failed to decode file: {filename}: {e}")))?
    } else {
        serde_yaml::from_str(&data)
            .map_err(|e| Error::Config(format!("failed to decode file: {filename}: {e}")))?
    };

    if let Some(pin_path) = cfg.pin.expose_secret().strip_prefix("file:") {
        let pin_path = pin_path.to_string();
        // `Path::exists()` already resolves a relative path against the process
        // CWD, so an explicit empty-base candidate would only ever duplicate the
        // `cwd` candidate below; two candidates fully cover the search.
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let config_dir = path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
        let folders = [cwd, config_dir];

        let mut resolved = pin_path.clone();
        let mut found = false;
        for folder in &folders {
            match resolve_path(&pin_path, folder) {
                Ok(p) => {
                    resolved = p;
                    found = true;
                    break;
                }
                Err(_) => {
                    // Expected control flow: most candidate base dirs miss before
                    // the right one is found. The final `fs::read` below reports
                    // failure if none of them resolved.
                    debug!(
                        reason = "resolve",
                        pinfile = %pin_path,
                        basedir = %folder.display()
                    );
                }
            }
        }

        if !found {
            // Last attempt: use as-is so the read error names the path.
            resolved = pin_path;
        }

        let mut bytes = fs::read(&resolved).map_err(|e| {
            Error::Io(e).context(format!("unable to load PIN for configuration: {filename}"))
        })?;
        let mut text = String::from_utf8_lossy(&bytes).into_owned();
        bytes.zeroize();
        // Prefer trimming trailing CR/LF only (usability); other whitespace kept.
        let trimmed = text.trim_end_matches(['\r', '\n']);
        cfg.pin = SecretString::from(trimmed);
        text.zeroize();
    }

    Ok(cfg)
}

/// Resolve `file` relative to `base_dir` (empty base = as-is / absolute).
fn resolve_path(file: &str, base_dir: &Path) -> Result<String> {
    if file.is_empty() {
        return Ok(file.to_string());
    }
    let candidate = if Path::new(file).is_absolute() || base_dir.as_os_str().is_empty() {
        PathBuf::from(file)
    } else {
        base_dir.join(file)
    };
    if !candidate.exists() {
        return Err(Error::Config(format!("not found: {}", candidate.display())));
    }
    Ok(candidate.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_shortcuts() {
        let c = load_token_config("").unwrap();
        assert_eq!(c.kind(), "inmem");
        assert_eq!(c.manufacturer(), "inmem");
        assert!(c.model().is_empty());

        let c = load_token_config("inmem").unwrap();
        assert_eq!(c.kind(), "inmem");
        assert_eq!(c.manufacturer(), "inmem");
    }

    #[test]
    fn file_pin_trims_trailing_newlines() {
        let dir = tempfile::tempdir().unwrap();
        let pin_path = dir.path().join("pin.txt");
        {
            use std::io::Write;
            let mut f = fs::File::create(&pin_path).unwrap();
            write!(f, "secret-pin\r\n").unwrap();
        }
        let cfg_path = dir.path().join("cfg.json");
        fs::write(&cfg_path, format!(r#"{{"kind":"inmem","pin":"file:{}"}}"#, pin_path.display()))
            .unwrap();

        let c = load_token_config(cfg_path.to_str().unwrap()).unwrap();
        assert_eq!(c.pin().expose_secret(), "secret-pin");
    }

    #[test]
    fn missing_file_is_io_error() {
        let err = load_token_config("missing-cryptoprov-config-xyz.json").unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }
}
