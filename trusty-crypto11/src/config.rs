//! Token configuration load and PKCS#11 library initialization.

use crate::Pkcs11Lib;
use crate::error::{Error, Result};
use crate::sessions::SessionPools;
use crate::types::SlotTokenInfo;
use crate::util::tokens_info_with_ctx;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CryptokiError, RvError};
use cryptoki::session::UserType;
use secrecy::{ExposeSecret, SecretString, zeroize::Zeroize};
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tracing::debug;

/// Owned copy of token config fields stored on [`Pkcs11Lib`].
///
/// Not `PartialEq`/`Eq`: `pin` is a [`SecretString`], which deliberately
/// does not implement those traits.
#[derive(Debug, Clone)]
pub struct OwnedTokenConfig {
    /// Manufacturer name.
    pub manufacturer: String,
    /// Model name.
    pub model: String,
    /// Path to PKCS#11 library.
    pub path: String,
    /// Token serial.
    pub token_serial: String,
    /// Token label.
    pub token_label: String,
    /// Resolved PIN. `Debug`-redacted; use [`ExposeSecret::expose_secret`] to read it.
    pub pin: SecretString,
    /// Extra attributes string.
    pub attributes: String,
}

impl From<&FileTokenConfig> for OwnedTokenConfig {
    fn from(cfg: &FileTokenConfig) -> Self {
        Self {
            manufacturer: cfg.manufacturer.clone(),
            model: cfg.model.clone(),
            path: cfg.path.clone(),
            token_serial: cfg.token_serial.clone(),
            token_label: cfg.token_label.clone(),
            pin: cfg.pin.clone(),
            attributes: cfg.attributes.clone(),
        }
    }
}

impl From<FileTokenConfig> for OwnedTokenConfig {
    fn from(cfg: FileTokenConfig) -> Self {
        Self {
            manufacturer: cfg.manufacturer,
            model: cfg.model,
            path: cfg.path,
            token_serial: cfg.token_serial,
            token_label: cfg.token_label,
            pin: cfg.pin,
            attributes: cfg.attributes,
        }
    }
}

/// Serde shape compatible with Go JSON (PascalCase) and YAML (snake_case).
///
/// Like Go's `encoding/json` / yaml decode into a struct, missing string fields
/// default to empty (Go SoftHSM unit config often omits `Model`).
#[derive(Debug, Clone, Deserialize)]
pub struct FileTokenConfig {
    /// Manufacturer (`Manufacturer` / `manufacturer`).
    #[serde(default, alias = "Manufacturer")]
    pub manufacturer: String,
    /// Model (`Model` / `model`).
    #[serde(default, alias = "Model")]
    pub model: String,
    /// Library path (`Path` / `path`).
    #[serde(alias = "Path")]
    pub path: String,
    /// Token serial (`TokenSerial` / `token_serial`).
    #[serde(default, alias = "TokenSerial")]
    pub token_serial: String,
    /// Token label (`TokenLabel` / `token_label`).
    #[serde(default, alias = "TokenLabel")]
    pub token_label: String,
    /// PIN (`Pin` / `pin`), may start with `file:`. `Debug`-redacted; use
    /// [`ExposeSecret::expose_secret`] to read it.
    #[serde(default, alias = "Pin")]
    pub pin: SecretString,
    /// Attributes (`Attributes` / `attributes`).
    #[serde(default, alias = "Attributes")]
    pub attributes: String,
}

/// Resolve a `file:`-prefixed PIN using a true prefix strip (not Go `TrimLeft`).
///
/// Trailing `\r`/`\n` are trimmed from the file's contents (but not other
/// whitespace, to avoid altering intentional leading/trailing PIN
/// characters), matching the common convention for secret files (e.g.
/// Docker/K8s secrets, or a PIN file created with a plain `echo "1234" >
/// pinfile`, which appends a trailing newline).
///
/// # Examples
///
/// - `"file:/tmp/pin"` → read `/tmp/pin`
/// - `"file:file:/tmp/pin"` → read `file:/tmp/pin` (differs from Go charset trim)
///
/// # Errors
///
/// Returns [`Error::Io`] if `pin` is `file:`-prefixed and the referenced
/// file cannot be read.
pub fn resolve_pin_file_prefix(pin: &str) -> Result<SecretString> {
    if let Some(path) = pin.strip_prefix("file:") {
        let mut bytes = fs::read(path)?;
        let mut text = String::from_utf8_lossy(&bytes).into_owned();
        bytes.zeroize();
        let trimmed = text.trim_end_matches(['\r', '\n']);
        let secret = SecretString::from(trimmed);
        text.zeroize();
        Ok(secret)
    } else {
        Ok(SecretString::from(pin))
    }
}

/// Load token config from JSON (`.json` suffix) or YAML (any other suffix).
///
/// If `pin` starts with `file:`, the PIN is replaced with the file contents
/// using [`resolve_pin_file_prefix`].
///
/// # Errors
///
/// Returns [`Error::Io`] if `path` cannot be read (or its `file:`-prefixed
/// PIN cannot be read), or [`Error::Config`] if the contents cannot be
/// parsed as JSON/YAML.
pub fn load_token_config(path: impl AsRef<Path>) -> Result<FileTokenConfig> {
    let path = path.as_ref();
    let data = fs::read_to_string(path)?;
    let mut cfg: FileTokenConfig = if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("json"))
    {
        serde_json::from_str(&data).map_err(|e| Error::Config(e.to_string()))?
    } else {
        serde_yaml::from_str(&data).map_err(|e| Error::Config(e.to_string()))?
    };
    cfg.pin = resolve_pin_file_prefix(cfg.pin.expose_secret())?;
    Ok(cfg)
}

/// Open PKCS#11, select token, login if required, and seed the session pool.
///
/// # Errors
///
/// Returns [`Error::CannotOpenPkcs11`] if the shared library at
/// `cfg.path` cannot be loaded, [`Error::TokenNotFound`] if no slot's
/// serial or label matches `cfg`, or [`Error::Pkcs11`] for any other
/// initialize/login failure.
pub fn init(cfg: impl Into<OwnedTokenConfig>) -> Result<Pkcs11Lib> {
    let cfg: OwnedTokenConfig = cfg.into();
    let ctx = Pkcs11::new(&cfg.path).map_err(|e| match e {
        CryptokiError::LibraryLoading(_) => Error::CannotOpenPkcs11 { path: cfg.path.clone() },
        other => Error::from(other).context(format!("open PKCS#11 library: {}", cfg.path)),
    })?;

    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) => {}
        Err(CryptokiError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {
            debug!(state = "initialize", result = "already_initialized");
        }
        Err(e) => {
            return Err(Error::from(e).context(format!("initialize PKCS#11 library: {}", cfg.path)));
        }
    }

    let slots = tokens_info_with_ctx(&ctx).map_err(|e| e.context("TokensInfo failed"))?;
    let mut selected: Option<SlotTokenInfo> = None;
    for slot in &slots {
        debug!(
            state = "search",
            slot = slot.id,
            serial = %slot.serial,
            label = %slot.label
        );
        if slot.serial == cfg.token_serial || slot.label == cfg.token_label {
            debug!(
                state = "found",
                slot = slot.id,
                serial = %slot.serial,
                label = %slot.label
            );
            selected = Some(slot.clone());
            break;
        }
    }
    let slot_info = selected.ok_or(Error::TokenNotFound)?;
    let login_required = slot_info.login_required;
    let slot = slot_info.slot()?;

    let pools = SessionPools::new();
    pools.setup(slot_info.id);

    let lib = Pkcs11Lib {
        inner: Arc::new(crate::Pkcs11LibInner {
            ctx: Mutex::new(Some(ctx)),
            config: cfg,
            slot: slot_info,
            pools,
            closed: AtomicBool::new(false),
        }),
    };

    lib.with_session(slot, |session| {
        if login_required {
            let pin = lib.inner.config.pin.clone();
            match session.login(UserType::User, Some(&pin)) {
                Ok(()) => Ok(()),
                Err(CryptokiError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {
                    debug!(state = "login", result = "already_logged_in");
                    Ok(())
                }
                Err(e) => Err(Error::from(e).context("login into PKCS#11 token")),
            }
        } else {
            Ok(())
        }
    })
    .map_err(|e| e.context("open PKCS#11 session"))?;

    Ok(lib)
}

/// Load config from `path` and [`init`].
///
/// Unlike the Go comment, there is no `CRYPTO11_CONFIG_PATH` override.
///
/// # Errors
///
/// Returns [`Error::Io`]/[`Error::Config`] from [`load_token_config`], or
/// any error from [`init`] once the config is loaded.
pub fn configure_from_file(path: impl AsRef<Path>) -> Result<Pkcs11Lib> {
    let path_ref = path.as_ref();
    let cfg = load_token_config(path_ref)
        .map_err(|e| e.context(format!("load p11 config: {:?}", path_ref)))?;
    init(cfg).map_err(|e| e.context(format!("initialize p11 config: {:?}", path_ref)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn load_json_pascal_case() {
        let mut f = NamedTempFile::with_suffix(".json").unwrap();
        write!(
            f,
            r#"{{
                "Manufacturer": "SoftHSM",
                "Model": "SoftHSM v2",
                "Path": "/usr/lib/softhsm/libsofthsm2.so",
                "TokenSerial": "123",
                "TokenLabel": "test",
                "Pin": "1234",
                "Attributes": "ServiceName=x"
            }}"#
        )
        .unwrap();
        let cfg = load_token_config(f.path()).unwrap();
        assert_eq!(cfg.manufacturer, "SoftHSM");
        assert_eq!(cfg.model, "SoftHSM v2");
        assert_eq!(cfg.path, "/usr/lib/softhsm/libsofthsm2.so");
        assert_eq!(cfg.token_serial, "123");
        assert_eq!(cfg.token_label, "test");
        assert_eq!(cfg.pin.expose_secret(), "1234");
        assert_eq!(cfg.attributes, "ServiceName=x");
    }

    #[test]
    fn load_yaml_snake_case() {
        let mut f = NamedTempFile::with_suffix(".yaml").unwrap();
        write!(
            f,
            r#"
manufacturer: SoftHSM
model: SoftHSM v2
path: /usr/lib/softhsm/libsofthsm2.so
token_serial: "123"
token_label: test
pin: "5678"
attributes: "UserName=y"
"#
        )
        .unwrap();
        let cfg = load_token_config(f.path()).unwrap();
        assert_eq!(cfg.manufacturer, "SoftHSM");
        assert_eq!(cfg.pin.expose_secret(), "5678");
        assert_eq!(cfg.token_label, "test");
        assert_eq!(cfg.attributes, "UserName=y");
    }

    #[test]
    fn pin_file_prefix_strip() {
        let mut pin_file = NamedTempFile::new().unwrap();
        write!(pin_file, "secret-pin").unwrap();
        let pin = format!("file:{}", pin_file.path().display());
        assert_eq!(resolve_pin_file_prefix(&pin).unwrap().expose_secret(), "secret-pin");
    }

    /// A PIN file created with a plain `echo "1234" > pinfile` has a trailing
    /// `\n`; that must not become part of the resolved PIN. (§1.6)
    #[test]
    fn pin_file_trims_trailing_newline() {
        let mut pin_file = NamedTempFile::new().unwrap();
        writeln!(pin_file, "1234").unwrap();
        let pin = format!("file:{}", pin_file.path().display());
        assert_eq!(resolve_pin_file_prefix(&pin).unwrap().expose_secret(), "1234");
    }

    #[test]
    fn pin_file_trims_trailing_crlf() {
        let mut pin_file = NamedTempFile::new().unwrap();
        write!(pin_file, "1234\r\n").unwrap();
        let pin = format!("file:{}", pin_file.path().display());
        assert_eq!(resolve_pin_file_prefix(&pin).unwrap().expose_secret(), "1234");
    }

    /// Only trailing `\r`/`\n` are trimmed — leading/interior/other trailing
    /// whitespace in the PIN is preserved verbatim.
    #[test]
    fn pin_file_preserves_non_crlf_whitespace() {
        let mut pin_file = NamedTempFile::new().unwrap();
        writeln!(pin_file, " 12 34 ").unwrap();
        let pin = format!("file:{}", pin_file.path().display());
        assert_eq!(resolve_pin_file_prefix(&pin).unwrap().expose_secret(), " 12 34 ");
    }

    /// Go `TrimLeft(pin, "file:")` treats the arg as a charset, so `file:file:/x`
    /// collapses to `/x`. We keep a true prefix strip → `file:/x`.
    #[test]
    fn pin_file_prefix_differs_from_go_trim_left() {
        let mut pin_file = NamedTempFile::new().unwrap();
        // Create a file whose path ends up as `file:<tmpdir>/pin` when prefixed twice.
        write!(pin_file, "nested").unwrap();
        let inner = format!("file:{}", pin_file.path().display());
        // Write that exact string into another file so strip of one `file:` yields a path
        // that still starts with `file:` — callers must not charset-trim.
        let resolved_once =
            resolve_pin_file_prefix(&format!("file:{}", pin_file.path().display())).unwrap();
        assert_eq!(resolved_once.expose_secret(), "nested");

        // Direct string case: strip_prefix once leaves a path still starting with file:
        let quirky = "file:file:/tmp/does-not-need-to-exist-for-prefix-test";
        let stripped = quirky.strip_prefix("file:").unwrap();
        assert_eq!(stripped, "file:/tmp/does-not-need-to-exist-for-prefix-test");
        // Document Go TrimLeft would yield "/tmp/does-not-need-to-exist-for-prefix-test"
        let go_trim_left = quirky.trim_start_matches(['f', 'i', 'l', 'e', ':']);
        assert_eq!(go_trim_left, "/tmp/does-not-need-to-exist-for-prefix-test");
        assert_ne!(stripped, go_trim_left);
        let _ = inner;
    }

    /// Go SoftHSM unit JSON often omits Model (and sometimes Manufacturer defaults empty).
    #[test]
    fn load_json_omitted_model_defaults_empty() {
        let mut f = NamedTempFile::with_suffix(".json").unwrap();
        write!(
            f,
            r#"{{
                "Manufacturer": "SoftHSM",
                "Path": "/usr/lib/softhsm/libsofthsm2.so",
                "TokenLabel": "trusty11_unittest",
                "Pin": "1234"
            }}"#
        )
        .unwrap();
        let cfg = load_token_config(f.path()).unwrap();
        assert_eq!(cfg.manufacturer, "SoftHSM");
        assert_eq!(cfg.model, "");
        assert_eq!(cfg.token_label, "trusty11_unittest");
        assert_eq!(cfg.path, "/usr/lib/softhsm/libsofthsm2.so");
    }

    #[test]
    fn load_config_resolves_pin_file() {
        let mut pin_file = NamedTempFile::new().unwrap();
        write!(pin_file, "from-file").unwrap();
        let mut f = NamedTempFile::with_suffix(".json").unwrap();
        write!(
            f,
            r#"{{
                "Manufacturer": "M",
                "Model": "Mod",
                "Path": "/lib.so",
                "TokenLabel": "t",
                "Pin": "file:{}"
            }}"#,
            pin_file.path().display()
        )
        .unwrap();
        let cfg = load_token_config(f.path()).unwrap();
        assert_eq!(cfg.pin.expose_secret(), "from-file");
    }

    #[test]
    fn pin_is_redacted_in_debug_output() {
        let file_cfg = FileTokenConfig {
            manufacturer: "M".to_string(),
            model: "Mod".to_string(),
            path: "/lib.so".to_string(),
            token_serial: String::new(),
            token_label: "t".to_string(),
            pin: SecretString::from("super-secret-pin"),
            attributes: String::new(),
        };
        let owned = OwnedTokenConfig::from(&file_cfg);

        let file_debug = format!("{file_cfg:?}");
        let owned_debug = format!("{owned:?}");
        assert!(!file_debug.contains("super-secret-pin"));
        assert!(!owned_debug.contains("super-secret-pin"));
        assert!(file_debug.contains("REDACTED"));
        assert!(owned_debug.contains("REDACTED"));
    }
}
