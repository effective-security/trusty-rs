//! SoftHSM test helpers. Integration tests are ignored unless a config is present.

use std::env;
use std::path::PathBuf;
use trusty_crypto11::{Pkcs11Lib, configure_from_file};

/// Config path: `TRUSTY_SOFTHSM_CONFIG`, else `/tmp/trusty11/softhsm_unittest.json`.
pub fn softhsm_config_path() -> Option<PathBuf> {
    if let Ok(p) = env::var("TRUSTY_SOFTHSM_CONFIG") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
    }
    let default = PathBuf::from("/tmp/trusty11/softhsm_unittest.json");
    if default.is_file() { Some(default) } else { None }
}

pub fn open_lib() -> Option<Pkcs11Lib> {
    let path = softhsm_config_path()?;
    match configure_from_file(&path) {
        Ok(lib) => Some(lib),
        Err(e) => {
            eprintln!("skip: SoftHSM configure_from_file({}): {e}", path.display());
            None
        }
    }
}
