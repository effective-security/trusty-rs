//! Attribute/class/key-type name maps and random ID/label helpers.

use crate::error::{Error, Result};
use cryptoki::object::{AttributeType, KeyType, ObjectClass};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// PKCS#11 attribute type → short name.
pub fn attribute_names() -> &'static HashMap<AttributeType, &'static str> {
    static MAP: OnceLock<HashMap<AttributeType, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        HashMap::from([
            (AttributeType::Id, "ID"),
            (AttributeType::Label, "Label"),
            (AttributeType::KeyType, "Key type"),
            (AttributeType::Class, "Class"),
        ])
    })
}

/// Object class → name pairs.
#[must_use]
pub fn object_class_names() -> &'static [(ObjectClass, &'static str)] {
    &[
        (ObjectClass::DATA, "Data"),
        (ObjectClass::CERTIFICATE, "Certificate"),
        (ObjectClass::PUBLIC_KEY, "Public key"),
        (ObjectClass::PRIVATE_KEY, "Private key"),
        (ObjectClass::SECRET_KEY, "Secret key"),
    ]
}

/// Key type → name pairs. DSA is listed for display-map completeness only.
///
/// `CKK_ECDSA` equals cryptoki's [`KeyType::EC`].
#[must_use]
pub fn key_type_names() -> &'static [(KeyType, &'static str)] {
    &[(KeyType::RSA, "RSA"), (KeyType::DSA, "DSA"), (KeyType::DH, "DH"), (KeyType::EC, "ECDSA")]
}

/// Look up a key type display name (empty string if unknown).
#[must_use]
pub fn key_type_name(key_type: KeyType) -> &'static str {
    key_type_names().iter().find(|(k, _)| *k == key_type).map(|(_, name)| *name).unwrap_or("")
}

/// Look up an object class display name (empty string if unknown).
#[must_use]
pub fn object_class_name(class: ObjectClass) -> &'static str {
    object_class_names().iter().find(|(c, _)| *c == class).map(|(_, name)| *name).unwrap_or("")
}

/// Look up a short attribute name.
#[must_use]
pub fn attribute_name(attr: AttributeType) -> Option<&'static str> {
    attribute_names().get(&attr).copied()
}

/// Format a PKCS#11 URI for a private key.
#[must_use]
pub fn format_pkcs11_uri(
    manufacturer: &str,
    model: &str,
    serial: &str,
    token: &str,
    key_id: &str,
) -> String {
    format!(
        "pkcs11:manufacturer={manufacturer};model={model};serial={};token={};id={};type=private",
        serial.trim(),
        token.trim(),
        key_id.trim(),
    )
}

/// Build a 32-byte key label from UTC timestamp + random bytes.
///
/// `raw` must be 32 random bytes; output is ASCII truncated to 32 bytes:
/// `YYYYMMDDhhmmss_` + hex(raw), then `[:32]`.
///
/// # Errors
///
/// Returns [`Error::CannotGetRandomData`] if `raw` is shorter than 32 bytes.
pub fn key_label_from_random(
    raw: &[u8],
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
) -> Result<Vec<u8>> {
    if raw.len() < 32 {
        return Err(Error::CannotGetRandomData);
    }
    let hex = hex_encode(&raw[..32]);
    let label = format!("{year:04}{month:02}{day:02}{hour:02}{min:02}{sec:02}_{hex}");
    let bytes = label.into_bytes();
    Ok(bytes[..32].to_vec())
}

/// Build a 32-byte key ID from random bytes: hex(raw)[:32].
///
/// # Errors
///
/// Returns [`Error::CannotGetRandomData`] if `raw` is shorter than 32 bytes.
pub fn key_id_from_random(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < 32 {
        return Err(Error::CannotGetRandomData);
    }
    let hex = hex_encode(&raw[..32]);
    Ok(hex.into_bytes()[..32].to_vec())
}

/// Current UTC components for label generation.
pub(crate) fn utc_now_parts() -> (i32, u32, u32, u32, u32, u32) {
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    // civil date from unix seconds (adequate for label prefix tests)
    let secs = dur.as_secs() as i64;
    let (y, m, d, hh, mm, ss) = civil_from_unix(secs);
    (y, m, d, hh, mm, ss)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Minimal UTC civil date from Unix timestamp.
///
/// Hand-rolled instead of pulling in a date/time crate: this is only ever
/// used to build a label prefix (see [`utc_now_parts`]), not a
/// general-purpose date utility, so exact calendar edge cases (leap
/// seconds, far-future/past timestamps, etc.) don't matter here — don't
/// spend time trying to "fix" its handling of those.
fn civil_from_unix(mut secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let ss = (secs.rem_euclid(60)) as u32;
    secs = secs.div_euclid(60);
    let mm = (secs.rem_euclid(60)) as u32;
    secs = secs.div_euclid(60);
    let hh = (secs.rem_euclid(24)) as u32;
    let mut days = secs.div_euclid(24);
    // 1970-01-01
    let mut year = 1970i32;
    loop {
        let diy = if is_leap(year) { 366 } else { 365 };
        if days >= diy {
            days -= diy;
            year += 1;
        } else if days < 0 {
            year -= 1;
            days += if is_leap(year) { 366 } else { 365 };
        } else {
            break;
        }
    }
    let mdays = month_days(year);
    let mut month = 1u32;
    for &dim in &mdays {
        if days >= dim as i64 {
            days -= dim as i64;
            month += 1;
        } else {
            break;
        }
    }
    let day = (days + 1) as u32;
    (year, month, day, hh, mm, ss)
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

fn month_days(year: i32) -> [u32; 12] {
    let feb = if is_leap(year) { 29 } else { 28 };
    [31, feb, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_length() {
        let raw = [0xabu8; 32];
        let id = key_id_from_random(&raw).unwrap();
        assert_eq!(id.len(), 32);
        assert_eq!(std::str::from_utf8(&id).unwrap(), "abababababababababababababababab");
    }

    #[test]
    fn key_label_length_and_prefix() {
        let raw = [0x11u8; 32];
        let label = key_label_from_random(&raw, 2026, 8, 2, 12, 30, 45).unwrap();
        assert_eq!(label.len(), 32);
        let s = std::str::from_utf8(&label).unwrap();
        assert!(s.starts_with("20260802123045_"), "{s}");
    }

    #[test]
    fn name_maps_contain_expected() {
        assert_eq!(key_type_name(KeyType::RSA), "RSA");
        assert_eq!(key_type_name(KeyType::EC), "ECDSA");
        assert_eq!(object_class_name(ObjectClass::PRIVATE_KEY), "Private key");
        assert_eq!(attribute_name(AttributeType::Id), Some("ID"));
        assert_eq!(attribute_names().get(&AttributeType::Label).copied(), Some("Label"));
    }

    #[test]
    fn uri_format() {
        let uri = format_pkcs11_uri("SoftHSM", "v2", "  serial  ", " token ", " kid ");
        assert_eq!(
            uri,
            "pkcs11:manufacturer=SoftHSM;model=v2;serial=serial;token=token;id=kid;type=private"
        );
    }
}
