//! `hsm list|info|generate|remove` command implementations.

use crate::cli::{GenerateArgs, InfoArgs, ListArgs, RemoveArgs};
use anyhow::{Context, Result, anyhow, bail};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use trusty_cryptoprov_core::{KeyInfo, KeyManager, KeyPurpose, NamedCurve, Provider, TokenInfo};
use uuid::Uuid;

/// Whether `token` should be included given the CLI's optional `--serial`/`--token` filters.
///
/// A `None` filter never matches an empty provider-reported field: unlike Go's
/// zero-value string, `Option::None` unambiguously means "no filter given" so
/// no sentinel value is needed to keep it from matching an empty string.
fn token_matches(
    token: &TokenInfo,
    is_default_slot: bool,
    serial: Option<&str>,
    label: Option<&str>,
) -> bool {
    is_default_slot
        || serial.is_some_and(|s| s == token.serial)
        || label.is_some_and(|l| l == token.label)
}

fn selected_tokens(
    key_manager: &dyn KeyManager,
    serial: Option<&str>,
    label: Option<&str>,
) -> Result<Vec<TokenInfo>> {
    let is_default_slot = serial.is_none() && label.is_none();
    let tokens = key_manager.enum_tokens(is_default_slot).context("failed to list tokens")?;
    Ok(tokens.into_iter().filter(|t| token_matches(t, is_default_slot, serial, label)).collect())
}

fn print_if_not_empty(out: &mut dyn Write, label: &str, value: &str) -> Result<()> {
    if !value.is_empty() {
        writeln!(out, "{label}:  {value}")?;
    }
    Ok(())
}

fn format_creation_time(t: SystemTime) -> Result<String> {
    Ok(OffsetDateTime::from(t).format(&Rfc3339)?)
}

fn print_key_info(out: &mut dyn Write, key: &KeyInfo, indent: &str) -> Result<()> {
    writeln!(out, "{indent}Id:    {}", key.id)?;
    print_if_not_empty(out, &format!("{indent}Label"), &key.label)?;
    print_if_not_empty(out, &format!("{indent}Type"), &key.key_type)?;
    print_if_not_empty(out, &format!("{indent}Class"), &key.class)?;
    print_if_not_empty(out, &format!("{indent}Version"), &key.current_version_id)?;
    if let Some(t) = key.creation_time {
        writeln!(out, "{indent}Created: {}", format_creation_time(t)?)?;
    }
    let mut meta: Vec<_> = key.meta.iter().collect();
    meta.sort_by(|a, b| a.0.cmp(b.0));
    for (k, v) in meta {
        writeln!(out, "{indent}{k}: {v}")?;
    }
    if !key.public_key.is_empty() {
        writeln!(out, "{indent}Public key: \n{}", key.public_key)?;
    }
    Ok(())
}

/// Run `hsm list`.
pub fn run_list(provider: &dyn Provider, args: &ListArgs, out: &mut dyn Write) -> Result<()> {
    let key_manager = provider
        .as_key_manager()
        .ok_or_else(|| anyhow!("unsupported command for this crypto provider"))?;

    for token in selected_tokens(key_manager, args.serial.as_deref(), args.token.as_deref())? {
        writeln!(out, "Slot: {}", token.slot_id)?;
        print_if_not_empty(out, "  Manufacturer", &token.manufacturer)?;
        print_if_not_empty(out, "  Model", &token.model)?;
        print_if_not_empty(out, "  Description", &token.description)?;
        print_if_not_empty(out, "  Token serial", &token.serial)?;
        print_if_not_empty(out, "  Token label", &token.label)?;

        let prefix = args.prefix.as_deref().unwrap_or("");
        let keys = key_manager
            .enum_keys(token.slot_id, prefix)
            .with_context(|| format!("failed to list keys on slot {}", token.slot_id))?;

        if let Some(prefix) = args.prefix.as_deref().filter(|p| !p.is_empty())
            && keys.is_empty()
        {
            writeln!(out, "no keys found with prefix: {prefix}")?;
        }

        for (i, key) in keys.iter().enumerate() {
            writeln!(out, "[{i}]")?;
            print_key_info(out, key, "  ")?;
        }
    }
    Ok(())
}

/// Run `hsm info`.
pub fn run_info(provider: &dyn Provider, args: &InfoArgs, out: &mut dyn Write) -> Result<()> {
    let key_manager = provider
        .as_key_manager()
        .ok_or_else(|| anyhow!("unsupported command for this crypto provider"))?;

    for token in selected_tokens(key_manager, args.serial.as_deref(), args.token.as_deref())? {
        writeln!(out, "Slot: {}", token.slot_id)?;
        writeln!(out, "  Description:  {}", token.description)?;
        writeln!(out, "  Token serial: {}", token.serial)?;

        let key = key_manager
            .key_info(token.slot_id, &args.id, args.public)
            .with_context(|| format!("failed to get key on slot {}", token.slot_id))?;
        print_key_info(out, &key, "  ")?;
    }
    Ok(())
}

/// Run `hsm remove`.
pub fn run_remove(provider: &dyn Provider, args: &RemoveArgs, out: &mut dyn Write) -> Result<()> {
    let key_manager = provider
        .as_key_manager()
        .ok_or_else(|| anyhow!("unsupported command for this crypto provider"))?;

    if let Some(token) =
        selected_tokens(key_manager, args.serial.as_deref(), args.token.as_deref())?
            .into_iter()
            .next()
    {
        key_manager.destroy_key_pair_on_slot(token.slot_id, &args.id).with_context(|| {
            format!("unable to destroy key {:?} on slot {}", args.id, token.slot_id)
        })?;
        writeln!(out, "destroyed key: {}", args.id)?;
    }
    Ok(())
}

/// Parse the `--purpose` flag (`sign(ing)` or `encrypt(ion)`, case-insensitive).
fn parse_key_purpose(purpose: &str) -> Result<KeyPurpose> {
    match purpose.to_lowercase().as_str() {
        "s" | "sign" | "signing" => Ok(KeyPurpose::Signing),
        "e" | "encrypt" | "encryption" => Ok(KeyPurpose::Encryption),
        other => bail!("unsupported purpose: {other:?}"),
    }
}

/// Map an ECDSA key size in bits to its named curve.
fn curve_for_bits(bits: usize) -> Result<NamedCurve> {
    match bits {
        224 => Ok(NamedCurve::P224),
        256 => Ok(NamedCurve::P256),
        384 => Ok(NamedCurve::P384),
        521 => Ok(NamedCurve::P521),
        other => bail!("unsupported ECDSA key size: {other}"),
    }
}

/// If `label` ends with `*`, replace the `*` with a UTC-timestamp + short-GUID
/// suffix so repeated `--label name*` invocations don't collide.
fn unique_key_label(label: &str) -> String {
    let Some(base) = label.strip_suffix('*') else {
        return label.to_string();
    };
    let now = OffsetDateTime::now_utc();
    let suffix: String =
        Uuid::new_v4().as_bytes()[..4].iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{base}_{:04}{:02}{:02}{:02}{:02}{:02}_{suffix}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// Run `hsm generate`.
pub fn run_generate(
    provider: &dyn Provider,
    args: &GenerateArgs,
    out: &mut dyn Write,
) -> Result<()> {
    if let Some(output) = &args.output
        && !args.force
        && Path::new(output).exists()
    {
        bail!("{output:?} file exists, specify --force flag to override");
    }

    let purpose = parse_key_purpose(&args.purpose)?;
    let label = unique_key_label(&args.label);

    let signer = match args.algo.to_uppercase().as_str() {
        "RSA" => {
            provider.generate_rsa_key(&label, args.size, purpose).context("generate RSA key")?
        }
        "ECDSA" => provider
            .generate_ecdsa_key(&label, curve_for_bits(args.size)?)
            .context("generate ECDSA key")?,
        other => bail!("unsupported algorithm: {other:?}"),
    };

    let key_id = signer.key_id().ok_or_else(|| anyhow!("generated key has no id"))?;
    let (uri, pem) = provider.export_key(key_id).context("export key")?;
    let material: &[u8] = if pem.is_empty() { uri.as_bytes() } else { &pem };

    match &args.output {
        Some(path) => {
            fs::write(path, material).with_context(|| format!("write key to {path}"))?;
        }
        None => {
            out.write_all(material)?;
            if !material.ends_with(b"\n") {
                writeln!(out)?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(serial: &str, label: &str) -> TokenInfo {
        TokenInfo { serial: serial.to_string(), label: label.to_string(), ..Default::default() }
    }

    #[test]
    fn token_matches_default_slot_matches_everything() {
        assert!(token_matches(&token("s1", "l1"), true, None, None));
        assert!(token_matches(&token("", ""), true, None, None));
    }

    #[test]
    fn token_matches_requires_explicit_filter_hit() {
        let t = token("s1", "l1");
        assert!(token_matches(&t, false, Some("s1"), None));
        assert!(token_matches(&t, false, None, Some("l1")));
        assert!(!token_matches(&t, false, Some("other"), None));
    }

    #[test]
    fn token_matches_none_filter_never_matches_empty_field() {
        // Unlike a Go zero-value string, an absent Option filter must not
        // match a token whose serial/label happens to be empty.
        let empty = token("", "");
        assert!(!token_matches(&empty, false, None, None));
    }

    #[test]
    fn parse_key_purpose_accepts_known_aliases() {
        assert_eq!(parse_key_purpose("sign").unwrap(), KeyPurpose::Signing);
        assert_eq!(parse_key_purpose("SIGNING").unwrap(), KeyPurpose::Signing);
        assert_eq!(parse_key_purpose("e").unwrap(), KeyPurpose::Encryption);
        assert_eq!(parse_key_purpose("Encrypt").unwrap(), KeyPurpose::Encryption);
    }

    #[test]
    fn parse_key_purpose_rejects_unknown() {
        assert!(parse_key_purpose("bogus").is_err());
    }

    #[test]
    fn curve_for_bits_maps_known_sizes() {
        assert_eq!(curve_for_bits(224).unwrap(), NamedCurve::P224);
        assert_eq!(curve_for_bits(256).unwrap(), NamedCurve::P256);
        assert_eq!(curve_for_bits(384).unwrap(), NamedCurve::P384);
        assert_eq!(curve_for_bits(521).unwrap(), NamedCurve::P521);
        assert!(curve_for_bits(999).is_err());
    }

    #[test]
    fn unique_key_label_passes_through_without_star() {
        assert_eq!(unique_key_label("my-key"), "my-key");
    }

    #[test]
    fn unique_key_label_expands_trailing_star() {
        let label = unique_key_label("my-key*");
        assert!(label.starts_with("my-key_"));
        assert_ne!(label, unique_key_label("my-key*"));
    }
}
