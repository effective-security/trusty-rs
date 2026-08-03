//! `hsm-tool`: CLI to work with keys backed by HSM or KMS (AWS KMS, GCP KMS, PKCS#11).

mod cli;
mod hsm;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, HsmCommand, TopCommand};
use std::str::FromStr;
use std::sync::Arc;
use trusty_cryptoprov_core::{Crypto, Provider, ProviderRegistry};
use trusty_cryptoprov_inmem::InmemProvider;

fn init_tracing(cli: &Cli) -> Result<()> {
    let level_name = if cli.debug { "debug" } else { cli.log_level.as_str() };
    let level = tracing::Level::from_str(level_name).with_context(|| {
        format!("invalid log level: {level_name:?} (expected debug|info|warn|error)")
    })?;
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .without_time()
        .init();
    Ok(())
}

/// Build a registry with every provider crate this binary links in.
fn provider_registry() -> Result<ProviderRegistry> {
    let mut registry = ProviderRegistry::new();
    registry.register("inmem", trusty_cryptoprov_inmem::loader())?;
    registry.register("pkcs11", trusty_cryptoprov_pkcs11::loader())?;
    registry.register("aws-kms", trusty_cryptoprov_aws_kms::loader())?;
    registry.register("gcp-kms", trusty_cryptoprov_gcp_kms::loader())?;
    Ok(registry)
}

/// Load the `Crypto` provider set for `--cfg`/`--add-cfg`.
///
/// `"plain"` is accepted as a synonym for the `"inmem"` shortcut already
/// handled by `trusty_cryptoprov_core::load_token_config`.
fn load_crypto(cli: &Cli, registry: &ProviderRegistry) -> Result<Crypto> {
    let cfg = if cli.cfg == "plain" { "inmem" } else { cli.cfg.as_str() };
    let extra: Vec<&str> = cli.add_cfg.iter().map(String::as_str).collect();
    registry
        .load(cfg, &extra)
        .with_context(|| format!("unable to initialize crypto providers: {cfg}"))
}

/// The provider new keys are created on: `--plain-key` forces a fresh, unregistered
/// inmem provider even when `--cfg` points at a real HSM/KMS config.
fn default_provider(cli: &Cli, crypto: &Crypto) -> Arc<dyn Provider> {
    if cli.plain_key { Arc::new(InmemProvider::new()) } else { crypto.default_provider() }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli)?;

    let registry = provider_registry()?;
    let crypto = load_crypto(&cli, &registry)?;
    let provider = default_provider(&cli, &crypto);

    let TopCommand::Hsm { command } = &cli.command;
    let mut stdout = std::io::stdout();

    match command {
        HsmCommand::List(args) => hsm::run_list(provider.as_ref(), args, &mut stdout),
        HsmCommand::Info(args) => hsm::run_info(provider.as_ref(), args, &mut stdout),
        HsmCommand::Generate(args) => hsm::run_generate(provider.as_ref(), args, &mut stdout),
        HsmCommand::Remove(args) => hsm::run_remove(provider.as_ref(), args, &mut stdout),
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}
