//! Command-line argument definitions.
//!
//! `clap`'s `#[derive]` macros generate the parser from these structs, the
//! Rust analogue of Go's struct-tag-driven `kong` CLI definitions.

use clap::{Args, Parser, Subcommand};

/// CLI tool for HSM or KMS.
#[derive(Debug, Parser)]
#[command(name = "hsm-tool", about = "CLI tool for HSM or KMS")]
pub struct Cli {
    /// Location of HSM config file, as default crypto provider where the key will be created
    #[arg(long)]
    pub cfg: String,

    /// Location of additional HSM config files
    #[arg(long = "add-cfg")]
    pub add_cfg: Vec<String>,

    /// Generate plain key using inmem provider
    #[arg(long = "plain-key")]
    pub plain_key: bool,

    /// Enable debug mode, the same as -l debug
    #[arg(short = 'D', long)]
    pub debug: bool,

    /// Set the logging level (debug|info|warn|error)
    #[arg(short = 'l', long = "log-level", default_value = "error")]
    pub log_level: String,

    #[command(subcommand)]
    pub command: TopCommand,
}

/// Top-level command groups.
#[derive(Debug, Subcommand)]
pub enum TopCommand {
    /// HSM commands
    Hsm {
        #[command(subcommand)]
        command: HsmCommand,
    },
}

/// HSM key management commands.
#[derive(Debug, Subcommand)]
pub enum HsmCommand {
    /// list keys
    List(ListArgs),
    /// print key information
    Info(InfoArgs),
    /// generate key
    Generate(GenerateArgs),
    /// delete key
    Remove(RemoveArgs),
}

/// Arguments for `hsm list`.
#[derive(Debug, Args)]
pub struct ListArgs {
    /// specifies slot token (optional)
    #[arg(long)]
    pub token: Option<String>,

    /// specifies slot serial (optional)
    #[arg(long)]
    pub serial: Option<String>,

    /// specifies key label prefix (optional)
    #[arg(long)]
    pub prefix: Option<String>,
}

/// Arguments for `hsm info`.
#[derive(Debug, Args)]
pub struct InfoArgs {
    /// key ID
    pub id: String,

    /// specifies slot token (optional)
    #[arg(long)]
    pub token: Option<String>,

    /// specifies slot serial (optional)
    #[arg(long)]
    pub serial: Option<String>,

    /// print Public Key
    #[arg(long)]
    pub public: bool,
}

/// Arguments for `hsm generate`.
#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// algorithm: RSA|ECDSA
    #[arg(long)]
    pub algo: String,

    /// key size in bits
    #[arg(long)]
    pub size: usize,

    /// purpose of the key: SIGN|ENCRYPT
    #[arg(long)]
    pub purpose: String,

    /// name for generated key
    #[arg(long)]
    pub label: String,

    /// location to write the key, if not set, the output will be printed to STDOUT only
    #[arg(long)]
    pub output: Option<String>,

    /// force to override key file if exists
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `hsm remove`.
#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// specifies key ID
    pub id: String,

    /// specifies slot token (optional)
    #[arg(long)]
    pub token: Option<String>,

    /// specifies slot serial (optional)
    #[arg(long)]
    pub serial: Option<String>,
}
