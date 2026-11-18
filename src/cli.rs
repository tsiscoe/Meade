use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::db::models::SecretCategory;

#[derive(Debug, Parser)]
#[command(
    name = "meade",
    version,
    about = "Meade: Pure-Rust Two-Tier AEAD Credential Vault, Win32 Clipboard Interceptor Daemon & Ratatui Catalogue Viewer"
)]
pub struct MeadeCli {
    /// Custom path to the SQLite vault database (defaults to ~/.meade/vault.db)
    #[arg(short, long, global = true)]
    pub vault: Option<PathBuf>,

    /// Master passphrase (for headless automation/CI; interactive prompt used when omitted)
    #[arg(short, long, global = true, env = "MEADE_PASSPHRASE")]
    pub passphrase: Option<String>,

    /// Use OS Keyring (Windows Credential Manager DPAPI) to cache/retrieve unlocked session keys
    #[arg(long, global = true)]
    pub keyring: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize a new Meade cryptographic vault
    Init {
        /// Seed 3 sample credentials (AWS IAM + TOTP, Cloud API Key, Bastion SSH Key)
        #[arg(long)]
        seed_demo: bool,
    },

    /// Launch the interactive Ratatui v0.30+ Catalogue Viewer (default when no subcommand is given)
    Tui,

    /// Unlock the vault and cache session subkeys in the background Daemon and/or OS Keyring
    Unlock,

    /// Immediately wipe session keys from Daemon RAM & OS Keyring and scrub the OS clipboard
    Lock,

    /// Add a new credential entry from the command line
    Add {
        #[arg(short, long)]
        title: String,
        #[arg(short, long, value_enum, default_value_t = CliCategory::Login)]
        category: CliCategory,
        #[arg(short, long, default_value = "")]
        identity: String,
        #[arg(short, long, default_value = "")]
        url: String,
        #[arg(long, default_value = "")]
        tags: String,
        /// Secret value (omit to be prompted securely via hidden TTY or use --secret-stdin)
        #[arg(short, long)]
        secret: Option<String>,
        /// Read the secret value from standard input (avoids exposing secret in OS process arguments)
        #[arg(long)]
        secret_stdin: bool,
        #[arg(long)]
        totp: Option<String>,
        #[arg(long, default_value = "")]
        notes: String,
    },

    /// List all Tier-1 catalogue headers without decrypting Tier-2 secrets
    List {
        /// Optional fuzzy or substring filter
        #[arg(short, long)]
        query: Option<String>,
    },

    /// Queue a credential into the Sequential Clipboard Daemon (Username -> Password -> TOTP)
    Queue {
        /// Title or UUID of the credential to queue, or `next` / `scrub` / `status`
        target: String,
    },

    /// Run or control the background Clipboard Interceptor & Ctrl+Shift+V Hotkey Daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Import credentials from .env, JSON, or ~/.ssh/config
    Import {
        /// Format: `dotenv`, `json`, or `ssh`
        #[arg(short, long, value_enum)]
        format: ImportFormat,
        /// Input file path
        #[arg(short, long)]
        file: PathBuf,
        /// Tag prefix for imported items
        #[arg(long, default_value = "imported")]
        tag: String,
    },

    /// Export credentials to .env or JSON format
    Export {
        /// Format: `dotenv` or `json`
        #[arg(short, long, value_enum)]
        format: ExportFormat,
        /// Optional tag filter for .env export
        #[arg(long)]
        tag: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliCategory {
    Login,
    Api,
    Ssh,
    Totp,
    Note,
}

impl From<CliCategory> for SecretCategory {
    fn from(val: CliCategory) -> Self {
        match val {
            CliCategory::Login => SecretCategory::Login,
            CliCategory::Api => SecretCategory::ApiKey,
            CliCategory::Ssh => SecretCategory::SshKey,
            CliCategory::Totp => SecretCategory::TotpOnly,
            CliCategory::Note => SecretCategory::SecureNote,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum DaemonAction {
    /// Start the foreground/background Clipboard Interceptor & Ctrl+Shift+V Hotkey Daemon
    Serve {
        /// Clipboard auto-scrub TTL in seconds
        #[arg(long, default_value_t = 20)]
        ttl: u64,
        /// Session key inactivity auto-lock timeout in minutes (0 disables auto-lock)
        #[arg(long, default_value_t = 15)]
        idle_timeout: u64,
    },
    /// Advance the active sequential paste queue to the next stage (same as pressing Ctrl+Shift+V)
    Next,
    /// Immediately scrub the OS clipboard and clear the queue
    Scrub,
    /// Show daemon status and active clipboard queue stage
    Status,
    /// Stop the running daemon and scrub clipboard
    Stop,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ImportFormat {
    Dotenv,
    Json,
    Ssh,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    Dotenv,
    Json,
}
