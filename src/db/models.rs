use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Taxonomy of credentials and secrets supported by the Meade catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretCategory {
    Login,
    ApiKey,
    SshKey,
    TotpOnly,
    SecureNote,
}

impl SecretCategory {
    pub fn label(self) -> &'static str {
        match self {
            Self::Login => "Login / Password",
            Self::ApiKey => "API / Cloud Token",
            Self::SshKey => "SSH / PEM Key",
            Self::TotpOnly => "TOTP Authenticator",
            Self::SecureNote => "Secure Note",
        }
    }

    pub fn short_badge(self) -> &'static str {
        match self {
            Self::Login => "[LOGIN]",
            Self::ApiKey => "[API]",
            Self::SshKey => "[SSH]",
            Self::TotpOnly => "[TOTP]",
            Self::SecureNote => "[NOTE]",
        }
    }

    pub fn all() -> &'static [SecretCategory] {
        &[
            Self::Login,
            Self::ApiKey,
            Self::SshKey,
            Self::TotpOnly,
            Self::SecureNote,
        ]
    }
}

/// Tier-1 Catalogue Header: Encrypted on disk with the Tier-1 Subkey, decrypted in RAM
/// when browsing/fuzzy-searching the Ratatui catalogue viewer. Contains zero raw passwords or keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tier1Header {
    pub title: String,
    pub category: SecretCategory,
    pub identity: String,
    pub url_or_host: String,
    pub tags: Vec<String>,
    pub has_totp: bool,
}

/// Tier-2 Secret Payload: Encrypted on disk with the Tier-2 Subkey and its own random 192-bit nonce.
/// Never decrypted during TUI browsing or searching—only opened for the single record being inspected
/// or queued into the Clipboard Interceptor Daemon. Automatically zeroized on Drop.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Tier2Secret {
    /// Primary secret (Password, API Token, or SSH Private Key material).
    pub primary_secret: String,
    /// Optional RFC 6238 Base32 TOTP seed or otpauth:// URI.
    pub totp_secret: Option<String>,
    /// Optional freeform notes or recovery codes.
    pub notes: String,
}

/// A lightweight catalogue item combining the SQLite row metadata with its decrypted Tier-1 Header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogueItem {
    pub id: String,
    pub header: Tier1Header,
    pub created_at: i64,
    pub updated_at: i64,
}
