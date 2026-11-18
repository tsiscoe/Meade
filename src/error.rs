use thiserror::Error;

#[derive(Debug, Error)]
pub enum MeadeError {
    #[error("Cryptographic key derivation or AEAD failure: {0}")]
    Crypto(String),

    #[error("Vault is currently locked; unlock with master passphrase first")]
    VaultLocked,

    #[error("Invalid master passphrase or tampered ciphertext authentication tag")]
    AuthenticationFailed,

    #[error("Database storage error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOTP configuration or RFC 6238 generation error: {0}")]
    Totp(String),

    #[error("Clipboard or OS integration error: {0}")]
    Clipboard(String),

    #[error("OS Keyring error: {0}")]
    Keyring(String),

    #[error("Entry not found: {0}")]
    NotFound(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, MeadeError>;
