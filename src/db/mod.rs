pub mod models;

use std::path::Path;

use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::crypto::envelope::{EnvelopeTier, open_envelope, seal_envelope};
use crate::crypto::{SALT_LEN, VaultKeys};
use crate::db::models::{CatalogueItem, SecretCategory, Tier1Header, Tier2Secret};
use crate::error::{MeadeError, Result};

const CANARY_ENTRY_ID: &str = "__meade_vault_canary_v1__";
const CANARY_PLAINTEXT: &[u8] = b"MEADE_VAULT_AUTHENTICATED_CANARY_V1";

/// Enforces fail-closed owner-only filesystem permissions (`0700`/`0600` on Unix; absolute
/// `System32\icacls.exe /inheritance:r` owner-SID DACL on Windows) (`MEADE-HORDE-02` / `03`).
pub fn enforce_owner_only_acl(path: &Path, is_dir: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if is_dir { 0o700 } else { 0o600 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        let applied = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if applied != mode {
            return Err(MeadeError::Io(std::io::Error::other(format!(
                "effective Unix mode {:o} != {:o} on {}",
                applied,
                mode,
                path.display()
            ))));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let sid = resolve_windows_owner_sid()?;
        let icacls_exe = resolve_system32_binary("icacls.exe");
        let (grant_owner, grant_system, grant_admins) = if is_dir {
            (
                format!("*{sid}:(OI)(CI)F"),
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            )
        } else {
            (
                format!("*{sid}:F"),
                "*S-1-5-18:(F)",
                "*S-1-5-32-544:(F)",
            )
        };
        let output = std::process::Command::new(&icacls_exe)
            .arg(path)
            .args([
                "/inheritance:r",
                "/grant:r",
                &grant_owner,
                grant_system,
                grant_admins,
            ])
            .output()?;
        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MeadeError::Io(std::io::Error::other(format!(
                "icacls failed on {} ({}): {} {}",
                path.display(),
                output.status,
                stdout.trim(),
                stderr.trim()
            ))));
        }
        Ok(())
    }
}

#[cfg(windows)]
fn resolve_system32_binary(name: &str) -> std::path::PathBuf {
    let sys_root = std::env::var_os("SystemRoot")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
    sys_root.join("System32").join(name)
}

#[cfg(windows)]
fn resolve_windows_owner_sid() -> Result<String> {
    let whoami_exe = resolve_system32_binary("whoami.exe");
    let output = std::process::Command::new(&whoami_exe)
        .args(["/user", "/fo", "csv", "/nh"])
        .output()?;
    if !output.status.success() {
        return Err(MeadeError::Io(std::io::Error::other(format!(
            "whoami.exe /user failed with status {}",
            output.status
        ))));
    }
    let csv = String::from_utf8_lossy(&output.stdout);
    let sid = csv
        .trim()
        .split(',')
        .next_back()
        .map(|s| s.trim().trim_matches('"').to_string())
        .unwrap_or_default();
    if !sid.starts_with("S-1-") || sid.chars().any(|c| !c.is_ascii_digit() && c != 'S' && c != '-') {
        return Err(MeadeError::Io(std::io::Error::other(
            "unable to parse valid Windows user SID from whoami.exe",
        )));
    }
    Ok(sid)
}

/// Applies strict owner-only ACLs to the SQLite database and any live `-wal` / `-shm` sidecars.
pub fn enforce_db_and_sidecar_acls(db_path: &Path) -> Result<()> {
    enforce_owner_only_acl(db_path, false)?;
    for suffix in ["-wal", "-shm"] {
        let mut os = db_path.as_os_str().to_os_string();
        os.push(suffix);
        let sidecar = std::path::PathBuf::from(os);
        if sidecar.exists() {
            enforce_owner_only_acl(&sidecar, false)?;
        }
    }
    Ok(())
}

/// SQLite-backed Two-Tier Cryptographic Vault operating in WAL mode.
pub struct VaultDb {
    conn: Connection,
}

impl VaultDb {
    /// Opens or creates a SQLite vault file at `path` with WAL mode, strict foreign keys, and owner-only permissions.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path_ref = path.as_ref();
        if let Some(parent) = path_ref.parent()
            && !parent.as_os_str().is_empty()
        {
            let parent_existed = parent.exists();
            std::fs::create_dir_all(parent)?;
            let is_meade_dir = parent
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.eq_ignore_ascii_case(".meade"));
            if !parent_existed || is_meade_dir {
                enforce_owner_only_acl(parent, true)?;
            }
        }
        let conn = Connection::open(path_ref)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        enforce_db_and_sidecar_acls(path_ref)?;

        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    /// Opens an in-memory SQLite vault for unit and integration testing.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS vault_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                argon2_salt BLOB NOT NULL,
                canary_nonce BLOB NOT NULL,
                canary_ciphertext BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vault_entries (
                id TEXT PRIMARY KEY,
                tier1_nonce BLOB NOT NULL,
                tier1_ciphertext BLOB NOT NULL,
                tier2_nonce BLOB NOT NULL,
                tier2_ciphertext BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            ",
        )?;
        Ok(())
    }

    /// Returns `true` if this vault database has been initialized with a master passphrase & salt.
    pub fn is_initialized(&self) -> Result<bool> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM vault_meta WHERE id = 1", [], |row| {
                    row.get(0)
                })?;
        Ok(count > 0)
    }

    /// Initializes a brand-new vault using the provided passphrase, storing the Argon2id salt
    /// and an AEAD canary encrypted under the Tier-1 key.
    pub fn initialize_vault(&self, passphrase: &[u8], test_mode: bool) -> Result<VaultKeys> {
        if self.is_initialized()? {
            return Err(MeadeError::InvalidInput(
                "Vault is already initialized".to_string(),
            ));
        }

        let salt = VaultKeys::generate_salt();
        let keys = if test_mode {
            VaultKeys::derive_for_testing(passphrase, &salt)?
        } else {
            VaultKeys::derive_from_passphrase(passphrase, &salt)?
        };

        let (canary_nonce, canary_ciphertext) = seal_envelope(
            keys.tier1_key(),
            CANARY_ENTRY_ID,
            EnvelopeTier::Tier1Header,
            CANARY_PLAINTEXT,
        )?;

        let now = Utc::now().timestamp();
        self.conn.execute(
            "INSERT INTO vault_meta (id, argon2_salt, canary_nonce, canary_ciphertext, created_at)
             VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                salt.as_slice(),
                canary_nonce.as_slice(),
                canary_ciphertext,
                now
            ],
        )?;

        Ok(keys)
    }

    /// Unlocks an initialized vault using `passphrase`, verifying the AEAD canary before returning `VaultKeys`.
    pub fn unlock_vault(&self, passphrase: &[u8], test_mode: bool) -> Result<VaultKeys> {
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT argon2_salt, canary_nonce, canary_ciphertext FROM vault_meta WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        let (salt_vec, canary_nonce, canary_ciphertext) = row.ok_or_else(|| {
            MeadeError::InvalidInput(
                "Vault is not initialized yet. Run `meade init` first.".to_string(),
            )
        })?;

        if salt_vec.len() != SALT_LEN {
            return Err(MeadeError::Crypto(
                "Corrupt salt length in vault_meta".into(),
            ));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&salt_vec);

        let keys = if test_mode {
            VaultKeys::derive_for_testing(passphrase, &salt)?
        } else {
            VaultKeys::derive_from_passphrase(passphrase, &salt)?
        };

        self.verify_keys(&keys, &canary_nonce, &canary_ciphertext)?;
        Ok(keys)
    }

    /// Verifies that a pre-derived `VaultKeys` bundle (e.g. from Daemon RAM or OS Keyring) matches this vault's canary.
    pub fn verify_session_keys(&self, keys: &VaultKeys) -> Result<()> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT canary_nonce, canary_ciphertext FROM vault_meta WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        let (canary_nonce, canary_ciphertext) = row.ok_or(MeadeError::VaultLocked)?;
        self.verify_keys(keys, &canary_nonce, &canary_ciphertext)
    }

    fn verify_keys(
        &self,
        keys: &VaultKeys,
        canary_nonce: &[u8],
        canary_ciphertext: &[u8],
    ) -> Result<()> {
        let opened = open_envelope(
            keys.tier1_key(),
            CANARY_ENTRY_ID,
            EnvelopeTier::Tier1Header,
            canary_nonce,
            canary_ciphertext,
        )?;
        if opened.as_slice() != CANARY_PLAINTEXT {
            return Err(MeadeError::AuthenticationFailed);
        }
        Ok(())
    }

    /// Inserts a new credential entry into the vault, sealing Tier-1 and Tier-2 under separate subkeys and nonces.
    pub fn add_entry(
        &self,
        keys: &VaultKeys,
        mut header: Tier1Header,
        secret: &Tier2Secret,
    ) -> Result<String> {
        let entry_id = Uuid::new_v4().to_string();
        header.has_totp = secret
            .totp_secret
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty());

        let t1_bytes = zeroize::Zeroizing::new(serde_json::to_vec(&header)?);
        let (t1_nonce, t1_cipher) = seal_envelope(
            keys.tier1_key(),
            &entry_id,
            EnvelopeTier::Tier1Header,
            &t1_bytes,
        )?;

        let t2_bytes = zeroize::Zeroizing::new(serde_json::to_vec(secret)?);
        let (t2_nonce, t2_cipher) = seal_envelope(
            keys.tier2_key(),
            &entry_id,
            EnvelopeTier::Tier2Payload,
            &t2_bytes,
        )?;

        let now = Utc::now().timestamp();
        self.conn.execute(
            "INSERT INTO vault_entries (
                id, tier1_nonce, tier1_ciphertext, tier2_nonce, tier2_ciphertext, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry_id,
                t1_nonce.as_slice(),
                t1_cipher,
                t2_nonce.as_slice(),
                t2_cipher,
                now,
                now
            ],
        )?;

        Ok(entry_id)
    }

    /// Updates an existing credential entry's Tier-1 Header and Tier-2 Secret payload with fresh 192-bit nonces.
    pub fn update_entry(
        &self,
        keys: &VaultKeys,
        entry_id: &str,
        mut header: Tier1Header,
        secret: &Tier2Secret,
    ) -> Result<()> {
        header.has_totp = secret
            .totp_secret
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty());

        let t1_bytes = zeroize::Zeroizing::new(serde_json::to_vec(&header)?);
        let (t1_nonce, t1_cipher) = seal_envelope(
            keys.tier1_key(),
            entry_id,
            EnvelopeTier::Tier1Header,
            &t1_bytes,
        )?;

        let t2_bytes = zeroize::Zeroizing::new(serde_json::to_vec(secret)?);
        let (t2_nonce, t2_cipher) = seal_envelope(
            keys.tier2_key(),
            entry_id,
            EnvelopeTier::Tier2Payload,
            &t2_bytes,
        )?;

        let now = Utc::now().timestamp();
        let affected = self.conn.execute(
            "UPDATE vault_entries
             SET tier1_nonce = ?1, tier1_ciphertext = ?2, tier2_nonce = ?3, tier2_ciphertext = ?4, updated_at = ?5
             WHERE id = ?6",
            params![
                t1_nonce.as_slice(),
                t1_cipher,
                t2_nonce.as_slice(),
                t2_cipher,
                now,
                entry_id
            ],
        )?;

        if affected == 0 {
            return Err(MeadeError::NotFound(entry_id.to_string()));
        }
        Ok(())
    }

    /// Deletes an entry from the vault (`secure_delete = ON` zeroes freed SQLite pages and truncates WAL).
    pub fn delete_entry(&self, entry_id: &str) -> Result<()> {
        let affected = self
            .conn
            .execute("DELETE FROM vault_entries WHERE id = ?1", params![entry_id])?;
        if affected == 0 {
            return Err(MeadeError::NotFound(entry_id.to_string()));
        }
        let _ = self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        Ok(())
    }

    /// Lists all catalogue items by decrypting ONLY Tier-1 Headers.
    /// Tier-2 secret payloads are not even read from the SQLite table during catalogue enumeration.
    pub fn list_catalogue(&self, keys: &VaultKeys) -> Result<Vec<CatalogueItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, tier1_nonce, tier1_ciphertext, created_at, updated_at
             FROM vault_entries
             ORDER BY updated_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;

        let mut items = Vec::new();
        for r in rows {
            let (id, t1_nonce, t1_cipher, created_at, updated_at) = r?;
            let plaintext = open_envelope(
                keys.tier1_key(),
                &id,
                EnvelopeTier::Tier1Header,
                &t1_nonce,
                &t1_cipher,
            )?;
            let header: Tier1Header = serde_json::from_slice(&plaintext)?;
            items.push(CatalogueItem {
                id,
                header,
                created_at,
                updated_at,
            });
        }

        items.sort_by(|a, b| {
            a.header
                .title
                .to_lowercase()
                .cmp(&b.header.title.to_lowercase())
        });
        Ok(items)
    }

    /// Decrypts the Tier-2 Secret Payload for a single specific `entry_id` on demand.
    pub fn decrypt_secret(&self, keys: &VaultKeys, entry_id: &str) -> Result<Tier2Secret> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT tier2_nonce, tier2_ciphertext FROM vault_entries WHERE id = ?1",
                params![entry_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        let (t2_nonce, t2_cipher) =
            row.ok_or_else(|| MeadeError::NotFound(entry_id.to_string()))?;

        let plaintext = open_envelope(
            keys.tier2_key(),
            entry_id,
            EnvelopeTier::Tier2Payload,
            &t2_nonce,
            &t2_cipher,
        )?;
        let secret: Tier2Secret = serde_json::from_slice(&plaintext)?;
        Ok(secret)
    }

    /// Finds a single catalogue item by exact ID or case-insensitive title substring.
    pub fn find_item(&self, keys: &VaultKeys, query: &str) -> Result<CatalogueItem> {
        let items = self.list_catalogue(keys)?;
        let q_lower = query.to_lowercase();
        if let Some(exact) = items
            .iter()
            .find(|i| i.id == query || i.header.title.to_lowercase() == q_lower)
        {
            return Ok(exact.clone());
        }
        items
            .into_iter()
            .find(|i| i.header.title.to_lowercase().contains(&q_lower))
            .ok_or_else(|| MeadeError::NotFound(query.to_string()))
    }

    /// Seeds demo catalogue records if the vault is newly initialized and requested by the user.
    pub fn seed_demo_entries(&self, keys: &VaultKeys) -> Result<usize> {
        let demos = vec![
            (
                Tier1Header {
                    title: "AWS Production Root IAM".to_string(),
                    category: SecretCategory::Login,
                    identity: "admin@example.com".to_string(),
                    url_or_host: "https://console.aws.amazon.com".to_string(),
                    tags: vec!["prod".to_string(), "aws".to_string(), "cloud".to_string()],
                    has_totp: true,
                },
                Tier2Secret {
                    primary_secret: "Xk9#mP2$vL8@qR5!zW3&nF7*".to_string(),
                    totp_secret: Some("JBSWY3DPEHPK3PXP".to_string()),
                    notes: "Root account break-glass login. Use Ctrl+Shift+V queue.".to_string(),
                },
            ),
            (
                Tier1Header {
                    title: "Production Cloud API Key".to_string(),
                    category: SecretCategory::ApiKey,
                    identity: "svc-ci-runner".to_string(),
                    url_or_host: "https://api.example.com".to_string(),
                    tags: vec!["ci".to_string(), "cloud".to_string(), "api".to_string()],
                    has_totp: false,
                },
                Tier2Secret {
                    primary_secret: "api_key_demo_9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c".to_string(),
                    totp_secret: None,
                    notes: "Production API key for automated CI runner pipeline.".to_string(),
                },
            ),
            (
                Tier1Header {
                    title: "Production Bastion Ed25519 SSH Key".to_string(),
                    category: SecretCategory::SshKey,
                    identity: "deploy@192.0.2.10".to_string(),
                    url_or_host: "ssh://192.0.2.10:22".to_string(),
                    tags: vec!["ssh".to_string(), "bastion".to_string(), "infra".to_string()],
                    has_totp: false,
                },
                Tier2Secret {
                    primary_secret: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACB8k9X2mL1pQ7vR4wT9yZ3cN6bM8vK1jH5gF2dS4aP0qQ==\n-----END OPENSSH PRIVATE KEY-----".to_string(),
                    totp_secret: None,
                    notes: "Primary Ed25519 key for production bastion host.".to_string(),
                },
            ),
        ];

        for (hdr, sec) in &demos {
            self.add_entry(keys, hdr.clone(), sec)?;
        }
        Ok(demos.len())
    }

    /// Expose underlying connection for forensic verification tests (e.g. checking raw ciphertexts on disk).
    pub fn raw_connection(&self) -> &Connection {
        &self.conn
    }
}
