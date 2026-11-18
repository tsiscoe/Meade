use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::VaultKeys;
use crate::db::VaultDb;
use crate::db::models::{SecretCategory, Tier1Header, Tier2Secret};
use crate::error::{MeadeError, Result};

/// Maximum permitted SSH private key file size (64 KiB) to prevent arbitrary large-file DoS (CWE-400).
const MAX_SSH_KEY_FILE_BYTES: u64 = 65_536;

/// Serializable bundle used for full JSON import/export across environments.
/// Automatically zeroizes sensitive fields when dropped from memory (CWE-316).
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ExportedEntry {
    pub title: String,
    #[zeroize(skip)]
    pub category: SecretCategory,
    pub identity: String,
    pub url_or_host: String,
    pub tags: Vec<String>,
    pub primary_secret: String,
    pub totp_secret: Option<String>,
    pub notes: String,
}

/// Sanitizes untrusted imported strings by stripping terminal ANSI escape / ASCII control characters
/// (except `\n` and `\t` for notes) to prevent terminal escape sequence injection (CWE-150).
pub fn sanitize_terminal_str(input: &str, allow_newlines: bool) -> String {
    input
        .chars()
        .filter(|&c| {
            if allow_newlines && (c == '\n' || c == '\t') {
                true
            } else {
                !c.is_control()
            }
        })
        .collect()
}

/// Escapes a secret string for safe single-line `.env` double-quoted output, neutralizing
/// newline injection (`\n`, `\r`), command substitution (`$`, `` ` ``), and quote breakout (`"`, `\`) (CWE-158).
pub fn escape_dotenv_value(raw: &str) -> Zeroizing<String> {
    let mut out = String::with_capacity(raw.len() + 8);
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '$' => out.push_str("\\$"),
            '`' => out.push_str("\\`"),
            _ => out.push(ch),
        }
    }
    Zeroizing::new(out)
}

/// Unescapes a double-quoted `.env` value back into its raw secret string.
pub fn unescape_dotenv_value(escaped: &str) -> Zeroizing<String> {
    let mut out = String::with_capacity(escaped.len());
    let mut chars = escaped.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('$') => out.push('$'),
                Some('`') => out.push('`'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    Zeroizing::new(out)
}

/// Imports a `.env` file into the vault, creating an `ApiKey` entry for each `KEY=VALUE` pair.
pub fn import_dotenv_str(
    db: &VaultDb,
    keys: &VaultKeys,
    content: &str,
    tag_prefix: &str,
) -> Result<usize> {
    let mut imported = 0;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim);
        if let Some((raw_key, raw_val)) = line.split_once('=') {
            let key_name = sanitize_terminal_str(raw_key.trim(), false);
            if key_name.is_empty() {
                continue;
            }
            let trimmed_val = raw_val.trim();
            let val: Zeroizing<String> = if trimmed_val.starts_with('"')
                && trimmed_val.ends_with('"')
                && trimmed_val.len() >= 2
            {
                unescape_dotenv_value(&trimmed_val[1..trimmed_val.len() - 1])
            } else if trimmed_val.starts_with('\'')
                && trimmed_val.ends_with('\'')
                && trimmed_val.len() >= 2
            {
                Zeroizing::new(trimmed_val[1..trimmed_val.len() - 1].to_string())
            } else {
                Zeroizing::new(trimmed_val.to_string())
            };

            let header = Tier1Header {
                title: key_name.clone(),
                category: SecretCategory::ApiKey,
                identity: key_name,
                url_or_host: "env://local".to_string(),
                tags: vec![
                    "dotenv".to_string(),
                    sanitize_terminal_str(tag_prefix, false),
                ],
                has_totp: false,
            };
            let secret = Tier2Secret {
                primary_secret: (*val).clone(),
                totp_secret: None,
                notes: format!("Imported from .env ({tag_prefix})"),
            };

            db.add_entry(keys, header, &secret)?;
            imported += 1;
        }
    }

    Ok(imported)
}

/// Exports matching `ApiKey` (or all) entries from the vault back into `.env` format inside a `Zeroizing<String>`.
pub fn export_dotenv_str(
    db: &VaultDb,
    keys: &VaultKeys,
    filter_tag: Option<&str>,
) -> Result<Zeroizing<String>> {
    let catalogue = db.list_catalogue(keys)?;
    let mut out = Zeroizing::new(String::from("# Generated by Meade Cryptographic Vault\n"));

    for item in catalogue {
        if let Some(tag) = filter_tag
            && !item.header.tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
        {
            continue;
        }
        if item.header.category == SecretCategory::ApiKey {
            let sec = db.decrypt_secret(keys, &item.id)?;
            let env_key: String = item
                .header
                .title
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '_' {
                        c.to_ascii_uppercase()
                    } else {
                        '_'
                    }
                })
                .collect();
            let escaped = escape_dotenv_value(&sec.primary_secret);
            out.push_str(&format!("{env_key}=\"{}\"\n", escaped.as_str()));
        }
    }

    Ok(out)
}

/// Verifies that an `IdentityFile` path does not contain parent-directory traversal (`..`) components (CWE-22),
/// resolves canonical filesystem paths (`std::fs::canonicalize`) to neutralize symlink/junction escapes (`RT-04b`),
/// enforces containment inside `~/.ssh` or `base_dir`, and reads at most 64 KiB only if the file is a PEM/OpenSSH key.
fn safe_read_ssh_identity_file(
    raw_path: &str,
    base_dir: Option<&Path>,
) -> Option<Zeroizing<String>> {
    let (allowed_root, candidate_path) = if let Some(stripped) = raw_path.strip_prefix("~/") {
        let p = Path::new(stripped);
        if p.components().any(|c| matches!(c, Component::ParentDir)) {
            return None;
        }
        let home = dirs::home_dir()?;
        (home.join(".ssh"), home.join(p))
    } else {
        let p = Path::new(raw_path);
        if p.components().any(|c| matches!(c, Component::ParentDir)) {
            return None;
        }
        if p.is_absolute() {
            let ssh_dir = dirs::home_dir()?.join(".ssh");
            (ssh_dir, p.to_path_buf())
        } else {
            let dir = base_dir?;
            (dir.to_path_buf(), dir.join(p))
        }
    };

    let canonical_root = std::fs::canonicalize(&allowed_root).ok()?;
    let canonical_target = std::fs::canonicalize(&candidate_path).ok()?;
    if !canonical_target.starts_with(&canonical_root) {
        return None;
    }

    let meta = std::fs::metadata(&canonical_target).ok()?;
    if !meta.is_file() || meta.len() > MAX_SSH_KEY_FILE_BYTES {
        return None;
    }

    let content = Zeroizing::new(std::fs::read_to_string(&canonical_target).ok()?);
    if content.contains("-----BEGIN ") {
        Some(content)
    } else {
        None
    }
}

/// Imports an OpenSSH `~/.ssh/config` file, safely reading referenced `IdentityFile` private keys when valid.
pub fn import_ssh_config_str(
    db: &VaultDb,
    keys: &VaultKeys,
    ssh_config_content: &str,
    base_dir: Option<&Path>,
) -> Result<usize> {
    #[derive(Default)]
    struct SshHostBlock {
        host_alias: String,
        hostname: String,
        user: String,
        port: String,
        identity_file: String,
    }

    let mut blocks: Vec<SshHostBlock> = Vec::new();
    let mut current: Option<SshHostBlock> = None;

    for raw_line in ssh_config_content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(keyword) = parts.next() else {
            continue;
        };
        let rest: String = sanitize_terminal_str(&parts.collect::<Vec<_>>().join(" "), false);
        if rest.is_empty() {
            continue;
        }

        match keyword.to_ascii_lowercase().as_str() {
            "host" => {
                if let Some(prev) = current.take()
                    && prev.host_alias != "*"
                {
                    blocks.push(prev);
                }
                current = Some(SshHostBlock {
                    host_alias: rest,
                    port: "22".to_string(),
                    ..Default::default()
                });
            }
            "hostname" => {
                if let Some(cur) = current.as_mut() {
                    cur.hostname = rest;
                }
            }
            "user" => {
                if let Some(cur) = current.as_mut() {
                    cur.user = rest;
                }
            }
            "port" => {
                if let Some(cur) = current.as_mut() {
                    cur.port = rest;
                }
            }
            "identityfile" => {
                if let Some(cur) = current.as_mut() {
                    cur.identity_file = rest.trim_matches('"').to_string();
                }
            }
            _ => {}
        }
    }

    if let Some(last) = current.take()
        && last.host_alias != "*"
    {
        blocks.push(last);
    }

    let mut count = 0;
    for b in blocks {
        let host_target = if b.hostname.is_empty() {
            b.host_alias.clone()
        } else {
            b.hostname.clone()
        };
        let identity = if b.user.is_empty() {
            format!("ssh@{host_target}")
        } else {
            format!("{}@{}", b.user, host_target)
        };

        let mut key_payload = Zeroizing::new(format!("ssh {} -p {}", identity, b.port));
        if !b.identity_file.is_empty() {
            if let Some(pem) = safe_read_ssh_identity_file(&b.identity_file, base_dir) {
                key_payload = pem;
            } else {
                key_payload = Zeroizing::new(format!("IdentityFile: {}", b.identity_file));
            }
        }

        let header = Tier1Header {
            title: format!("SSH: {}", b.host_alias),
            category: SecretCategory::SshKey,
            identity,
            url_or_host: format!("ssh://{}:{}", host_target, b.port),
            tags: vec!["ssh".to_string(), "ssh-config".to_string()],
            has_totp: false,
        };
        let secret = Tier2Secret {
            primary_secret: (*key_payload).clone(),
            totp_secret: None,
            notes: format!("Imported from SSH Host block `{}`", b.host_alias),
        };
        db.add_entry(keys, header, &secret)?;
        count += 1;
    }

    Ok(count)
}

/// Exports all vault entries to a structured JSON string wrapped in `Zeroizing<String>`.
pub fn export_json_str(db: &VaultDb, keys: &VaultKeys) -> Result<Zeroizing<String>> {
    let catalogue = db.list_catalogue(keys)?;
    let mut exported = Vec::with_capacity(catalogue.len());

    for item in catalogue {
        let sec = db.decrypt_secret(keys, &item.id)?;
        exported.push(ExportedEntry {
            title: item.header.title,
            category: item.header.category,
            identity: item.header.identity,
            url_or_host: item.header.url_or_host,
            tags: item.header.tags,
            primary_secret: sec.primary_secret.clone(),
            totp_secret: sec.totp_secret.clone(),
            notes: sec.notes.clone(),
        });
    }

    let serialized = serde_json::to_string_pretty(&exported).map_err(MeadeError::from)?;
    Ok(Zeroizing::new(serialized))
}

/// Imports entries from a JSON string produced by `export_json_str`, sanitizing terminal control characters.
pub fn import_json_str(db: &VaultDb, keys: &VaultKeys, json_str: &str) -> Result<usize> {
    let entries: Vec<ExportedEntry> = serde_json::from_str(json_str)?;
    let count = entries.len();
    for entry in entries {
        let header = Tier1Header {
            title: sanitize_terminal_str(&entry.title, false),
            category: entry.category,
            identity: sanitize_terminal_str(&entry.identity, false),
            url_or_host: sanitize_terminal_str(&entry.url_or_host, false),
            tags: entry
                .tags
                .iter()
                .map(|t| sanitize_terminal_str(t, false))
                .collect(),
            has_totp: entry.totp_secret.is_some(),
        };
        let secret = Tier2Secret {
            primary_secret: entry.primary_secret.clone(),
            totp_secret: entry.totp_secret.clone(),
            notes: sanitize_terminal_str(&entry.notes, true),
        };
        db.add_entry(keys, header, &secret)?;
    }
    Ok(count)
}
