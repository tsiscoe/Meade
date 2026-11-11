use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use clap::Parser;
use color_eyre::eyre::WrapErr;
use zeroize::Zeroizing;

use meade::cli::{Commands, DaemonAction, ExportFormat, ImportFormat, MeadeCli};
use meade::crypto::VaultKeys;
use meade::crypto::memlock::{
    clear_os_keyring, load_keys_from_os_keyring, store_keys_in_os_keyring,
};
use meade::daemon::clipboard::{scrub_clipboard, write_secret_to_clipboard};
use meade::daemon::{
    DEFAULT_DAEMON_ADDR, DaemonRequest, DaemonResponse, run_daemon_server_with_idle_timeout,
    send_daemon_request,
};
use meade::db::VaultDb;
use meade::db::models::{Tier1Header, Tier2Secret};
use meade::importer::{
    export_dotenv_str, export_json_str, import_dotenv_str, import_json_str, import_ssh_config_str,
};
use meade::tui::run_interactive_tui;

fn default_vault_path() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".meade").join("vault.db")
    } else {
        PathBuf::from("meade_vault.db")
    }
}

fn prompt_passphrase(
    prompt: &str,
    cli_pass: &Option<String>,
) -> color_eyre::Result<Zeroizing<String>> {
    if let Some(p) = cli_pass {
        return Ok(Zeroizing::new(p.clone()));
    }
    let pass = rpassword::prompt_password(prompt).wrap_err("Failed to read passphrase from TTY")?;
    Ok(Zeroizing::new(pass))
}

async fn resolve_unlocked_keys(db: &VaultDb, cli: &MeadeCli) -> color_eyre::Result<VaultKeys> {
    // 1. Check if the background Daemon already holds valid unlocked keys in VirtualLock RAM
    if let Ok(DaemonResponse::SessionKeys {
        b64_blob: Some(b64),
    }) = send_daemon_request(DEFAULT_DAEMON_ADDR, &DaemonRequest::FetchSessionKeys).await
        && let Ok(decoded) = B64.decode(b64.as_bytes())
        && let Ok(keys) = VaultKeys::from_session_blob(&decoded)
        && db.verify_session_keys(&keys).is_ok()
    {
        return Ok(keys);
    }

    // 2. Check Windows Credential Manager (OS Keyring) if `--keyring` was passed
    if cli.keyring
        && let Ok(keys) = load_keys_from_os_keyring()
        && db.verify_session_keys(&keys).is_ok()
    {
        return Ok(keys);
    }

    // 3. Otherwise derive from master passphrase via Argon2id
    let pass = prompt_passphrase("Enter Meade Master Passphrase: ", &cli.passphrase)?;
    let keys = db.unlock_vault(pass.as_bytes(), false)?;

    // Cache in OS keyring if requested
    if cli.keyring {
        let _ = store_keys_in_os_keyring(&keys);
    }

    // Cache in running Daemon RAM if daemon is active
    let raw = keys.export_session_blob();
    let _ = send_daemon_request(
        DEFAULT_DAEMON_ADDR,
        &DaemonRequest::StoreSessionKeys {
            b64_blob: B64.encode(raw.as_slice()),
        },
    )
    .await;

    Ok(keys)
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    // Terminal safety contract: install color_eyre BEFORE ratatui::init()
    color_eyre::install()?;

    let cli = MeadeCli::parse();
    let vault_path = cli.vault.clone().unwrap_or_else(default_vault_path);

    match cli.command.as_ref().unwrap_or(&Commands::Tui) {
        Commands::Init { seed_demo } => {
            let db = VaultDb::open(&vault_path)?;
            if db.is_initialized()? {
                println!(
                    "[MEADE] Vault at `{}` is already initialized.",
                    vault_path.display()
                );
                return Ok(());
            }
            let pass = prompt_passphrase("Create Meade Master Passphrase: ", &cli.passphrase)?;
            let keys = db.initialize_vault(pass.as_bytes(), false)?;
            if cli.keyring {
                let _ = store_keys_in_os_keyring(&keys);
            }
            let seeded = if *seed_demo {
                db.seed_demo_entries(&keys)?
            } else {
                0
            };
            println!(
                "[MEADE] Initialized Two-Tier AEAD Vault at `{}` ({seeded} demo items seeded).",
                vault_path.display()
            );
        }

        Commands::Tui => {
            let db = VaultDb::open(&vault_path)?;
            let keys = if !db.is_initialized()? {
                let pass = prompt_passphrase(
                    "Initialize New Meade Vault — Enter Master Passphrase: ",
                    &cli.passphrase,
                )?;
                let k = db.initialize_vault(pass.as_bytes(), false)?;
                let _ = db.seed_demo_entries(&k);
                k
            } else {
                resolve_unlocked_keys(&db, &cli).await?
            };

            run_interactive_tui(db, keys).await?;
        }

        Commands::Unlock => {
            let db = VaultDb::open(&vault_path)?;
            let _keys = resolve_unlocked_keys(&db, &cli).await?;
            println!("[MEADE] Vault unlocked and session keys pinned in memory.");
        }

        Commands::Lock => {
            let _ = clear_os_keyring();
            let _ = scrub_clipboard();
            let _ = send_daemon_request(DEFAULT_DAEMON_ADDR, &DaemonRequest::LockSession).await;
            println!(
                "[MEADE] Session locked: OS Keyring purged, Daemon RAM wiped, and Clipboard scrubbed."
            );
        }

        Commands::Add {
            title,
            category,
            identity,
            url,
            tags,
            secret,
            secret_stdin,
            totp,
            notes,
        } => {
            let db = VaultDb::open(&vault_path)?;
            let keys = resolve_unlocked_keys(&db, &cli).await?;
            let resolved_secret: Zeroizing<String> = if *secret_stdin {
                use std::io::Read;
                let mut buf = Zeroizing::new(String::new());
                std::io::stdin().read_to_string(&mut buf)?;
                Zeroizing::new(buf.trim_end_matches(&['\r', '\n'][..]).to_string())
            } else if let Some(s) = secret {
                Zeroizing::new(s.clone())
            } else {
                prompt_passphrase("Enter Primary Secret Value: ", &None)?
            };

            let tag_vec: Vec<String> = tags
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let header = Tier1Header {
                title: title.clone(),
                category: (*category).into(),
                identity: identity.clone(),
                url_or_host: url.clone(),
                tags: tag_vec,
                has_totp: totp.is_some(),
            };
            let sec = Tier2Secret {
                primary_secret: (*resolved_secret).clone(),
                totp_secret: totp.clone(),
                notes: notes.clone(),
            };
            let id = db.add_entry(&keys, header, &sec)?;
            println!(
                "[MEADE] Sealed `{title}` (ID: {id}) in Two-Tier XChaCha20-Poly1305 envelope."
            );
        }

        Commands::List { query } => {
            let db = VaultDb::open(&vault_path)?;
            let keys = resolve_unlocked_keys(&db, &cli).await?;
            let items = db.list_catalogue(&keys)?;
            let q_lower = query.as_deref().unwrap_or("").to_lowercase();

            println!(
                "{:<10} | {:<32} | {:<24} | {:<18}",
                "CATEGORY", "TITLE", "IDENTITY", "TAGS"
            );
            for item in items {
                if !q_lower.is_empty()
                    && !item.header.title.to_lowercase().contains(&q_lower)
                    && !item.header.identity.to_lowercase().contains(&q_lower)
                {
                    continue;
                }
                let tags = item
                    .header
                    .tags
                    .iter()
                    .map(|t| format!("[{t}]"))
                    .collect::<Vec<_>>()
                    .join(" ");
                println!(
                    "{:<10} | {:<32} | {:<24} | {:<18}",
                    item.header.category.short_badge(),
                    item.header.title,
                    item.header.identity,
                    tags
                );
            }
        }

        Commands::Queue { target } => match target.as_str() {
            "next" => {
                let resp =
                    send_daemon_request(DEFAULT_DAEMON_ADDR, &DaemonRequest::AdvanceQueue).await?;
                println!("[MEADE] {resp:?}");
            }
            "scrub" => {
                let _ = scrub_clipboard();
                let _ = send_daemon_request(DEFAULT_DAEMON_ADDR, &DaemonRequest::ScrubNow).await;
                println!("[MEADE] OS clipboard scrubbed clean.");
            }
            "status" => {
                let resp =
                    send_daemon_request(DEFAULT_DAEMON_ADDR, &DaemonRequest::GetStatus).await?;
                println!("[MEADE] {resp:?}");
            }
            query => {
                let db = VaultDb::open(&vault_path)?;
                let keys = resolve_unlocked_keys(&db, &cli).await?;
                let item = db.find_item(&keys, query)?;
                let sec = db.decrypt_secret(&keys, &item.id)?;

                if let Ok(DaemonResponse::QueueUpdated { message, .. }) = send_daemon_request(
                    DEFAULT_DAEMON_ADDR,
                    &DaemonRequest::EnqueueFullCredential {
                        header: item.header.clone(),
                        secret: sec.clone(),
                    },
                )
                .await
                {
                    println!("[MEADE DAEMON] {message}");
                } else {
                    write_secret_to_clipboard(&sec.primary_secret)?;
                    println!(
                        "[MEADE DIRECT] Copied primary secret for `{}` with Win32 privacy flags.",
                        item.header.title
                    );
                }
            }
        },

        Commands::Daemon { action } => match action {
            DaemonAction::Serve { ttl, idle_timeout } => {
                println!(
                    "[MEADE DAEMON] Listening on {DEFAULT_DAEMON_ADDR} | Global Hotkey: Ctrl+Shift+V (fallback Ctrl+Alt+V) | TTL: {ttl}s | Idle Auto-Lock: {idle_timeout}m"
                );
                let idle_dur = std::time::Duration::from_secs(idle_timeout.saturating_mul(60));
                run_daemon_server_with_idle_timeout(DEFAULT_DAEMON_ADDR, *ttl, idle_dur).await?;
            }
            DaemonAction::Next => {
                let resp =
                    send_daemon_request(DEFAULT_DAEMON_ADDR, &DaemonRequest::AdvanceQueue).await?;
                println!("[MEADE DAEMON] {resp:?}");
            }
            DaemonAction::Scrub => {
                let _ = scrub_clipboard();
                let resp =
                    send_daemon_request(DEFAULT_DAEMON_ADDR, &DaemonRequest::ScrubNow).await?;
                println!("[MEADE DAEMON] {resp:?}");
            }
            DaemonAction::Status => {
                let resp =
                    send_daemon_request(DEFAULT_DAEMON_ADDR, &DaemonRequest::GetStatus).await?;
                println!("[MEADE DAEMON] {resp:?}");
            }
            DaemonAction::Stop => {
                let _ = send_daemon_request(DEFAULT_DAEMON_ADDR, &DaemonRequest::Shutdown).await;
                println!("[MEADE DAEMON] Shutdown signal dispatched and clipboard scrubbed.");
            }
        },

        Commands::Import { format, file, tag } => {
            let db = VaultDb::open(&vault_path)?;
            let keys = resolve_unlocked_keys(&db, &cli).await?;
            let content = std::fs::read_to_string(file)?;
            let count = match format {
                ImportFormat::Dotenv => import_dotenv_str(&db, &keys, &content, tag)?,
                ImportFormat::Json => import_json_str(&db, &keys, &content)?,
                ImportFormat::Ssh => import_ssh_config_str(&db, &keys, &content, file.parent())?,
            };
            println!(
                "[MEADE] Imported {count} entries from `{}` into Two-Tier AEAD vault.",
                file.display()
            );
        }

        Commands::Export { format, tag } => {
            let db = VaultDb::open(&vault_path)?;
            let keys = resolve_unlocked_keys(&db, &cli).await?;
            let out = match format {
                ExportFormat::Dotenv => export_dotenv_str(&db, &keys, tag.as_deref())?,
                ExportFormat::Json => export_json_str(&db, &keys)?,
            };
            print!("{}", out.as_str());
        }
    }

    Ok(())
}
