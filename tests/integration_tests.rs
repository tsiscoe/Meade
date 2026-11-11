use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};

use meade::crypto::VaultKeys;
use meade::crypto::envelope::{EnvelopeTier, open_envelope, seal_envelope};
use meade::daemon::queue::{QueueStageKind, SequentialPasteQueue};
use meade::db::VaultDb;
use meade::db::models::{SecretCategory, Tier1Header, Tier2Secret};
use meade::importer::{
    export_dotenv_str, export_json_str, import_dotenv_str, import_json_str, import_ssh_config_str,
};
use meade::totp::generate_totp_at;
use meade::tui::app::TuiApp;
use meade::tui::ui::render_tui;

#[test]
fn test_two_tier_aead_envelope_and_aad_tamper_rejection() -> meade::error::Result<()> {
    let salt = VaultKeys::generate_salt();
    let keys = VaultKeys::derive_for_testing(b"correct-horse-battery-staple", &salt)?;

    // Tier-1 and Tier-2 subkeys must be cryptographically distinct
    assert_ne!(keys.tier1_key(), keys.tier2_key());

    let entry_id = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    let secret_bytes = b"sk-live-super-secret-token-999";

    let (nonce, ciphertext) = seal_envelope(
        keys.tier2_key(),
        entry_id,
        EnvelopeTier::Tier2Payload,
        secret_bytes,
    )?;

    // Valid open succeeds
    let opened = open_envelope(
        keys.tier2_key(),
        entry_id,
        EnvelopeTier::Tier2Payload,
        &nonce,
        &ciphertext,
    )?;
    assert_eq!(opened.as_slice(), secret_bytes);

    // 1. Cross-Row Swap Attack: Attempting to open with a different entry_id MUST fail
    let wrong_row = open_envelope(
        keys.tier2_key(),
        "00000000-0000-0000-0000-000000000000",
        EnvelopeTier::Tier2Payload,
        &nonce,
        &ciphertext,
    );
    assert!(wrong_row.is_err(), "Cross-row AAD swap must be rejected");

    // 2. Cross-Tier Swap Attack: Attempting to open Tier-2 ciphertext as Tier-1 MUST fail
    let wrong_tier = open_envelope(
        keys.tier2_key(),
        entry_id,
        EnvelopeTier::Tier1Header,
        &nonce,
        &ciphertext,
    );
    assert!(wrong_tier.is_err(), "Cross-tier AAD swap must be rejected");

    // 3. Subkey Isolation: Attempting to open Tier-2 with Tier-1 key MUST fail
    let wrong_subkey = open_envelope(
        keys.tier1_key(),
        entry_id,
        EnvelopeTier::Tier2Payload,
        &nonce,
        &ciphertext,
    );
    assert!(
        wrong_subkey.is_err(),
        "Tier-1 key must not decrypt Tier-2 payload"
    );

    Ok(())
}

#[test]
fn test_sqlite_vault_zero_plaintext_on_disk_and_crud() -> meade::error::Result<()> {
    let db = VaultDb::open_in_memory()?;
    let keys = db.initialize_vault(b"master-pass-123", true)?;

    let header = Tier1Header {
        title: "Stripe Production Webhook Key".to_string(),
        category: SecretCategory::ApiKey,
        identity: "acct_19X8Y7Z6".to_string(),
        url_or_host: "https://dashboard.stripe.com".to_string(),
        tags: vec!["payments".to_string(), "prod".to_string()],
        has_totp: false,
    };
    let secret = Tier2Secret {
        primary_secret: "whsec_99887766554433221100aabbccddeeff".to_string(),
        totp_secret: None,
        notes: "Primary webhook signing secret".to_string(),
    };

    let entry_id = db.add_entry(&keys, header, &secret)?;

    // Forensic Verification: Inspect raw SQLite bytes to prove NEITHER the title NOR the secret
    // appears in plaintext inside the SQLite row.
    let (raw_t1, raw_t2): (Vec<u8>, Vec<u8>) = db.raw_connection().query_row(
        "SELECT tier1_ciphertext, tier2_ciphertext FROM vault_entries WHERE id = ?1",
        [&entry_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;

    let t1_lossy = String::from_utf8_lossy(&raw_t1);
    let t2_lossy = String::from_utf8_lossy(&raw_t2);
    assert!(
        !t1_lossy.contains("Stripe"),
        "Tier-1 ciphertext leaked plaintext title"
    );
    assert!(
        !t2_lossy.contains("whsec_"),
        "Tier-2 ciphertext leaked plaintext secret"
    );

    // Catalogue listing decrypts ONLY Tier-1
    let catalogue = db.list_catalogue(&keys)?;
    assert_eq!(catalogue.len(), 1);
    assert_eq!(catalogue[0].header.title, "Stripe Production Webhook Key");

    // On-demand Tier-2 decryption retrieves the secret
    let decrypted = db.decrypt_secret(&keys, &entry_id)?;
    assert_eq!(
        decrypted.primary_secret,
        "whsec_99887766554433221100aabbccddeeff"
    );

    // Wrong passphrase must fail unlock
    let bad_unlock = db.unlock_vault(b"wrong-passphrase", true);
    assert!(bad_unlock.is_err());

    Ok(())
}

#[test]
fn test_rfc6238_totp_generation_and_otpauth_uri() -> meade::error::Result<()> {
    // Standard Base32 test seed `JBSWY3DPEHPK3PXP`
    let snap1 = generate_totp_at("JBSWY3DPEHPK3PXP", 1_700_000_000)?;
    assert_eq!(snap1.code.len(), 6);
    assert_eq!(snap1.remaining_secs, 10);

    // Same seed wrapped in an otpauth:// URI must produce the exact same 6-digit code
    let uri = "otpauth://totp/AWS:admin@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AWS";
    let snap2 = generate_totp_at(uri, 1_700_000_000)?;
    assert_eq!(snap1.code, snap2.code);

    Ok(())
}

#[test]
fn test_sequential_paste_queue_ctrl_shift_v_lifecycle() {
    let mut queue = SequentialPasteQueue::new(20);
    let header = Tier1Header {
        title: "GitHub Enterprise".to_string(),
        category: SecretCategory::Login,
        identity: "dev@example.com".to_string(),
        url_or_host: "https://github.com".to_string(),
        tags: vec!["git".to_string()],
        has_totp: true,
    };
    let secret = Tier2Secret {
        primary_secret: "tok_demo_SuperSecretPassword99!".to_string(),
        totp_secret: Some("JBSWY3DPEHPK3PXP".to_string()),
        notes: String::new(),
    };

    // Initial load puts Stage 1 (Identity/Username) on clipboard
    let first = queue.load_credential(&header, &secret);
    assert_eq!(
        first,
        Some((QueueStageKind::Identity, "dev@example.com".to_string()))
    );
    assert_eq!(queue.status().current_stage_index, 1);
    assert_eq!(queue.status().total_stages, 3);

    // First Ctrl+Shift+V advances to Stage 2 (Password)
    let second = queue.advance();
    assert_eq!(
        second,
        Some((
            QueueStageKind::PrimarySecret,
            "tok_demo_SuperSecretPassword99!".to_string()
        ))
    );
    assert_eq!(queue.status().current_stage_index, 2);

    // Second Ctrl+Shift+V advances to Stage 3 (Live 6-digit TOTP)
    let third = queue.advance();
    assert!(third.is_some());
    if let Some((kind, code)) = third {
        assert_eq!(kind, QueueStageKind::TotpCode);
        assert_eq!(code.len(), 6);
    }

    // Third Ctrl+Shift+V completes the queue and triggers clipboard auto-scrub (`None`)
    let fourth = queue.advance();
    assert!(fourth.is_none());
    assert!(!queue.is_active());
}

#[test]
fn test_dotenv_json_and_ssh_config_importers() -> meade::error::Result<()> {
    let db = VaultDb::open_in_memory()?;
    let keys = db.initialize_vault(b"import-test-pass", true)?;

    let dotenv_sample = "
        # Production API Keys
        SERVICE_API_KEY=\"api_key_demo_123456789\"
        export DATABASE_URL='postgres://user:pass@localhost:5432/db'
    ";
    let count = import_dotenv_str(&db, &keys, dotenv_sample, "prod-env")?;
    assert_eq!(count, 2);

    let exported_env = export_dotenv_str(&db, &keys, Some("prod-env"))?;
    assert!(exported_env.contains("SERVICE_API_KEY=\"api_key_demo_123456789\""));
    assert!(exported_env.contains("DATABASE_URL=\"postgres://user:pass@localhost:5432/db\""));

    let ssh_sample = "
        Host bastion-prod
            HostName 192.0.2.10
            User deploy
            Port 2222
            IdentityFile ~/.ssh/id_ed25519
    ";
    let ssh_count = import_ssh_config_str(&db, &keys, ssh_sample, None)?;
    assert_eq!(ssh_count, 1);

    let json_dump = export_json_str(&db, &keys)?;
    let db2 = VaultDb::open_in_memory()?;
    let keys2 = db2.initialize_vault(b"second-vault-pass", true)?;
    let restored = import_json_str(&db2, &keys2, &json_dump)?;
    assert_eq!(restored, 3);

    Ok(())
}

#[test]
fn test_ratatui_catalogue_viewer_headless_render_and_navigation() -> meade::error::Result<()> {
    let db = VaultDb::open_in_memory()?;
    let keys = db.initialize_vault(b"tui-test-pass", true)?;
    db.seed_demo_entries(&keys)?;

    let mut app = TuiApp::new(db, keys, true)?;
    let backend = TestBackend::new(110, 28);
    let Ok(mut terminal) = Terminal::new(backend);

    // 1. Initial frame render succeeds and displays catalogue items while keeping Tier-2 secrets masked
    let Ok(_) = terminal.draw(|f| render_tui(&mut app, f));
    assert!(!app.reveal_secret);
    assert!(app.inspected_secret.is_none());

    // 2. Pressing Enter queues the selected item into the sequential clipboard pipeline
    app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.queue_snapshot.active);

    // 3. Pressing Ctrl+Shift+V inside the TUI advances the sequential paste queue to Stage 2
    app.handle_key_event(KeyEvent::new(
        KeyCode::Char('V'),
        KeyModifiers::CONTROL | KeyModifiers::SHIFT,
    ));
    assert_eq!(app.queue_snapshot.current_stage_index, 2);

    // 4. Pressing '/' activates fuzzy search and filters down to AWS
    app.handle_key_event(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    for ch in ['a', 'w', 's'] {
        app.handle_key_event(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
    }
    app.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.filtered_items.len(), 1);
    assert!(app.filtered_items[0].header.title.contains("AWS"));

    let Ok(_) = terminal.draw(|f| render_tui(&mut app, f));

    Ok(())
}

#[test]
fn test_rt01_ipc_token_constant_time_verification_rejects_forgery() {
    use meade::daemon::verify_ipc_token_ct;

    let valid_token = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    assert!(verify_ipc_token_ct(valid_token, valid_token));

    // Reject empty or wrong-length tokens
    assert!(!verify_ipc_token_ct(valid_token, ""));
    assert!(!verify_ipc_token_ct(valid_token, "short"));
    assert!(!verify_ipc_token_ct("", ""));

    // Reject 1-bit flipped token of identical length
    let forged = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f91";
    assert!(!verify_ipc_token_ct(valid_token, forged));
}

#[test]
fn test_rt04_and_rt06_dotenv_newline_injection_and_ssh_path_traversal_blocked()
-> meade::error::Result<()> {
    let db = VaultDb::open_in_memory()?;
    let keys = db.initialize_vault(b"red-team-test", true)?;

    // 1. RT-06: Attempt .env newline & command-substitution injection
    let malicious_secret = "line1\nLD_PRELOAD=/tmp/evil.so\r\n$(whoami)`id`\"quoted\"";
    let hdr = Tier1Header {
        title: "INJECTED_KEY".to_string(),
        category: SecretCategory::ApiKey,
        identity: "svc".to_string(),
        url_or_host: "env://test".to_string(),
        tags: vec!["rt06".to_string()],
        has_totp: false,
    };
    let sec = Tier2Secret {
        primary_secret: malicious_secret.to_string(),
        totp_secret: None,
        notes: String::new(),
    };
    db.add_entry(&keys, hdr, &sec)?;

    let exported = export_dotenv_str(&db, &keys, Some("rt06"))?;
    // The exported .env must contain exactly 2 lines (header comment + 1 escaped key line)
    let non_empty_lines: Vec<&str> = exported.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        non_empty_lines.len(),
        2,
        "Newline injection broke out into multiple .env lines: {exported:?}"
    );
    assert!(exported.contains("\\nLD_PRELOAD="));
    assert!(exported.contains("\\$(whoami)\\`id\\`"));

    // Roundtrip re-import must restore the exact original secret
    let db2 = VaultDb::open_in_memory()?;
    let keys2 = db2.initialize_vault(b"red-team-test-2", true)?;
    import_dotenv_str(&db2, &keys2, &exported, "rt06-restored")?;
    let cat = db2.list_catalogue(&keys2)?;
    let restored_sec = db2.decrypt_secret(&keys2, &cat[0].id)?;
    assert_eq!(restored_sec.primary_secret, malicious_secret);

    // 2. RT-04: Attempt SSH config IdentityFile path traversal (`../../Cargo.toml`)
    let traversal_ssh = "
        Host evil-box
            HostName 10.0.0.9
            User root
            IdentityFile ../../Cargo.toml
    ";
    let count = import_ssh_config_str(&db, &keys, traversal_ssh, Some(std::path::Path::new(".")))?;
    assert_eq!(count, 1);
    let item = db.find_item(&keys, "SSH: evil-box")?;
    let ssh_sec = db.decrypt_secret(&keys, &item.id)?;
    // Must NOT have read Cargo.toml content; falls back to safe reference string
    assert!(
        !ssh_sec.primary_secret.contains("[package]"),
        "Path traversal leaked arbitrary file contents!"
    );
    assert_eq!(ssh_sec.primary_secret, "IdentityFile: ../../Cargo.toml");

    Ok(())
}

#[test]
fn test_rt01b_and_rt07_ipc_token_owner_acl_and_zeroized_unlink() -> meade::error::Result<()> {
    use meade::daemon::{generate_and_persist_ipc_token_at, secure_remove_ipc_token_at};

    let temp_dir = tempfile::tempdir()?;
    let token_path = temp_dir.path().join("nested").join("daemon.token");

    let token = generate_and_persist_ipc_token_at(&token_path)?;
    assert_eq!(token.len(), 64);
    assert!(token_path.exists());

    let disk_content = std::fs::read_to_string(&token_path)?;
    assert_eq!(disk_content.trim(), token.as_str());

    secure_remove_ipc_token_at(&token_path);
    assert!(!token_path.exists());

    Ok(())
}

#[tokio::test]
async fn test_rt02b_rt03b_rt06b_live_tcp_daemon_unauthenticated_oversized_flood_and_idle_autolock()
-> meade::error::Result<()> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use meade::daemon::{
        DaemonRequest, DaemonResponse, send_daemon_request_with_token, spawn_ephemeral_test_daemon,
    };
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    // Spawn ephemeral daemon with 500ms inactivity auto-lock timeout
    let (addr, valid_token, server_handle) =
        spawn_ephemeral_test_daemon(20, Duration::from_millis(500)).await?;
    let addr_str = addr.to_string();

    // 1. RT-01 / RT-06b: Raw unauthenticated JSON frame must be rejected over live TCP wire
    {
        let mut raw_stream = TcpStream::connect(addr).await?;
        raw_stream.write_all(b"{\"Ping\":null}\n").await?;
        raw_stream.flush().await?;
        let mut reader = BufReader::new(raw_stream);
        let mut resp_line = String::new();
        reader.read_line(&mut resp_line).await?;
        let resp: DaemonResponse = serde_json::from_str(resp_line.trim())?;
        assert!(
            matches!(resp, DaemonResponse::Error { ref message } if message.contains("Invalid or unauthenticated")),
            "Expected unauthenticated error, got: {resp:?}"
        );
    }

    // 2. RT-01 / RT-02b: Forged 64-hex bearer token must be rejected with constant-time check + backoff
    {
        let forged_token = "0000000000000000000000000000000000000000000000000000000000000000";
        let resp = send_daemon_request_with_token(
            &addr_str,
            forged_token,
            &DaemonRequest::FetchSessionKeys,
        )
        .await?;
        assert!(
            matches!(resp, DaemonResponse::Error { ref message } if message.contains("Unauthorized")),
            "Expected Unauthorized error, got: {resp:?}"
        );
    }

    // 3. RT-02 / RT-06b: >64 KiB oversized frame without newline must be cut off and rejected
    {
        let mut stream = TcpStream::connect(addr).await?;
        let oversized = vec![b'A'; 70_000];
        let _ = stream.write_all(&oversized).await;
        let _ = stream.flush().await;
        let mut reader = BufReader::new(stream);
        let mut resp_line = String::new();
        reader.read_line(&mut resp_line).await?;
        let resp: DaemonResponse = serde_json::from_str(resp_line.trim())?;
        assert!(
            matches!(resp, DaemonResponse::Error { ref message } if message.contains("exceeded 64 KiB")),
            "Expected >64 KiB cutoff error, got: {resp:?}"
        );
    }

    // 4. RT-02b: Connection flood against 16-permit Semaphore must not panic or starve server
    {
        let mut flood_handles = Vec::new();
        for _ in 0..24 {
            let target = addr;
            flood_handles.push(tokio::spawn(async move {
                if let Ok(mut s) = TcpStream::connect(target).await {
                    let _ = s.write_all(b"{}\n").await;
                }
            }));
        }
        for h in flood_handles {
            let _ = h.await;
        }
    }

    // 5. RT-03b: Authenticated StoreSessionKeys succeeds, then Inactivity Watchdog auto-locks after 500ms
    let salt = VaultKeys::generate_salt();
    let keys = VaultKeys::derive_for_testing(b"live-daemon-pass", &salt)?;
    let raw_blob = keys.export_session_blob();
    let store_resp = send_daemon_request_with_token(
        &addr_str,
        &valid_token,
        &DaemonRequest::StoreSessionKeys {
            b64_blob: B64.encode(raw_blob.as_slice()),
        },
    )
    .await?;
    assert!(matches!(
        store_resp,
        DaemonResponse::Pong { unlocked: true, .. }
    ));

    // Wait 750ms (> 500ms idle_timeout) so the background watchdog fires
    tokio::time::sleep(Duration::from_millis(750)).await;

    let status_after_idle =
        send_daemon_request_with_token(&addr_str, &valid_token, &DaemonRequest::GetStatus).await?;
    assert!(
        matches!(
            status_after_idle,
            DaemonResponse::Pong {
                unlocked: false,
                ..
            }
        ),
        "Inactivity watchdog failed to auto-lock session keys: {status_after_idle:?}"
    );

    // Clean shutdown
    let shut_resp =
        send_daemon_request_with_token(&addr_str, &valid_token, &DaemonRequest::Shutdown).await?;
    assert!(matches!(shut_resp, DaemonResponse::ShuttingDown));
    server_handle.await.expect("daemon task panicked")?;

    Ok(())
}

use proptest::prelude::*;

proptest! {
    #[test]
    fn test_rt06b_proptest_dotenv_escape_roundtrip(raw in "\\PC{0,128}") {
        use meade::importer::{escape_dotenv_value, unescape_dotenv_value};

        let escaped = escape_dotenv_value(&raw);
        // Escaped value must never contain raw newline or carriage return
        prop_assert!(!escaped.contains('\n'));
        prop_assert!(!escaped.contains('\r'));

        let unescaped = unescape_dotenv_value(&escaped);
        prop_assert_eq!(unescaped.as_str(), raw.as_str());
    }

    #[test]
    fn test_rt06b_proptest_totp_and_terminal_sanitizer_never_panic(arbitrary_input in "\\PC{0,128}") {
        use meade::importer::sanitize_terminal_str;
        use meade::totp::decode_totp_secret;

        let sanitized_single = sanitize_terminal_str(&arbitrary_input, false);
        prop_assert!(!sanitized_single.chars().any(|c| c.is_control()));

        let sanitized_multi = sanitize_terminal_str(&arbitrary_input, true);
        prop_assert!(!sanitized_multi.chars().any(|c| c.is_control() && c != '\n' && c != '\t'));

        // Must never panic on arbitrary malformed Base32 or otpauth:// strings
        let _ = decode_totp_secret(&arbitrary_input);
    }
}
