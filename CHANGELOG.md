# Changelog

All notable changes to **Meade** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2026-11-11

### Security (Second-Wave Pre-Release Security Hardening & CI Parity)
- **[RT-01b / RT-07] Strict Owner-Only NTFS DACLs & Zeroized Token Unlink (`src/db/mod.rs`, `src/daemon/mod.rs`):** Enforced explicit owner-only ACLs (`icacls /inheritance:r` on Windows and `0700`/`0600` on Unix) on `~/.meade/daemon.token` and `vault.db` via `enforce_owner_only_acl()`, and added `secure_remove_ipc_token()` to overwrite the 64-byte token file with zeros before unlinking on daemon shutdown.
- **[RT-02b] Bounded Concurrent IPC Semaphore & Auth Backoff (`src/daemon/mod.rs`):** Wrapped the daemon TCP accept loop in a 16-permit `tokio::sync::Semaphore` (`MAX_CONCURRENT_IPC_CLIENTS = 16`) with immediate non-blocking drop on connection floods, plus a 100ms backoff delay (`AUTH_FAILURE_BACKOFF`) on failed bearer-token attempts.
- **[RT-03b] Daemon Inactivity Auto-Lock Watchdog (`src/daemon/mod.rs`, `src/cli.rs`):** Added `--idle-timeout <MINS>` (default `15m`) to `meade daemon serve` and a background watchdog that automatically drops `VaultKeys` (triggering `Zeroize` + `VirtualUnlock`), clears the paste queue, and scrubs the OS clipboard when idle.
- **[RT-04b] Canonical Symlink Containment & TUI Render Sanitization (`src/importer.rs`, `src/tui/ui.rs`):** Enforced `std::fs::canonicalize` containment inside `~/.ssh` or `base_dir` for SSH `IdentityFile` imports to block symlink/junction escapes, and added `sanitize_terminal_str` at Ratatui table render boundaries.
- **[RT-05b] ANSSI Unsafe FFI Compliance & Fallback Hotkey (`src/daemon/mod.rs`, `Cargo.toml`):** Replaced `std::mem::zeroed()` with `MaybeUninit::<MSG>::zeroed().assume_init()` per ANSSI Rust Rule 3, added automatic `Ctrl+Alt+V` fallback hotkey registration when `Ctrl+Shift+V` collides, and enforced `clippy::undocumented_unsafe_blocks = "deny"`.
- **[RT-06b] Live TCP Wire Exploit Suite & `proptest` Fuzzing (`tests/integration_tests.rs`):** Added live ephemeral-port daemon socket exploit tests (unauthenticated raw frames, forged bearer tokens, >64 KiB payload cutoffs, 24-client connection floods, and idle auto-lock verification) plus 256-case `proptest` fuzz harnesses for `.env`, `otpauth://`, and terminal sanitization.
- **[CI] Cross-Platform Matrix & RustSec Audit Gate (`.github/workflows/ci.yml`, `Cargo.toml`):** Removed unnecessary `apt-get install libxcb*-dev` step (since `arboard` uses pure-Rust `x11rb` and `keyring` uses pure-Rust `linux-keyutils`), expanded matrix to `[windows-latest, ubuntu-latest, macos-latest]`, added `Swatinem/rust-cache@v2`, integrated `cargo audit`, and upgraded `rusqlite` to `0.42` (`libsqlite3-sys >= 0.39.0`) to remediate `RUSTSEC-2026-0459` (`CVE-2026-119375`).

---

## [0.1.1] - 2026-11-11

### Security (Red Team Recon Pre-Public Hardening)
- **[RT-01] Authenticated Localhost IPC (`src/daemon/mod.rs`):** Added a 256-bit (64-hex-char) CSPRNG per-user bearer token (`~/.meade/daemon.token`, `0600` permissions) verified in constant time via `subtle::ConstantTimeEq` on every `AuthenticatedDaemonRequest` frame, neutralizing unauthenticated localhost TCP key exfiltration (CWE-306).
- **[RT-02] Bounded IPC Frames & Socket Timeouts (`src/daemon/mod.rs`):** Enforced a hard 64 KiB frame ceiling (`AsyncReadExt::take(65_536)`) and a 2-second read/write socket timeout (`IPC_SOCKET_TIMEOUT`) to prevent memory exhaustion and Slowloris socket stalls (CWE-770 / CWE-400).
- **[RT-03] Zeroized Serde Buffers & Stdin Secret Ingestion (`src/db/mod.rs`, `src/importer.rs`, `src/cli.rs`):** Wrapped all intermediate `Tier1Header`, IPC frame, `.env`, and JSON export serialization buffers in `Zeroizing<T>`, added `ZeroizeOnDrop` to `ExportedEntry`, and added `--secret-stdin` / interactive TTY prompt support to `meade add` so secrets never need to be passed on the process command line (CWE-316 / CWE-214).
- **[RT-04] Hardened SSH `IdentityFile` Path & Size Guards (`src/importer.rs`):** Restricted `import_ssh_config_str` to reject parent-directory traversal (`..`), enforce `~/.ssh` containment on absolute paths, cap file reads at 64 KiB, and verify `-----BEGIN ` PEM markers before ingestion (CWE-22).
- **[RT-05] Win32 Clipboard FFI Ownership & Retry Hardening (`src/daemon/clipboard.rs`):** Added a 5-attempt (5ms backoff) retry loop around `OpenClipboard` and explicit `GlobalFree(hmem)` cleanup when `GlobalLock` or `SetClipboardData` returns null (CWE-401).
- **[RT-06] Dotenv Escape & Terminal Control Character Sanitization (`src/importer.rs`):** Escaped `\n`, `\r`, `"`, `\`, `$`, and `` ` `` in `.env` exports and stripped ASCII control characters from imported metadata to prevent `.env` newline injection and terminal escape injection (CWE-158 / CWE-150).
- **[RT-07] Explicit Unix `0700` / `0600` Permissions & Reproducible CI:** Enforced `0700` directory and `0600` file permissions on Unix targets, committed `Cargo.lock` for deterministic supply-chain builds, and added `.github/workflows/ci.yml`.

---

## [0.1.0] - 2026-10-29

### Added
- **Two-Tier Pure-Rust AEAD Cryptographic Engine (`src/crypto/`):**
  - `Argon2id` (`v0x13`, 64 MiB memory, 3 iterations, 4 lanes) root key derivation with 256-bit CSPRNG salts.
  - `HKDF-SHA256` domain separation splitting the root key into isolated `Tier-1 Catalogue Header` and `Tier-2 Secret Payload` subkeys plus an $O(1)$ vault canary verifier.
  - `XChaCha20-Poly1305` (192-bit nonces) per-record encryption with row-bound Associated Data (`AAD = "meade-aad-v1" || tier || entry_uuid`) to prevent cross-row and cross-tier ciphertext swapping.
- **Memory Pinning & OS Keyring Custody (`src/crypto/memlock.rs`):**
  - `PinnedKey` heap wrapper locking 256-bit subkeys in physical RAM via Win32 `VirtualLock` and wiping via `Zeroize` prior to `VirtualUnlock`.
  - Optional Windows Credential Manager (`keyring` crate DPAPI) session key caching (`--keyring`).
- **SQLite WAL Vault Engine (`src/db/`):**
  - Self-contained bundled SQLite 3 storage configured with `journal_mode = WAL`, `foreign_keys = ON`, and `secure_delete = ON`.
  - Strict separation between `list_catalogue()` (decrypts Tier-1 headers only) and `decrypt_secret()` (single-row Tier-2 decryption on demand).
- **Clipboard Interceptor Daemon & Sequential Paste Queue (`src/daemon/`):**
  - Background TCP IPC daemon (`127.0.0.1:49731`) with in-RAM session key custody and 500ms TTL auto-scrubber loop.
  - Global Windows `Ctrl+Shift+V` hotkey listener (`RegisterHotKey`) advancing the `SequentialPasteQueue` through `Stage 1 (Identity) -> Stage 2 (Primary Secret) -> Stage 3 (Live RFC 6238 TOTP) -> Stage 4 (Cryptographic Scrub)`.
  - Win32 clipboard privacy sentinel formats (`ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory = 0`, `CanUploadToCloudClipboard = 0`).
- **RFC 6238 TOTP & Developer Importers (`src/totp.rs`, `src/importer.rs`):**
  - Pure-Rust `HMAC-SHA1` RFC 6238 6-digit TOTP generator and `otpauth://` URI parser with 30-second countdown calculation.
  - Import and export pipelines for `.env` files, JSON vaults, and `~/.ssh/config` host blocks.
- **Ratatui v0.30+ Catalogue Viewer (`src/tui/`):**
  - Multi-pane Elm Architecture (TEA) terminal dashboard featuring Category Filter Sidebar, `SkimMatcherV2` Fuzzy Catalogue Table, Masked/Revealed Tier-2 Inspector, Live TOTP Progress Gauge, Active Clipboard Queue Footer, and Add/Delete modals.
- **Verification & Documentation Suite:**
  - 6 comprehensive integration and `TestBackend` snapshot tests in `tests/integration_tests.rs`.
  - Full documentation suite (`README.md`, `ARCHITECTURE.md`, `INSTALL.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `llms.txt`, and `LICENSE`).
