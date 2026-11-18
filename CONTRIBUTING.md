# Contributing to Meade

Thank you for helping audit, harden, and extend **Meade**. Because Meade is cryptographic security infrastructure, every pull request must preserve memory hygiene, zero-`unwrap()` panic safety, and strict AEAD Associated Data invariants.

---

## 1. Security & Code Quality Guardrails

1. **Zero Production `unwrap()` / `expect()`:**
   - Panicking while the Ratatui alternate screen is active corrupts the user's terminal state and bypasses cleanup.
   - Propagate all fallible operations via `crate::error::Result<T>` (`MeadeError`) or `color_eyre::Result<T>`.
2. **Zero C/OpenSSL Crypto Dependencies:**
   - All cryptographic primitives must remain pure, auditable Rust (`RustCrypto`). Do not introduce `openssl-sys` or `bundled-sqlcipher`.
3. **Memory Hygiene (`Zeroize` + `VirtualLock`):**
   - Any struct or buffer holding plaintext secrets, TOTP seeds, or derived key material must derive `Zeroize` / `ZeroizeOnDrop` or wrap allocations in `Zeroizing<T>`.
4. **Windows KeyEvent Filtering:**
   - Crossterm on Windows emits both `KeyEventKind::Press` and `KeyEventKind::Release`. Always filter for `key.kind == KeyEventKind::Press` in event loops.

---

## 2. Development & Verification Workflow

Before opening a Pull Request, run the full verification suite locally:

```powershell
# 1. Check formatting
cargo fmt --check

# 2. Run all unit, cryptographic AAD tamper, TOTP, importer, and headless TestBackend TUI tests
cargo test

# 3. Run Clippy with strict unwrap_used warnings enabled
cargo clippy --all-targets -- -W clippy::unwrap_used
```

---

## 3. Adding New Tests (`tests/integration_tests.rs`)

- **Cryptographic Changes:** Must include negative tamper tests proving that modified nonces, swapped `entry_id` UUIDs, or cross-tier (`Tier1Header` vs. `Tier2Payload`) ciphertexts fail authentication (`Err(MeadeError::AuthenticationFailed)`).
- **TUI Changes:** Must be tested headlessly using `ratatui::backend::TestBackend` and `TuiApp::new(db, keys, true)` (`headless_clipboard = true`) so tests execute deterministically in CI without requiring a physical display or mutating the host clipboard.

---

## 4. License Agreement

By contributing to **Meade**, you agree that your contributions will be licensed under the [MIT License](LICENSE).
