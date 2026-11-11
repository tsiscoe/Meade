# Installing & Configuring Meade

This guide covers building **Meade** from source, installing the binary onto your system `PATH`, configuring the background `Ctrl+Shift+V` Clipboard Interceptor Daemon on Windows, and troubleshooting common issues.

---

## 1. System Prerequisites

- **Rust Toolchain:** Rust `1.85+` (2024 Edition) and `cargo`.
  - Verify with:
    ```powershell
    rustc --version
    cargo --version
    ```
  - If not installed, download via [rustup.rs](https://rustup.rs/).
- **C Compiler / Linker (for `rusqlite` bundled SQLite 3):**
  - **Windows:** Visual Studio Build Tools (Desktop development with C++ / MSVC linker).
  - **macOS:** Xcode Command Line Tools (`xcode-select --install`).
  - **Linux:** `build-essential` or `gcc` (`sudo apt install build-essential libxcb1-dev`).
- **Zero OpenSSL Requirement:** Because Meade uses 100% pure-Rust cryptography (`argon2`, `chacha20poly1305`, `hkdf`, `sha2`), you do **not** need OpenSSL, Perl, NASM, or `vcpkg`.

---

## 2. Building & Installing from Source

### Option A: Global Cargo Install (Recommended)
Install the optimized release binary directly into `~/.cargo/bin/meade` (or `%USERPROFILE%\.cargo\bin\meade.exe` on Windows):

```powershell
git clone https://github.com/tsiscoe/Meade.git
cd Meade
cargo install --path .
```

Verify installation:
```powershell
meade --version
meade --help
```

### Option B: Standalone Release Binary Build
If you want to place a portable `meade.exe` into a custom directory:

```powershell
git clone https://github.com/tsiscoe/Meade.git
cd Meade
cargo build --release
```
The compiled binary will be located at `target\release\meade.exe` (Windows) or `target/release/meade` (macOS/Linux).

---

## 3. Vault Initialization & Storage Location

By default, Meade stores its encrypted SQLite WAL database at:
- **Windows:** `C:\Users\<YourUsername>\.meade\vault.db`
- **macOS / Linux:** `~/.meade/vault.db`

### Initialize Your Vault
```powershell
# Interactive initialization (prompts for Master Passphrase via hidden TTY input)
meade init

# Or initialize with 3 sample credentials (AWS Root + TOTP, Cloud API Key, Bastion SSH Key)
meade init --seed-demo
```

### Using a Custom Vault Path
Pass `--vault <PATH>` to any subcommand to use an isolated project or team vault:
```powershell
meade --vault C:\Secure\project_vault.db init
meade --vault C:\Secure\project_vault.db tui
```

---

## 4. Running the Background Clipboard & `Ctrl+Shift+V` Daemon

To enable global `Ctrl+Shift+V` sequential pasting across external browsers, terminals, and IDEs—and to keep your unlocked subkeys pinned in `VirtualLock` RAM so you don't have to re-type your Argon2id passphrase on every CLI command:

### Start the Daemon in a Background Terminal or Startup Task
```powershell
# Start daemon with a 20-second clipboard auto-scrub TTL
meade daemon serve --ttl 20
```

### Start Hidden in PowerShell (Background Process)
```powershell
Start-Process -FilePath "meade" -ArgumentList "daemon", "serve", "--ttl", "20" -WindowStyle Hidden
```

### Unlock Once per Session
```powershell
# Unlocks the vault and caches the split subkeys inside the running Daemon's VirtualLock RAM
meade unlock

# Or also cache wrapped session keys in Windows Credential Manager (DPAPI)
meade --keyring unlock
```

---

## 5. Environment Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `MEADE_PASSPHRASE` | *(None — prompts via TTY)* | Supplies the master passphrase non-interactively for automated CI/CD or headless scripts. Avoid exporting in interactive shell history. |

---

## 6. Troubleshooting

### `Ctrl+Shift+V` Does Not Advance the Queue in External Apps
- **Cause:** Another running application (such as a third-party clipboard utility or terminal multiplexer) has already claimed the global `Ctrl+Shift+V` hotkey via Win32 `RegisterHotKey`.
- **Resolution:**
  1. Ensure `meade daemon serve` is running (`meade daemon status`).
  2. Inside the Ratatui TUI (`meade tui`), you can also press `n` or `Ctrl+N` to advance the queue.
  3. From any terminal or script/macro, run `meade daemon next` (or `meade queue next`) to advance the stage.

### Terminal Looks Garbled After Forced Kill
- Meade installs `color-eyre` panic hooks before `ratatui::init()` so normal panics automatically restore the alternate screen. If the process was forcefully terminated via `kill -9` / `Stop-Process -Force`, run `reset` (Linux/macOS) or open a fresh PowerShell tab.
