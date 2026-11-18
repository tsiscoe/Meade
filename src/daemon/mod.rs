pub mod clipboard;
pub mod queue;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use data_encoding::HEXLOWER;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use zeroize::Zeroizing;

use crate::crypto::VaultKeys;
use crate::daemon::clipboard::{scrub_clipboard, write_secret_to_clipboard};
use crate::daemon::queue::{QueueStageKind, QueueStatusSnapshot, SequentialPasteQueue};
use crate::db::enforce_owner_only_acl;
use crate::db::models::{Tier1Header, Tier2Secret};
use crate::error::{MeadeError, Result};

/// Default localhost port for the Meade Clipboard & Key-Custody Daemon.
pub const DEFAULT_DAEMON_ADDR: &str = "127.0.0.1:49731";
/// Default clipboard auto-scrub TTL in seconds.
pub const DEFAULT_CLIPBOARD_TTL_SECS: u64 = 20;
/// Default daemon session-key inactivity auto-lock timeout in seconds (15 minutes).
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 15 * 60;
/// Maximum allowed IPC request frame size in bytes (64 KiB) to prevent memory exhaustion (CWE-770).
pub const MAX_IPC_FRAME_BYTES: u64 = 65_536;
/// Maximum per-connection socket read/write timeout to neutralize Slowloris stalling (CWE-400).
pub const IPC_SOCKET_TIMEOUT: Duration = Duration::from_secs(2);
/// Maximum concurrent IPC client connections permitted before immediate drop (RT-02b / CWE-400).
pub const MAX_CONCURRENT_IPC_CLIENTS: usize = 16;
/// Delay applied to failed IPC bearer token authentication attempts to throttle probing (RT-02b).
pub const AUTH_FAILURE_BACKOFF: Duration = Duration::from_millis(100);

/// Authenticated IPC wire frame requiring a 256-bit (64-hex-char) per-user CSPRNG bearer token (CWE-306).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedDaemonRequest {
    pub auth_token: String,
    pub request: DaemonRequest,
}

/// IPC Request messages sent between the CLI/Ratatui TUI and the background Meade Daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonRequest {
    Ping,
    StoreSessionKeys {
        b64_blob: String,
    },
    FetchSessionKeys,
    LockSession,
    EnqueueFullCredential {
        header: Tier1Header,
        secret: Tier2Secret,
    },
    EnqueueSingle {
        title: String,
        kind: QueueStageKind,
        value: String,
        is_live_totp_seed: bool,
    },
    AdvanceQueue,
    ScrubNow,
    GetStatus,
    Shutdown,
}

/// IPC Response messages returned by the Meade Daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonResponse {
    Pong {
        unlocked: bool,
        queue: QueueStatusSnapshot,
    },
    SessionKeys {
        b64_blob: Option<String>,
    },
    QueueUpdated {
        queue: QueueStatusSnapshot,
        message: String,
    },
    Error {
        message: String,
    },
    ShuttingDown,
}

struct DaemonState {
    auth_token: Zeroizing<String>,
    session_keys: Option<VaultKeys>,
    queue: SequentialPasteQueue,
    last_activity: Instant,
    idle_timeout: Duration,
}

/// Returns the path to the owner-only IPC authentication token file (`~/.meade/daemon.token`).
pub fn daemon_token_path() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".meade").join("daemon.token")
    } else {
        PathBuf::from(".meade_daemon.token")
    }
}

/// Generates a fresh 256-bit CSPRNG token and writes it to `path` with strict owner-only permissions.
pub fn generate_and_persist_ipc_token_at(path: &Path) -> Result<Zeroizing<String>> {
    let mut raw = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(raw.as_mut());
    let hex_token = Zeroizing::new(HEXLOWER.encode(raw.as_slice()));

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
        enforce_owner_only_acl(parent, true);
    }

    std::fs::write(path, hex_token.as_bytes())?;
    enforce_owner_only_acl(path, false);

    Ok(hex_token)
}

/// Generates a fresh 256-bit CSPRNG token and writes it to `~/.meade/daemon.token` with strict owner-only permissions.
pub fn generate_and_persist_ipc_token() -> Result<Zeroizing<String>> {
    generate_and_persist_ipc_token_at(&daemon_token_path())
}

/// Overwrites the IPC token file at `path` with zeros before unlinking it from the filesystem (RT-01b / RT-07).
pub fn secure_remove_ipc_token_at(path: &Path) {
    if path.exists() {
        let _ = std::fs::write(path, [b'0'; 64]);
        let _ = std::fs::remove_file(path);
    }
}

/// Overwrites `~/.meade/daemon.token` with zeros and removes it on daemon shutdown.
pub fn secure_remove_ipc_token() {
    secure_remove_ipc_token_at(&daemon_token_path());
}

/// Loads the active IPC bearer token from `~/.meade/daemon.token`.
pub fn load_ipc_token() -> Result<Zeroizing<String>> {
    let path = daemon_token_path();
    let content = std::fs::read_to_string(&path).map_err(|e| {
        MeadeError::Clipboard(format!(
            "Could not read daemon IPC token at `{}`: {e}",
            path.display()
        ))
    })?;
    Ok(Zeroizing::new(content.trim().to_string()))
}

/// Constant-time verification of a client-supplied IPC bearer token against the daemon's token.
pub fn verify_ipc_token_ct(expected: &str, candidate: &str) -> bool {
    if expected.len() != candidate.len() || expected.is_empty() {
        return false;
    }
    expected.as_bytes().ct_eq(candidate.as_bytes()).into()
}

/// Runs the Meade Clipboard Interceptor & Key-Custody Daemon with the default 15-minute inactivity auto-lock.
pub async fn run_daemon_server(addr: &str, ttl_secs: u64) -> Result<()> {
    run_daemon_server_with_idle_timeout(
        addr,
        ttl_secs,
        Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
    )
    .await
}

/// Runs the Meade Clipboard Interceptor & Key-Custody Daemon in the current process until Shutdown.
/// Enforces a 16-permit concurrent IPC semaphore (`RT-02b`), a configurable session-key inactivity
/// auto-lock watchdog (`RT-03b`), global `Ctrl+Shift+V` (with `Ctrl+Alt+V` fallback) hotkey polling (`RT-05b`),
/// and 500ms TTL clipboard auto-scrubbing.
pub async fn run_daemon_server_with_idle_timeout(
    addr: &str,
    ttl_secs: u64,
    idle_timeout: Duration,
) -> Result<()> {
    let auth_token = generate_and_persist_ipc_token()?;
    let listener = TcpListener::bind(addr).await?;
    run_daemon_loop(listener, auth_token, ttl_secs, idle_timeout, true, true).await
}

/// Spawns an isolated, ephemeral-port Meade Daemon instance for adversarial integration testing (`RT-06b`).
/// Does not overwrite `~/.meade/daemon.token` or call `std::process::exit(0)` on `Shutdown`.
pub async fn spawn_ephemeral_test_daemon(
    ttl_secs: u64,
    idle_timeout: Duration,
) -> Result<(
    SocketAddr,
    Zeroizing<String>,
    tokio::task::JoinHandle<Result<()>>,
)> {
    let mut raw = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(raw.as_mut());
    let auth_token = Zeroizing::new(HEXLOWER.encode(raw.as_slice()));
    let thread_token = auth_token.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let bound_addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        run_daemon_loop(listener, thread_token, ttl_secs, idle_timeout, false, false).await
    });

    Ok((bound_addr, auth_token, handle))
}

async fn run_daemon_loop(
    listener: TcpListener,
    auth_token: Zeroizing<String>,
    ttl_secs: u64,
    idle_timeout: Duration,
    enable_global_hotkey: bool,
    exit_process_on_shutdown: bool,
) -> Result<()> {
    let state = Arc::new(Mutex::new(DaemonState {
        auth_token,
        session_keys: None,
        queue: SequentialPasteQueue::new(ttl_secs),
        last_activity: Instant::now(),
        idle_timeout,
    }));

    if enable_global_hotkey {
        let hotkey_state = Arc::clone(&state);
        std::thread::spawn(move || {
            run_ctrl_shift_v_hotkey_thread(hotkey_state);
        });
    }

    // Spawn the 200ms TTL auto-scrubber & Inactivity Auto-Lock Watchdog task (RT-03b)
    let watchdog_state = Arc::clone(&state);
    let watchdog_handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(200));
        loop {
            ticker.tick().await;
            let mut guard = watchdog_state.lock().await;
            if guard.queue.check_expired() {
                let _ = scrub_clipboard();
            }
            if !guard.idle_timeout.is_zero()
                && guard.session_keys.is_some()
                && guard.last_activity.elapsed() >= guard.idle_timeout
            {
                guard.session_keys = None;
                guard.queue.clear();
                let _ = scrub_clipboard();
            }
        }
    });

    let conn_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_IPC_CLIENTS));
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                watchdog_handle.abort();
                if exit_process_on_shutdown {
                    let _ = scrub_clipboard();
                    secure_remove_ipc_token();
                    std::process::exit(0);
                }
                return Ok(());
            }
            accept_res = listener.accept() => {
                let (stream, _) = accept_res?;
                // RT-02b: Enforce bounded concurrency via non-blocking Semaphore permit acquisition
                let Ok(permit) = Arc::clone(&conn_semaphore).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let conn_state = Arc::clone(&state);
                let tx = shutdown_tx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Ok(should_quit) = handle_client_stream(stream, conn_state).await
                        && should_quit
                    {
                        let _ = tx.send(());
                    }
                });
            }
        }
    }
}

/// Processes a single incoming TCP stream with a 2-second timeout, 64 KiB frame cap,
/// failed-auth backoff delay (`RT-02b`), and constant-time IPC bearer token verification.
async fn handle_client_stream(stream: TcpStream, state: Arc<Mutex<DaemonState>>) -> Result<bool> {
    let (reader, mut writer) = stream.into_split();
    let limited_reader = reader.take(MAX_IPC_FRAME_BYTES);
    let mut buf_reader = BufReader::new(limited_reader);
    let mut line = Zeroizing::new(String::new());

    let read_res = tokio::time::timeout(IPC_SOCKET_TIMEOUT, buf_reader.read_line(&mut line)).await;
    let n = match read_res {
        Ok(Ok(bytes_read)) => bytes_read,
        Ok(Err(e)) => return Err(MeadeError::Io(e)),
        Err(_) => {
            let resp = DaemonResponse::Error {
                message: "IPC socket read timed out".to_string(),
            };
            let out = serde_json::to_string(&resp)? + "\n";
            let _ =
                tokio::time::timeout(IPC_SOCKET_TIMEOUT, writer.write_all(out.as_bytes())).await;
            return Ok(false);
        }
    };

    if n == 0 {
        return Ok(false);
    }

    if n as u64 >= MAX_IPC_FRAME_BYTES && !line.ends_with('\n') {
        let resp = DaemonResponse::Error {
            message: "IPC frame exceeded 64 KiB maximum size limit".to_string(),
        };
        let out = serde_json::to_string(&resp)? + "\n";
        let _ = tokio::time::timeout(IPC_SOCKET_TIMEOUT, writer.write_all(out.as_bytes())).await;
        return Ok(false);
    }

    let auth_envelope: AuthenticatedDaemonRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let resp = DaemonResponse::Error {
                message: format!("Invalid or unauthenticated IPC JSON request: {e}"),
            };
            let out = serde_json::to_string(&resp)? + "\n";
            let _ =
                tokio::time::timeout(IPC_SOCKET_TIMEOUT, writer.write_all(out.as_bytes())).await;
            return Ok(false);
        }
    };

    let mut should_quit = false;
    let mut auth_failed = false;
    let resp = {
        let mut guard = state.lock().await;
        if !verify_ipc_token_ct(&guard.auth_token, &auth_envelope.auth_token) {
            auth_failed = true;
            DaemonResponse::Error {
                message: "Unauthorized: Invalid IPC bearer token".to_string(),
            }
        } else {
            match auth_envelope.request {
                DaemonRequest::Ping | DaemonRequest::GetStatus => DaemonResponse::Pong {
                    unlocked: guard.session_keys.is_some(),
                    queue: guard.queue.status(),
                },
                DaemonRequest::StoreSessionKeys { b64_blob } => {
                    let b64_zero = Zeroizing::new(b64_blob);
                    let decoded =
                        Zeroizing::new(B64.decode(b64_zero.as_bytes()).map_err(|e| {
                            MeadeError::Crypto(format!("Invalid session base64: {e}"))
                        })?);
                    let keys = VaultKeys::from_session_blob(&decoded)?;
                    guard.session_keys = Some(keys);
                    guard.last_activity = Instant::now();
                    DaemonResponse::Pong {
                        unlocked: true,
                        queue: guard.queue.status(),
                    }
                }
                DaemonRequest::FetchSessionKeys => {
                    guard.last_activity = Instant::now();
                    let b64_blob = guard.session_keys.as_ref().map(|k| {
                        let raw = k.export_session_blob();
                        B64.encode(raw.as_slice())
                    });
                    DaemonResponse::SessionKeys { b64_blob }
                }
                DaemonRequest::LockSession => {
                    guard.session_keys = None;
                    guard.queue.clear();
                    let _ = scrub_clipboard();
                    DaemonResponse::QueueUpdated {
                        queue: guard.queue.status(),
                        message: "Session keys wiped and clipboard scrubbed.".to_string(),
                    }
                }
                DaemonRequest::EnqueueFullCredential { header, secret } => {
                    guard.last_activity = Instant::now();
                    if let Some((kind, payload)) = guard.queue.load_credential(&header, &secret) {
                        let payload_zero = Zeroizing::new(payload);
                        let _ = write_secret_to_clipboard(&payload_zero);
                        DaemonResponse::QueueUpdated {
                            queue: guard.queue.status(),
                            message: format!(
                                "Loaded `{}` into clipboard. Press Ctrl+Shift+V for next stage.",
                                kind.label()
                            ),
                        }
                    } else {
                        DaemonResponse::Error {
                            message: "Credential had no copyable fields.".to_string(),
                        }
                    }
                }
                DaemonRequest::EnqueueSingle {
                    title,
                    kind,
                    value,
                    is_live_totp_seed,
                } => {
                    guard.last_activity = Instant::now();
                    if let Some((k, payload)) =
                        guard
                            .queue
                            .load_single_step(&title, kind, value, is_live_totp_seed)
                    {
                        let payload_zero = Zeroizing::new(payload);
                        let _ = write_secret_to_clipboard(&payload_zero);
                        DaemonResponse::QueueUpdated {
                            queue: guard.queue.status(),
                            message: format!("Copied `{}` with auto-scrub timer.", k.label()),
                        }
                    } else {
                        DaemonResponse::Error {
                            message: "Failed to load clipboard step.".to_string(),
                        }
                    }
                }
                DaemonRequest::AdvanceQueue => {
                    guard.last_activity = Instant::now();
                    if let Some((kind, payload)) = guard.queue.advance() {
                        let payload_zero = Zeroizing::new(payload);
                        let _ = write_secret_to_clipboard(&payload_zero);
                        DaemonResponse::QueueUpdated {
                            queue: guard.queue.status(),
                            message: format!("Advanced to `{}`.", kind.label()),
                        }
                    } else {
                        let _ = scrub_clipboard();
                        DaemonResponse::QueueUpdated {
                            queue: guard.queue.status(),
                            message: "Queue complete — OS clipboard scrubbed clean.".to_string(),
                        }
                    }
                }
                DaemonRequest::ScrubNow => {
                    guard.queue.clear();
                    let _ = scrub_clipboard();
                    DaemonResponse::QueueUpdated {
                        queue: guard.queue.status(),
                        message: "OS clipboard scrubbed immediately.".to_string(),
                    }
                }
                DaemonRequest::Shutdown => {
                    guard.session_keys = None;
                    guard.queue.clear();
                    let _ = scrub_clipboard();
                    should_quit = true;
                    DaemonResponse::ShuttingDown
                }
            }
        }
    };

    if auth_failed {
        tokio::time::sleep(AUTH_FAILURE_BACKOFF).await;
    }

    let out = Zeroizing::new(serde_json::to_string(&resp)? + "\n");
    tokio::time::timeout(IPC_SOCKET_TIMEOUT, writer.write_all(out.as_bytes()))
        .await
        .map_err(|_| MeadeError::Clipboard("IPC socket write timed out".into()))??;
    writer.flush().await?;
    Ok(should_quit)
}

/// Sends an authenticated IPC request to the running Meade Daemon using the local `~/.meade/daemon.token`.
pub async fn send_daemon_request(addr: &str, req: &DaemonRequest) -> Result<DaemonResponse> {
    let token = load_ipc_token()?;
    send_daemon_request_with_token(addr, &token, req).await
}

/// Sends an IPC request with an explicit bearer token (exposed for integration and negative security tests).
pub async fn send_daemon_request_with_token(
    addr: &str,
    token: &str,
    req: &DaemonRequest,
) -> Result<DaemonResponse> {
    let stream = tokio::time::timeout(Duration::from_millis(350), TcpStream::connect(addr))
        .await
        .map_err(|_| MeadeError::Clipboard("Daemon connection timed out".into()))?
        .map_err(|e| MeadeError::Clipboard(format!("Daemon not running on {addr}: {e}")))?;

    let (reader, mut writer) = stream.into_split();
    let auth_req = AuthenticatedDaemonRequest {
        auth_token: token.to_string(),
        request: req.clone(),
    };
    let payload = Zeroizing::new(serde_json::to_string(&auth_req)? + "\n");
    writer.write_all(payload.as_bytes()).await?;
    writer.flush().await?;

    let mut buf_reader = BufReader::new(reader.take(MAX_IPC_FRAME_BYTES));
    let mut line = Zeroizing::new(String::new());
    buf_reader.read_line(&mut line).await?;
    let resp: DaemonResponse = serde_json::from_str(line.trim())?;
    Ok(resp)
}

/// Registers a global `Ctrl+Shift+V` hotkey on Windows (falling back automatically to `Ctrl+Alt+V` on
/// hotkey collision per `RT-05b`) and pumps the Win32 message queue using `MaybeUninit` (`ANSSI Rule 3`).
fn run_ctrl_shift_v_hotkey_thread(state: Arc<Mutex<DaemonState>>) {
    let _ = &state;
    #[cfg(windows)]
    {
        use std::mem::MaybeUninit;
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
            MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT, RegisterHotKey, UnregisterHotKey,
        };
        use windows_sys::Win32::UI::WindowsAndMessaging::{GetMessageW, MSG, WM_HOTKEY};

        const HOTKEY_ID_ADVANCE: i32 = 0x4D45; // "ME"
        const VK_V: u32 = 0x56;

        // SAFETY: Registers thread-level global hotkey `Ctrl+Shift+V` (or fallback `Ctrl+Alt+V` if another
        // application holds `Ctrl+Shift+V`) and pumps the thread message queue using `MaybeUninit::<MSG>::zeroed()`.
        unsafe {
            let primary_ok = RegisterHotKey(
                std::ptr::null_mut(),
                HOTKEY_ID_ADVANCE,
                MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT,
                VK_V,
            );
            if primary_ok == 0 {
                let fallback_ok = RegisterHotKey(
                    std::ptr::null_mut(),
                    HOTKEY_ID_ADVANCE,
                    MOD_CONTROL | MOD_ALT | MOD_NOREPEAT,
                    VK_V,
                );
                if fallback_ok == 0 {
                    return;
                }
            }

            let mut msg: MSG = MaybeUninit::zeroed().assume_init();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                if msg.message == WM_HOTKEY && msg.wParam as i32 == HOTKEY_ID_ADVANCE {
                    let mut guard = state.blocking_lock();
                    guard.last_activity = Instant::now();
                    if guard.queue.is_active() {
                        if let Some((_kind, payload)) = guard.queue.advance() {
                            let payload_zero = Zeroizing::new(payload);
                            let _ = write_secret_to_clipboard(&payload_zero);
                        } else {
                            let _ = scrub_clipboard();
                        }
                    }
                }
            }

            let _ = UnregisterHotKey(std::ptr::null_mut(), HOTKEY_ID_ADVANCE);
        }
    }
}
