use zeroize::Zeroizing;

use crate::error::{MeadeError, Result};

/// Writes a secret string to the system clipboard and applies Windows privacy exclusion formats
/// (`ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory = 0`,
/// `CanUploadToCloudClipboard = 0`) atomically inside a single `OpenClipboard` transaction on Windows
/// so Windows Clipboard History (`Win+V`) and Cloud Sync never observe a secret via `WM_CLIPBOARDUPDATE`.
pub fn write_secret_to_clipboard(secret: &str) -> Result<()> {
    #[cfg(windows)]
    {
        write_secret_to_win32_clipboard_atomic(secret)
    }

    #[cfg(not(windows))]
    {
        let mut clipboard = arboard::Clipboard::new()
            .map_err(|e| MeadeError::Clipboard(format!("Failed to access OS clipboard: {e}")))?;
        clipboard
            .set_text(secret.to_string())
            .map_err(|e| MeadeError::Clipboard(format!("Failed to write secret to clipboard: {e}")))?;
        Ok(())
    }
}

/// Overwrites the OS clipboard with dummy entropy and clears it completely.
pub fn scrub_clipboard() -> Result<()> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|e| MeadeError::Clipboard(format!("Failed to access OS clipboard: {e}")))?;
    let dummy = Zeroizing::new("00000000000000000000000000000000".to_string());
    let _ = clipboard.set_text(dummy.as_str());
    clipboard
        .clear()
        .map_err(|e| MeadeError::Clipboard(format!("Failed to clear OS clipboard: {e}")))?;
    Ok(())
}

#[cfg(windows)]
fn write_secret_to_win32_clipboard_atomic(secret: &str) -> Result<()> {
    use std::time::Duration;
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{
        GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock,
    };
    use zeroize::Zeroize;

    const CF_UNICODETEXT_FMT: u32 = 13;

    struct ClipboardGuard;
    impl Drop for ClipboardGuard {
        fn drop(&mut self) {
            // SAFETY: Constructed only after a successful `OpenClipboard` call on this thread.
            unsafe {
                let _ = CloseClipboard();
            }
        }
    }

    fn wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    let mut utf16_secret = wide_null(secret);

    // SAFETY: Standard Win32 Clipboard API sequence inside a single `OpenClipboard`/`CloseClipboard`
    // transaction (`MEADE-HORDE-01`). `CloseClipboard` fires `WM_CLIPBOARDUPDATE` once after both
    // `CF_UNICODETEXT` and all three privacy exclusion formats are set; if any privacy format fails,
    // `EmptyClipboard` clears the secret before `ClipboardGuard` drops.
    let res = (|| -> Result<()> {
        let mut opened = false;
        for _ in 0..10 {
            // SAFETY: Null hwnd associates clipboard ownership with the current thread.
            if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
                opened = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if !opened {
            return Err(MeadeError::Clipboard(
                "Failed to open Win32 clipboard under lock contention".to_string(),
            ));
        }
        let _guard = ClipboardGuard;

        // SAFETY: Clipboard is currently open on this thread.
        if unsafe { EmptyClipboard() } == 0 {
            return Err(MeadeError::Clipboard(
                "Win32 EmptyClipboard failed before atomic secret write".to_string(),
            ));
        }

        let byte_len = utf16_secret.len() * std::mem::size_of::<u16>();
        // SAFETY: Allocates moveable global memory sized for UTF-16LE NUL-terminated buffer.
        let htext = unsafe { GlobalAlloc(GMEM_MOVEABLE, byte_len) };
        if htext.is_null() {
            return Err(MeadeError::Clipboard(
                "Win32 GlobalAlloc failed for secret buffer".to_string(),
            ));
        }
        // SAFETY: `htext` is a valid non-null `HGLOBAL` from `GlobalAlloc`.
        let ptr = unsafe { GlobalLock(htext) } as *mut u16;
        if ptr.is_null() {
            // SAFETY: Ownership was not transferred to `SetClipboardData`, so we must free `htext`.
            unsafe {
                let _ = GlobalFree(htext);
            }
            return Err(MeadeError::Clipboard(
                "Win32 GlobalLock failed for secret buffer".to_string(),
            ));
        }
        // SAFETY: `ptr` points to `utf16_secret.len()` writable `u16` elements.
        unsafe {
            std::ptr::copy_nonoverlapping(utf16_secret.as_ptr(), ptr, utf16_secret.len());
            let _ = GlobalUnlock(htext);
        }
        // SAFETY: `CF_UNICODETEXT_FMT` transfers ownership of `htext` on non-null return.
        let text_ok = unsafe { SetClipboardData(CF_UNICODETEXT_FMT, htext) };
        if text_ok.is_null() {
            // SAFETY: `SetClipboardData` failed, so caller retains ownership and must free `htext`.
            unsafe {
                let _ = GlobalFree(htext);
            }
            return Err(MeadeError::Clipboard(
                "Win32 SetClipboardData(CF_UNICODETEXT) failed".to_string(),
            ));
        }

        let formats = [
            ("ExcludeClipboardContentFromMonitorProcessing", 1u32),
            ("CanIncludeInClipboardHistory", 0u32),
            ("CanUploadToCloudClipboard", 0u32),
        ];

        for (name, dword_val) in formats {
            let wide = wide_null(name);
            // SAFETY: `wide` is NUL-terminated UTF-16.
            let fmt_id = unsafe { RegisterClipboardFormatW(wide.as_ptr()) };
            if fmt_id == 0 {
                // SAFETY: Fail closed — clear secret so `CloseClipboard` never broadcasts unprotected data.
                unsafe {
                    let _ = EmptyClipboard();
                }
                return Err(MeadeError::Clipboard(format!(
                    "RegisterClipboardFormatW failed for `{name}`"
                )));
            }
            // SAFETY: Allocates 4-byte DWORD flag buffer for clipboard exclusion marker.
            let hmem = unsafe { GlobalAlloc(GMEM_MOVEABLE, std::mem::size_of::<u32>()) };
            if hmem.is_null() {
                // SAFETY: Fail closed on allocation failure.
                unsafe {
                    let _ = EmptyClipboard();
                }
                return Err(MeadeError::Clipboard(format!(
                    "GlobalAlloc failed for clipboard privacy format `{name}`"
                )));
            }
            // SAFETY: `hmem` is valid non-null `HGLOBAL`.
            let ptr = unsafe { GlobalLock(hmem) } as *mut u32;
            if ptr.is_null() {
                // SAFETY: Free un-transferred `hmem` and clear clipboard before closing.
                unsafe {
                    let _ = GlobalFree(hmem);
                    let _ = EmptyClipboard();
                }
                return Err(MeadeError::Clipboard(format!(
                    "GlobalLock failed for clipboard privacy format `{name}`"
                )));
            }
            // SAFETY: `ptr` points to one writable `u32`.
            unsafe {
                *ptr = dword_val;
                let _ = GlobalUnlock(hmem);
            }
            // SAFETY: Transfers ownership of `hmem` on success; free and empty clipboard on failure.
            let transferred = unsafe { SetClipboardData(fmt_id, hmem) };
            if transferred.is_null() {
                // SAFETY: `SetClipboardData` failed; free `hmem` and fail closed.
                unsafe {
                    let _ = GlobalFree(hmem);
                    let _ = EmptyClipboard();
                }
                return Err(MeadeError::Clipboard(format!(
                    "SetClipboardData failed for clipboard privacy format `{name}`"
                )));
            }
        }

        Ok(())
    })();

    utf16_secret.zeroize();
    res
}
