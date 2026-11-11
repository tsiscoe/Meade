use zeroize::Zeroizing;

use crate::error::{MeadeError, Result};

/// Writes a secret string to the system clipboard and applies Windows privacy exclusion formats
/// (`ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory = 0`,
/// `CanUploadToCloudClipboard = 0`) so Windows Clipboard History (`Win+V`) and Cloud Sync never capture it.
pub fn write_secret_to_clipboard(secret: &str) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|e| MeadeError::Clipboard(format!("Failed to access OS clipboard: {e}")))?;
    clipboard
        .set_text(secret.to_string())
        .map_err(|e| MeadeError::Clipboard(format!("Failed to write secret to clipboard: {e}")))?;

    #[cfg(windows)]
    apply_win32_clipboard_privacy_flags();

    Ok(())
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
fn apply_win32_clipboard_privacy_flags() {
    use std::time::Duration;
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{
        GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock,
    };

    fn wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    // SAFETY: Standard Win32 Clipboard API sequence on the current thread.
    // 1. We retry `OpenClipboard(null)` up to 5 times (5ms backoff) in case another window briefly holds the lock.
    // 2. Per Microsoft Win32 `SetClipboardData` specification, the system takes ownership of `hmem` ONLY if
    //    `SetClipboardData` returns non-null. If `GlobalLock` or `SetClipboardData` fails, we must call `GlobalFree(hmem)`.
    unsafe {
        let mut opened = false;
        for _ in 0..5 {
            if OpenClipboard(std::ptr::null_mut()) != 0 {
                opened = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if !opened {
            return;
        }

        let formats = [
            ("ExcludeClipboardContentFromMonitorProcessing", 1u32),
            ("CanIncludeInClipboardHistory", 0u32),
            ("CanUploadToCloudClipboard", 0u32),
        ];

        for (name, dword_val) in formats {
            let wide = wide_null(name);
            let fmt_id = RegisterClipboardFormatW(wide.as_ptr());
            if fmt_id != 0 {
                let hmem = GlobalAlloc(GMEM_MOVEABLE, std::mem::size_of::<u32>());
                if !hmem.is_null() {
                    let ptr = GlobalLock(hmem) as *mut u32;
                    if !ptr.is_null() {
                        *ptr = dword_val;
                        let _ = GlobalUnlock(hmem);
                        let transferred = SetClipboardData(fmt_id, hmem);
                        if transferred.is_null() {
                            let _ = GlobalFree(hmem);
                        }
                    } else {
                        let _ = GlobalFree(hmem);
                    }
                }
            }
        }

        let _ = CloseClipboard();
    }
}
