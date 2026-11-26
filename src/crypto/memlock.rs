use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{KEY_LEN, VaultKeys};
use crate::error::{MeadeError, Result};

const KEYRING_SERVICE: &str = "meade-cryptographic-vault";
const KEYRING_ACCOUNT: &str = "session-subkey-bundle-v1";

/// A 256-bit cryptographic key buffer backed by an isolated page-aligned allocation on Windows
/// (`VirtualAlloc` + `VirtualLock` per key so `VirtualUnlock` never unpins sibling keys on a shared
/// heap slab) (`MEADE-HORDE-04`), wiped unconditionally on Drop.
pub struct PinnedKey {
    #[cfg(windows)]
    page_ptr: *mut u8,
    #[cfg(not(windows))]
    inner: Box<[u8; KEY_LEN]>,
    locked_in_ram: bool,
}

#[cfg(windows)]
// SAFETY: `PinnedKey` owns an isolated `VirtualAlloc` page exclusively and only exposes immutable
// `&[u8; KEY_LEN]` borrows until `Drop` zeroes and frees it.
unsafe impl Send for PinnedKey {}

#[cfg(windows)]
// SAFETY: Shared references only read the immutable key slice; mutation occurs solely in `&mut self` `Drop`.
unsafe impl Sync for PinnedKey {}

#[cfg(windows)]
const PINNED_PAGE_BYTES: usize = 4096;

impl PinnedKey {
    pub fn new(mut raw: [u8; KEY_LEN]) -> Self {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Memory::{
                MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualLock,
            };

            // SAFETY: Allocates one dedicated 4 KiB private read/write page so `VirtualLock` and
            // `VirtualUnlock` never share page refcounts with any other `PinnedKey` or heap object.
            let page_ptr = unsafe {
                VirtualAlloc(
                    std::ptr::null(),
                    PINNED_PAGE_BYTES,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                ) as *mut u8
            };
            assert!(
                !page_ptr.is_null(),
                "VirtualAlloc failed for PinnedKey page"
            );

            // SAFETY: `page_ptr` is valid for `PINNED_PAGE_BYTES` bytes and `raw` is `KEY_LEN` bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(raw.as_ptr(), page_ptr, KEY_LEN);
            }
            raw.zeroize();

            // SAFETY: Locks the entire dedicated 4 KiB page in physical RAM if working-set quota allows.
            let locked_in_ram = unsafe { VirtualLock(page_ptr as *const _, PINNED_PAGE_BYTES) != 0 };
            Self {
                page_ptr,
                locked_in_ram,
            }
        }

        #[cfg(not(windows))]
        {
            let mut inner = Box::new(raw);
            raw.zeroize();
            let _ = inner.as_mut_ptr();
            Self {
                inner,
                locked_in_ram: false,
            }
        }
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        #[cfg(windows)]
        {
            // SAFETY: `page_ptr` stays valid and initialized for `KEY_LEN` bytes until `Drop`.
            unsafe { &*(self.page_ptr as *const [u8; KEY_LEN]) }
        }
        #[cfg(not(windows))]
        {
            &self.inner
        }
    }

    pub fn is_pinned(&self) -> bool {
        self.locked_in_ram
    }
}

impl Drop for PinnedKey {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Memory::{MEM_RELEASE, VirtualFree, VirtualUnlock};

            // SAFETY: Volatile-zero the key slice before unlocking/releasing its dedicated page.
            unsafe {
                for offset in 0..KEY_LEN {
                    std::ptr::write_volatile(self.page_ptr.add(offset), 0);
                }
                std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
                if self.locked_in_ram {
                    let _ = VirtualUnlock(self.page_ptr as *const _, PINNED_PAGE_BYTES);
                }
                let _ = VirtualFree(self.page_ptr as *mut _, 0, MEM_RELEASE);
            }
        }
        #[cfg(not(windows))]
        {
            self.inner.zeroize();
        }
    }
}

/// Stores the active session subkeys inside Windows Credential Manager (DPAPI) when `--keyring` is enabled.
pub fn store_keys_in_os_keyring(keys: &VaultKeys) -> Result<()> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .map_err(|e| MeadeError::Keyring(e.to_string()))?;
    let blob = keys.export_session_blob();
    let encoded = Zeroizing::new(B64.encode(blob.as_slice()));
    entry
        .set_password(&encoded)
        .map_err(|e| MeadeError::Keyring(e.to_string()))?;
    Ok(())
}

/// Loads cached session subkeys from Windows Credential Manager (DPAPI).
pub fn load_keys_from_os_keyring() -> Result<VaultKeys> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .map_err(|e| MeadeError::Keyring(e.to_string()))?;
    let encoded = Zeroizing::new(
        entry
            .get_password()
            .map_err(|e| MeadeError::Keyring(e.to_string()))?,
    );
    let decoded = Zeroizing::new(
        B64.decode(encoded.as_bytes())
            .map_err(|e| MeadeError::Keyring(format!("Corrupt keyring base64: {e}")))?,
    );
    VaultKeys::from_session_blob(&decoded)
}

/// Purges any cached session subkeys from Windows Credential Manager on `meade lock`.
pub fn clear_os_keyring() -> Result<()> {
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT) {
        let _ = entry.delete_credential();
    }
    Ok(())
}
