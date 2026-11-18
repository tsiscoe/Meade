use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{KEY_LEN, VaultKeys};
use crate::error::{MeadeError, Result};

const KEYRING_SERVICE: &str = "meade-cryptographic-vault";
const KEYRING_ACCOUNT: &str = "session-subkey-bundle-v1";

/// A 256-bit cryptographic key buffer allocated on the heap, pinned against OS pagefile swapping
/// via Windows `VirtualLock`, and unconditionally overwritten with zeros on Drop.
pub struct PinnedKey {
    inner: Box<[u8; KEY_LEN]>,
    locked_in_ram: bool,
}

impl PinnedKey {
    pub fn new(raw: [u8; KEY_LEN]) -> Self {
        let mut inner = Box::new(raw);
        let locked_in_ram = lock_memory_region(inner.as_mut_ptr(), KEY_LEN);
        Self {
            inner,
            locked_in_ram,
        }
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.inner
    }

    pub fn is_pinned(&self) -> bool {
        self.locked_in_ram
    }
}

impl Drop for PinnedKey {
    fn drop(&mut self) {
        self.inner.zeroize();
        if self.locked_in_ram {
            unlock_memory_region(self.inner.as_mut_ptr(), KEY_LEN);
        }
    }
}

#[cfg(windows)]
fn lock_memory_region(ptr: *mut u8, len: usize) -> bool {
    // SAFETY: `ptr` points to a valid heap-allocated `[u8; 32]` owned by `Box` that does not move
    // until `Drop`. `VirtualLock` locks the virtual page in physical RAM when quota permits.
    unsafe { windows_sys::Win32::System::Memory::VirtualLock(ptr as *const _, len) != 0 }
}

#[cfg(not(windows))]
fn lock_memory_region(_ptr: *mut u8, _len: usize) -> bool {
    false
}

#[cfg(windows)]
fn unlock_memory_region(ptr: *mut u8, len: usize) {
    // SAFETY: Matches the prior successful `VirtualLock` call on the same heap allocation.
    unsafe {
        let _ = windows_sys::Win32::System::Memory::VirtualUnlock(ptr as *const _, len);
    }
}

#[cfg(not(windows))]
fn unlock_memory_region(_ptr: *mut u8, _len: usize) {}

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
