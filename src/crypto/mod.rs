pub mod envelope;
pub mod memlock;

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::memlock::PinnedKey;
use crate::error::{MeadeError, Result};

/// Salt length for Argon2id master key derivation (256-bit).
pub const SALT_LEN: usize = 32;
/// Key length for XChaCha20-Poly1305 (256-bit).
pub const KEY_LEN: usize = 32;
/// Current cryptographic envelope schema version.
pub const CRYPTO_SCHEMA_VERSION: u8 = 1;

/// Domain separation context for Tier-1 Catalogue Header Subkey.
const HKDF_INFO_TIER1_HEADER: &[u8] = b"meade-v1-tier1-header-subkey";
/// Domain separation context for Tier-2 Secret Payload Subkey.
const HKDF_INFO_TIER2_PAYLOAD: &[u8] = b"meade-v1-tier2-payload-subkey";
/// Domain separation context for Vault Verification Canary.
const HKDF_INFO_VERIFIER: &[u8] = b"meade-v1-vault-verifier";

/// Holds the split Tier-1 (Catalogue Header) and Tier-2 (Secret Payload) subkeys
/// pinned in non-pageable RAM via `VirtualLock` on Windows and wiped on Drop via `Zeroize`.
pub struct VaultKeys {
    tier1_header_key: PinnedKey,
    tier2_payload_key: PinnedKey,
    verifier_tag: [u8; 32],
}

impl VaultKeys {
    /// Generates a fresh random 256-bit salt for initializing a new vault.
    pub fn generate_salt() -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Derives the Master Key from the user passphrase + vault salt using Argon2id
    /// (64 MiB memory, 3 iterations, 4 parallelism lanes) and splits it via HKDF-SHA256.
    pub fn derive_from_passphrase(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self> {
        // 64 MiB (65536 KiB), 3 iterations, 4 lanes, 32-byte output
        let params = Params::new(65_536, 3, 4, Some(KEY_LEN))
            .map_err(|e| MeadeError::Crypto(format!("Invalid Argon2id parameters: {e}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut master_key = Zeroizing::new([0u8; KEY_LEN]);
        argon2
            .hash_password_into(passphrase, salt, master_key.as_mut())
            .map_err(|e| MeadeError::Crypto(format!("Argon2id derivation failed: {e}")))?;

        Self::from_master_key(&master_key, salt)
    }

    /// Derives fast test keys for unit testing (4 MiB, 1 iteration) to keep test suites sub-second.
    pub fn derive_for_testing(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self> {
        let params = Params::new(4_096, 1, 1, Some(KEY_LEN))
            .map_err(|e| MeadeError::Crypto(format!("Invalid Argon2id test parameters: {e}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut master_key = Zeroizing::new([0u8; KEY_LEN]);
        argon2
            .hash_password_into(passphrase, salt, master_key.as_mut())
            .map_err(|e| MeadeError::Crypto(format!("Argon2id test derivation failed: {e}")))?;

        Self::from_master_key(&master_key, salt)
    }

    /// Expands a 256-bit Master Key via HKDF-SHA256 into isolated Tier-1 and Tier-2 subkeys.
    pub fn from_master_key(master_key: &[u8; KEY_LEN], salt: &[u8; SALT_LEN]) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(Some(salt), master_key);

        let mut t1 = [0u8; KEY_LEN];
        hk.expand(HKDF_INFO_TIER1_HEADER, &mut t1)
            .map_err(|e| MeadeError::Crypto(format!("HKDF Tier-1 expansion failed: {e}")))?;
        let tier1_header_key = PinnedKey::new(t1);
        t1.zeroize();

        let mut t2 = [0u8; KEY_LEN];
        hk.expand(HKDF_INFO_TIER2_PAYLOAD, &mut t2)
            .map_err(|e| MeadeError::Crypto(format!("HKDF Tier-2 expansion failed: {e}")))?;
        let tier2_payload_key = PinnedKey::new(t2);
        t2.zeroize();

        let mut verifier_tag = [0u8; 32];
        hk.expand(HKDF_INFO_VERIFIER, &mut verifier_tag)
            .map_err(|e| MeadeError::Crypto(format!("HKDF Verifier expansion failed: {e}")))?;

        Ok(Self {
            tier1_header_key,
            tier2_payload_key,
            verifier_tag,
        })
    }

    /// Access the Tier-1 Catalogue Header subkey.
    pub fn tier1_key(&self) -> &[u8; KEY_LEN] {
        self.tier1_header_key.as_bytes()
    }

    /// Access the Tier-2 Secret Payload subkey.
    pub fn tier2_key(&self) -> &[u8; KEY_LEN] {
        self.tier2_payload_key.as_bytes()
    }

    /// Access the 256-bit verifier tag used to validate passphrase correctness on vault open.
    pub fn verifier_tag(&self) -> &[u8; 32] {
        &self.verifier_tag
    }

    /// Exports the combined subkey material as a Zeroizing 64-byte slice for IPC or OS Keyring wrapping.
    pub fn export_session_blob(&self) -> Zeroizing<[u8; 96]> {
        let mut blob = Zeroizing::new([0u8; 96]);
        blob[0..32].copy_from_slice(self.tier1_key());
        blob[32..64].copy_from_slice(self.tier2_key());
        blob[64..96].copy_from_slice(&self.verifier_tag);
        blob
    }

    /// Reconstructs `VaultKeys` from a 96-byte session blob (used by Daemon / OS Keyring session cache).
    pub fn from_session_blob(blob: &[u8]) -> Result<Self> {
        if blob.len() != 96 {
            return Err(MeadeError::Crypto(
                "Invalid session key blob length".to_string(),
            ));
        }
        let mut t1 = [0u8; 32];
        let mut t2 = [0u8; 32];
        let mut ver = [0u8; 32];
        t1.copy_from_slice(&blob[0..32]);
        t2.copy_from_slice(&blob[32..64]);
        ver.copy_from_slice(&blob[64..96]);

        let keys = Self {
            tier1_header_key: PinnedKey::new(t1),
            tier2_payload_key: PinnedKey::new(t2),
            verifier_tag: ver,
        };
        t1.zeroize();
        t2.zeroize();
        Ok(keys)
    }
}
