use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::crypto::{CRYPTO_SCHEMA_VERSION, KEY_LEN};
use crate::error::{MeadeError, Result};

/// 192-bit (24-byte) nonce required by XChaCha20-Poly1305.
pub const XNONCE_LEN: usize = 24;

/// Distinguishes Tier-1 (Catalogue Metadata Header) from Tier-2 (Secret Payload) in AEAD Associated Data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeTier {
    Tier1Header,
    Tier2Payload,
}

impl EnvelopeTier {
    pub fn as_tag(self) -> &'static [u8] {
        match self {
            Self::Tier1Header => b"T1_HDR",
            Self::Tier2Payload => b"T2_SEC",
        }
    }
}

/// Constructs canonical Associated Data (AAD) binding a ciphertext to its exact row UUID,
/// envelope tier, and schema version so an attacker cannot swap ciphertexts across rows or tiers.
pub fn build_aad(entry_id: &str, tier: EnvelopeTier) -> Vec<u8> {
    let mut aad = Vec::with_capacity(entry_id.len() + 16);
    aad.extend_from_slice(b"meade-aad-v");
    aad.push(CRYPTO_SCHEMA_VERSION);
    aad.push(b'|');
    aad.extend_from_slice(tier.as_tag());
    aad.push(b'|');
    aad.extend_from_slice(entry_id.as_bytes());
    aad
}

/// Encrypts plaintext using XChaCha20-Poly1305 with a fresh CSPRNG 192-bit nonce and bound AAD.
pub fn seal_envelope(
    subkey: &[u8; KEY_LEN],
    entry_id: &str,
    tier: EnvelopeTier,
    plaintext: &[u8],
) -> Result<([u8; XNONCE_LEN], Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(subkey));
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let aad = build_aad(entry_id, tier);
    let payload = Payload {
        msg: plaintext,
        aad: &aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| MeadeError::Crypto("XChaCha20-Poly1305 encryption failed".to_string()))?;

    Ok((nonce_bytes, ciphertext))
}

/// Decrypts and authenticates an XChaCha20-Poly1305 envelope into a Zeroizing buffer.
/// Fails closed if the key, nonce, ciphertext, entry_id, or tier has been modified.
pub fn open_envelope(
    subkey: &[u8; KEY_LEN],
    entry_id: &str,
    tier: EnvelopeTier,
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if nonce_bytes.len() != XNONCE_LEN {
        return Err(MeadeError::Crypto(format!(
            "Invalid XNonce length: expected {XNONCE_LEN}, got {}",
            nonce_bytes.len()
        )));
    }

    let cipher = XChaCha20Poly1305::new(Key::from_slice(subkey));
    let nonce = XNonce::from_slice(nonce_bytes);
    let aad = build_aad(entry_id, tier);
    let payload = Payload {
        msg: ciphertext,
        aad: &aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| MeadeError::AuthenticationFailed)?;

    Ok(Zeroizing::new(plaintext))
}
