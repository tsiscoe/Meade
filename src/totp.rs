use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::error::{MeadeError, Result};

type HmacSha1 = Hmac<Sha1>;

/// Default TOTP time step in seconds (RFC 6238).
pub const TOTP_PERIOD_SECS: u64 = 30;
/// Default TOTP code length (6 digits).
pub const TOTP_DIGITS: u32 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpSnapshot {
    pub code: String,
    pub remaining_secs: u64,
    pub period_secs: u64,
}

/// Extracts and decodes the raw Base32 secret from either a plain Base32 string
/// (e.g., `JBSWY3DPEHPK3PXP`) or an `otpauth://totp/...?secret=JBSWY3DPEHPK3PXP` URI.
pub fn decode_totp_secret(input: &str) -> Result<Zeroizing<Vec<u8>>> {
    let trimmed = input.trim();
    let raw_secret = if trimmed.starts_with("otpauth://") {
        extract_query_param(trimmed, "secret").ok_or_else(|| {
            MeadeError::Totp("Missing `secret=` parameter in otpauth:// URI".into())
        })?
    } else {
        trimmed.to_string()
    };

    // Strip spaces, hyphens, and padding '=' characters, and uppercase for RFC 4648 Base32
    let normalized: String = raw_secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();

    if normalized.is_empty() {
        return Err(MeadeError::Totp("Empty TOTP secret".into()));
    }

    let decoded = BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|e| MeadeError::Totp(format!("Invalid Base32 TOTP secret: {e}")))?;

    Ok(Zeroizing::new(decoded))
}

fn extract_query_param(uri: &str, key: &str) -> Option<String> {
    let (_, query) = uri.split_once('?')?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k.eq_ignore_ascii_case(key)
        {
            return Some(v.to_string());
        }
    }
    None
}

/// Generates an RFC 6238 / RFC 4226 TOTP code for a specific Unix timestamp in seconds.
pub fn generate_totp_at(secret_input: &str, unix_secs: u64) -> Result<TotpSnapshot> {
    let key_bytes = decode_totp_secret(secret_input)?;
    let counter = unix_secs / TOTP_PERIOD_SECS;
    let remaining_secs = TOTP_PERIOD_SECS - (unix_secs % TOTP_PERIOD_SECS);

    let mut mac = HmacSha1::new_from_slice(&key_bytes)
        .map_err(|e| MeadeError::Totp(format!("HMAC initialization error: {e}")))?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    // Dynamic truncation per RFC 4226 Section 5.4
    let offset = (result[19] & 0x0f) as usize;
    let binary = ((u32::from(result[offset]) & 0x7f) << 24)
        | ((u32::from(result[offset + 1]) & 0xff) << 16)
        | ((u32::from(result[offset + 2]) & 0xff) << 8)
        | (u32::from(result[offset + 3]) & 0xff);

    let modulus = 10_u32.pow(TOTP_DIGITS);
    let otp = binary % modulus;
    let code = format!("{otp:06}");

    Ok(TotpSnapshot {
        code,
        remaining_secs,
        period_secs: TOTP_PERIOD_SECS,
    })
}

/// Generates a live RFC 6238 TOTP code for the current system clock.
pub fn generate_totp_now(secret_input: &str) -> Result<TotpSnapshot> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| MeadeError::Totp(format!("System clock error: {e}")))?
        .as_secs();
    generate_totp_at(secret_input, now)
}
