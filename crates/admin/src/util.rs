//! Small crypto / encoding helpers shared by the admin handlers.

use argon2::password_hash::{PasswordHash, SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn now_secs() -> i64 {
    now_ms() / 1000
}

/// ISO-8601 with milliseconds + `Z`, matching JS `Date#toISOString`.
pub fn iso_from_ms(ms: i64) -> String {
    match chrono::DateTime::from_timestamp_millis(ms) {
        Some(dt) => dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        None => String::new(),
    }
}

/// RFC-1123 HTTP date, matching `new Date(ms).toUTCString()`.
pub fn http_date(ms: i64) -> String {
    match chrono::DateTime::from_timestamp_millis(ms) {
        Some(dt) => dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
        None => String::new(),
    }
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn random_hex(n: usize) -> String {
    hex(&random_bytes(n))
}

/// Decode a `btoa(...)` payload (standard base64, may carry padding).
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let t = s.trim();
    STANDARD
        .decode(t)
        .or_else(|_| STANDARD_NO_PAD.decode(t))
        .ok()
}

pub fn b64url_nopad(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// `randomBytes(n).toString("base64")` with `+ / =` stripped (JS secretKey).
pub fn b64_strip(bytes: &[u8]) -> String {
    STANDARD
        .encode(bytes)
        .replace('+', "")
        .replace('/', "")
        .replace('=', "")
}

pub fn sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex(&h.finalize())
}

/// Constant-time comparison of two admin keys via their fixed-length digests
/// (mirrors `timingSafeEqual(sha256(a), sha256(b))` in auth.js).
pub fn admin_key_eq(expected: &str, provided: &str) -> bool {
    let a = Sha256::digest(provided.as_bytes());
    let b = Sha256::digest(expected.as_bytes());
    a.ct_eq(&b).into()
}

pub fn argon2_hash(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

pub fn argon2_verify(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Normalize an integrity hash the way `integrity.js#norm` does: trim, lower,
/// drop a leading `sha256-`, and require 64 hex chars. Returns `None` otherwise.
pub fn norm_hash(v: &Value) -> Option<String> {
    let s = v.as_str()?;
    let cleaned = s
        .trim()
        .to_lowercase()
        .strip_prefix("sha256-")
        .map(|x| x.to_string())
        .unwrap_or_else(|| s.trim().to_lowercase());
    if cleaned.len() == 64 && cleaned.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(cleaned)
    } else {
        None
    }
}

pub fn last_chars(s: &str, n: usize) -> String {
    let count = s.chars().count();
    s.chars().skip(count.saturating_sub(n)).collect()
}
