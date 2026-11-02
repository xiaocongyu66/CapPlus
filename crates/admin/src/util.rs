//! Small crypto / encoding helpers shared by the admin handlers.

use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHasher};
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
        .replace(['+', '/', '='], "")
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

#[derive(Debug)]
pub enum ArgonError {
    Cpu(cap_kv::cpu::CpuError),
    InvalidPhc,
    HashFailed,
}

pub(crate) fn argon2_error_response(error: ArgonError) -> crate::AdminResponse {
    if matches!(error, ArgonError::Cpu(cap_kv::cpu::CpuError::Busy)) {
        let mut response = crate::resp(
            503,
            serde_json::json!({"success": false, "error": "CPU service busy"}),
        );
        response.headers.push(("Retry-After".into(), "1".into()));
        response
    } else {
        crate::internal()
    }
}

fn argon2_hash(password: &str) -> Result<String, ArgonError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ArgonError::HashFailed)
}

fn argon2_verify(password: &str, phc: &str) -> Result<bool, ArgonError> {
    cap_verify::verify_argon2(password, phc).map_err(|_| ArgonError::InvalidPhc)
}

/// Wrong passwords are Ok(false); admission and malformed stored PHCs are errors.
pub async fn argon2_verify_async(password: &str, phc: &str) -> Result<bool, ArgonError> {
    cap_verify::validate_argon2_phc(phc).map_err(|_| ArgonError::InvalidPhc)?;
    let (password, phc) = (password.to_string(), phc.to_string());
    cap_kv::cpu::run_cpu(cap_kv::cpu::CpuClass::Argon, move || {
        argon2_verify(&password, &phc)
    })
    .await
    .map_err(ArgonError::Cpu)?
}

pub async fn argon2_hash_async(password: &str) -> Result<String, ArgonError> {
    let password = password.to_string();
    cap_kv::cpu::run_cpu(cap_kv::cpu::CpuClass::Argon, move || argon2_hash(&password))
        .await
        .map_err(ArgonError::Cpu)?
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

#[cfg(test)]
mod cpu_tests {
    use super::*;
    #[test]
    fn password_mismatch_and_service_failure_are_distinct() {
        let phc = argon2_hash("correct").unwrap();
        assert!(argon2_verify("correct", &phc).unwrap());
        assert!(!argon2_verify("wrong", &phc).unwrap());
        assert!(matches!(
            argon2_verify("x", "broken"),
            Err(ArgonError::InvalidPhc)
        ));
        assert_eq!(
            argon2_error_response(ArgonError::Cpu(cap_kv::cpu::CpuError::Busy)).status,
            503
        );
        assert_eq!(argon2_error_response(ArgonError::InvalidPhc).status, 500);
        assert_eq!(
            argon2_error_response(ArgonError::Cpu(cap_kv::cpu::CpuError::WorkerFailed)).status,
            500
        );
    }
    #[test]
    fn accepts_legacy_node_argon2_default_costs() {
        let params = argon2::Params::new(65536, 3, 4, None).unwrap();
        let legacy = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let salt = SaltString::encode_b64(b"legacy-test-salt").unwrap();
        let phc = legacy.hash_password(b"correct", &salt).unwrap().to_string();
        assert!(argon2_verify("correct", &phc).unwrap());
        assert!(!argon2_verify("wrong", &phc).unwrap());
    }
    #[test]
    fn rejects_excessive_phc_work_before_hashing() {
        let phc = argon2_hash("correct").unwrap();
        for excessive in ["m=65537,t=2,p=1", "m=19456,t=11,p=1", "m=19456,t=2,p=5"] {
            let bad = phc.replace("m=19456,t=2,p=1", excessive);
            assert_ne!(phc, bad);
            assert!(matches!(
                argon2_verify("correct", &bad),
                Err(ArgonError::InvalidPhc)
            ));
        }
    }
}
