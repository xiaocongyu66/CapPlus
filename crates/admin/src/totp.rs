//! TOTP (RFC 6238) + recovery codes for admin two-factor authentication.
//!
//! Single-admin storage on hash `settings:2fa`:
//! - `totpSecret`  base32 (no padding) shared secret
//! - `totpPending` secret awaiting confirmation (setup started, not enabled)
//! - `totpEnabled` `"true"` once the first code checks out
//! - `recovery`    JSON array of argon2 hashes (single use)
//! - `recoveryVersion` `"1"` only for freshly published atomic-consumption sets;
//!   missing/older versions cannot authenticate (normal TOTP remains valid).

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha1::Sha1;

use crate::util;
use crate::{AdminConfig, AdminStore, bad_request, internal, ok, resp};

type HmacSha1 = Hmac<Sha1>;

const TWOFA_KEY: &str = "settings:2fa";

/// Interval in seconds, as every authenticator app assumes.
const STEP: i64 = 30;
const DIGITS: u32 = 6;
/// Accept one step of clock drift either way.
const DRIFT: i64 = 1;
const RECOVERY_COUNT: usize = 10;

pub(crate) fn new_secret() -> String {
    BASE32_NOPAD.encode(&util::random_bytes(20))
}

fn hotp(secret_b32: &str, counter: u64) -> Option<String> {
    let key = BASE32_NOPAD.decode(secret_b32.as_bytes()).ok()?;
    let mut mac = HmacSha1::new_from_slice(&key).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let off = (digest[19] & 0x0f) as usize;
    let bin = ((digest[off] as u32 & 0x7f) << 24)
        | ((digest[off + 1] as u32) << 16)
        | ((digest[off + 2] as u32) << 8)
        | (digest[off + 3] as u32);
    let code = bin % 10u32.pow(DIGITS);
    Some(format!("{code:0width$}", width = DIGITS as usize))
}

/// Verify a 6-digit code against the current time step (±1).
pub(crate) fn verify(secret_b32: &str, code: &str) -> bool {
    matching_counter(secret_b32, code).is_some()
}

/// The time step a valid code belongs to, so the caller can mark it used.
fn matching_counter(secret_b32: &str, code: &str) -> Option<u64> {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let now = util::now_secs() / STEP;
    (-DRIFT..=DRIFT)
        .map(|d| (now + d).max(0) as u64)
        .find(|&counter| hotp(secret_b32, counter).as_deref() == Some(code.as_str()))
}

/// `otpauth://` URI for authenticator apps.
pub(crate) fn otpauth_uri(issuer: &str, account: &str, secret: &str) -> String {
    let issuer_enc = urlencode(issuer);
    let account_enc = urlencode(account);
    format!(
        "otpauth://totp/{issuer_enc}:{account_enc}?secret={secret}&issuer={issuer_enc}&algorithm=SHA1&digits={DIGITS}&period={STEP}"
    )
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn recovery_codes() -> Vec<String> {
    (0..RECOVERY_COUNT)
        .map(|_| {
            let raw = util::random_hex(16);
            format!("{}-{}", &raw[..4], &raw[4..])
        })
        .collect()
}

pub(crate) async fn status(store: &AdminStore) -> Value {
    let h = store.hgetall(TWOFA_KEY).await.unwrap_or_default();
    json!({
        "enabled": h.get("totpEnabled").map(|v| v == "true").unwrap_or(false),
        "pending": h.contains_key("totpPending"),
        "recoveryRegenerationRequired": h.get("totpEnabled").map(String::as_str) == Some("true")
            && h.get("recoveryVersion").map(String::as_str) != Some("1"),
        "recoveryCodes": h
            .get("recovery")
            .and_then(|v| serde_json::from_str::<Vec<String>>(v).ok())
            .map(|v| v.len())
            .unwrap_or(0),
    })
}

/// `POST /auth/2fa/setup` → fresh secret + otpauth URI, not yet enabled.
pub(crate) async fn setup(store: &AdminStore) -> crate::AdminResponse {
    let secret = new_secret();
    if store
        .hset_pairs(TWOFA_KEY, &[("totpPending", secret.clone())])
        .await
        .is_err()
    {
        return internal();
    }
    ok(json!({
        "secret": secret,
        "uri": otpauth_uri("Cap", "admin", &secret),
    }))
}

/// `POST /auth/2fa/enable` → confirm a code, switch 2FA on, mint recovery codes.
pub(crate) async fn enable(store: &AdminStore, body: &Value) -> crate::AdminResponse {
    let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("");
    let pending = match store.hget(TWOFA_KEY, "totpPending").await {
        Ok(Some(s)) => s,
        _ => return bad_request("Start two-factor setup first"),
    };
    if !verify(&pending, code) {
        return bad_request("That code is not valid, check your authenticator app");
    }

    let codes = recovery_codes();
    let mut hashes = Vec::new();
    for c in &codes {
        match util::argon2_hash_async(c).await {
            Ok(h) => hashes.push(h),
            Err(_) => return internal(),
        }
    }

    let recovery = serde_json::to_string(&hashes).expect("string hashes serialize");
    match store.publish_totp(TWOFA_KEY, &pending, &recovery).await {
        Ok(true) => {}
        Ok(false) => return bad_request("Two-factor setup changed; start again"),
        Err(_) => return internal(),
    }

    ok(json!({ "success": true, "recoveryCodes": codes }))
}

/// `POST /auth/2fa/disable` → requires confirming `admin_key`.
pub(crate) async fn disable(
    store: &AdminStore,
    cfg: &AdminConfig,
    body: &Value,
) -> crate::AdminResponse {
    let provided = body
        .get("admin_key")
        .or_else(|| body.get("password"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !util::admin_key_eq(&cfg.admin_key, provided) {
        return resp(401, json!({ "success": false, "error": "Incorrect admin key" }));
    }
    if store
        .hdel_fields(TWOFA_KEY, &["totpSecret", "totpEnabled", "recovery", "totpPending", "recoveryVersion"])
        .await
        .is_err()
    {
        return internal();
    }
    ok(json!({ "success": true }))
}

/// Check a login attempt's second factor. `Ok(true)` = passed.
pub(crate) async fn check_second_factor(
    store: &AdminStore,
    body: &Value,
) -> Result<bool, crate::AdminResponse> {
    check_second_factor_at(store, body, TWOFA_KEY).await
}

async fn check_second_factor_at(
    store: &AdminStore,
    body: &Value,
    name: &str,
) -> Result<bool, crate::AdminResponse> {
    // A storage error must not silently skip the second factor.
    let h = match store.hgetall(name).await {
        Ok(h) => h,
        Err(_) => return Err(crate::internal()),
    };
    if h.get("totpEnabled").map(|v| v == "true") != Some(true) {
        return Ok(true);
    }

    if let Some(code) = body.get("code").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        if let Some(secret) = h.get("totpSecret") {
            if let Some(counter) = matching_counter(secret, code) {
                // One login per time step: an observed code cannot be
                // replayed inside its validity window. SET NX makes the
                // claim atomic across concurrent logins.
                let used_key = format!("2fa:totp-used:{counter}");
                let ttl = STEP * (2 * DRIFT + 2);
                if store.set_nx_ex(&used_key, "1", ttl).await.unwrap_or(false) {
                    return Ok(true);
                }
            }
        }
        return Err(resp(
            401,
            json!({ "success": false, "twofa": true, "error": "Invalid authentication code" }),
        ));
    }

    if let Some(code) = body
        .get("recovery")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        let hashes: Vec<String> = h
            .get("recovery")
            .and_then(|v| serde_json::from_str(v).ok())
            .unwrap_or_default();
        if let Some(secret) = h.get("totpSecret") {
            for hash in &hashes {
                if util::argon2_verify_async(code, hash).await {
                    // Argon runs outside Redis; consume only if the hash is
                    // still present in the current configuration. Never write
                    // this snapshot back over another login or a rotation.
                    match store.consume_recovery_hash(name, secret, hash).await {
                        Ok(true) => return Ok(true),
                        Ok(false) => break,
                        Err(_) => return Err(internal()),
                    }
                }
            }
        }
        return Err(resp(
            401,
            json!({ "success": false, "twofa": true, "error": "Invalid recovery code" }),
        ));
    }

    Err(resp(
        401,
        json!({ "success": false, "twofa": true, "error": "Authentication code required" }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires CAP_TEST_REDIS_URL pointing to an isolated Redis"]
    async fn recovery_login_concurrency() {
        let store = AdminStore::connect(&std::env::var("CAP_TEST_REDIS_URL").unwrap()).await.unwrap();
        let name = &format!("test:2fa:{}", util::random_hex(16));
        let a = util::argon2_hash_async("recovery-a").await.unwrap();
        let b = util::argon2_hash_async("recovery-b").await.unwrap();
        store.hset_pairs(name, &[
            ("totpEnabled", "true".into()),
            ("totpSecret", new_secret()),
            ("recoveryVersion", "1".into()),
            ("recovery", serde_json::to_string(&[&a, &b]).unwrap()),
        ]).await.unwrap();
        let body_a = json!({"recovery": "recovery-a"});
        let body_b = json!({"recovery": "recovery-b"});
        let (one, two) = tokio::join!(check_second_factor_at(&store, &body_a, name), check_second_factor_at(&store, &body_b, name));
        assert!(matches!(one, Ok(true)) && matches!(two, Ok(true)));
        assert_eq!(store.hget(name, "recovery").await.unwrap().as_deref(), Some("[]"));
        assert!(check_second_factor_at(&store, &body_a, name).await.is_err());
        assert!(check_second_factor_at(&store, &body_b, name).await.is_err());
        store.hset_pairs(name, &[("recovery", serde_json::to_string(&[&a]).unwrap())]).await.unwrap();
        let (one, two) = tokio::join!(check_second_factor_at(&store, &body_a, name), check_second_factor_at(&store, &body_a, name));
        assert_ne!(matches!(one, Ok(true)), matches!(two, Ok(true)));
        assert_eq!(store.hget(name, "recovery").await.unwrap().as_deref(), Some("[]"));
        // Legacy recovery is refused independently of markers, while ordinary
        // TOTP still works, allowing authenticated users to regenerate codes.
        store.hdel_fields(name, &["recoveryVersion"]).await.unwrap();
        store.hset_pairs(name, &[("recovery", serde_json::to_string(&[&a]).unwrap())]).await.unwrap();
        assert!(check_second_factor_at(&store, &body_a, name).await.is_err());
        let secret = store.hget(name, "totpSecret").await.unwrap().unwrap();
        let counter = (util::now_secs() / STEP).max(0) as u64;
        let totp = json!({"code": hotp(&secret, counter).unwrap()});
        assert!(matches!(check_second_factor_at(&store, &totp, name).await, Ok(true)));
        store.del(&format!("2fa:totp-used:{counter}")).await.unwrap();
        store.del(name).await.unwrap();
    }

    #[test]
    fn rfc6238_vector() {
        // RFC 6238 appendix B, SHA-1, secret "12345678901234567890".
        let secret = BASE32_NOPAD.encode(b"12345678901234567890");
        assert_eq!(hotp(&secret, 1).unwrap(), "287082");
        assert_eq!(hotp(&secret, 59 / 30).unwrap(), "287082");
    }

    #[test]
    fn verify_window_and_shape() {
        let secret = new_secret();
        assert!(!verify(&secret, "12345"));
        assert!(!verify(&secret, "abcdef"));
        let now = util::now_secs() / STEP;
        let good = hotp(&secret, now.max(0) as u64).unwrap();
        assert!(verify(&secret, &good));
    }
}
