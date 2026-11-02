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

#[cfg(test)]
tokio::task_local! {
    static CONSUME_BARRIER: std::sync::Arc<tokio::sync::Barrier>;
}

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
            Err(e) => return util::argon2_error_response(e),
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
    match h.get("totpEnabled").map(String::as_str) {
        // Explicit false remains a supported disabled state even if a legacy
        // writer retained secret/recovery fields. Missing is not equivalent.
        Some("false") => return Ok(true),
        None if !["totpSecret", "recovery", "recoveryVersion"]
            .iter().any(|key| h.contains_key(*key)) => return Ok(true),
        Some("true") => {
            let valid_secret = h.get("totpSecret")
                .and_then(|s| BASE32_NOPAD.decode(s.as_bytes()).ok())
                .is_some_and(|bytes| !bytes.is_empty());
            if !valid_secret { return Err(internal()); }
        }
        _ => return Err(internal()),
    }

    if let Some(code) = body.get("code").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        if let Some(secret) = h.get("totpSecret")
            && let Some(counter) = matching_counter(secret, code)
            // Recheck the current enabled flag and verified secret in the
            // same script that claims the existing replay marker.
            && confirm_totp(store, name, secret, counter).await?
        {
            return Ok(true);
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
                if util::argon2_verify_async(code, hash).await.map_err(util::argon2_error_response)? {
                    // Argon runs outside Redis; consume only if the hash is
                    // still present in the current configuration. Never write
                    // this snapshot back over another login or a rotation.
                    #[cfg(test)]
                    if let Ok(barrier) = CONSUME_BARRIER.try_with(Clone::clone) {
                        barrier.wait().await;
                    }
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

async fn confirm_totp(
    store: &AdminStore,
    name: &str,
    secret: &str,
    counter: u64,
) -> Result<bool, crate::AdminResponse> {
    store.claim_totp(name, secret, counter, STEP * (2 * DRIFT + 2))
        .await.map_err(|_| internal())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Production intentionally shares counter markers across secret rotations.
    // Serialize Redis login tests that exercise that global marker namespace.
    static LOGIN_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    #[ignore = "requires CAP_TEST_REDIS_URL pointing to an isolated Redis"]
    async fn recovery_login_concurrency() {
        cap_kv::cpu::init(cap_kv::cpu::CpuConfig::default()).unwrap();
        let _guard = LOGIN_TEST_LOCK.lock().await;
        let url = std::env::var("CAP_TEST_REDIS_URL").expect("isolated Redis required");
        assert!(!url.is_empty());
        assert_eq!(std::env::var("REDIS_URL").expect("explicit REDIS_URL required"), url);
        let store = AdminStore::connect(&url).await.unwrap();
        let name = &format!("test:2fa:{}", util::random_hex(16));
        // Cheap fixture hashes isolate the CAS race from admission deadlines;
        // production and legacy cost compatibility are tested separately.
        fn fixture(password: &str) -> String {
            use argon2::PasswordHasher;
            let salt = argon2::password_hash::SaltString::encode_b64(b"recovery-test-salt").unwrap();
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13,
                argon2::Params::new(32, 1, 1, None).unwrap())
                .hash_password(password.as_bytes(), &salt).unwrap().to_string()
        }
        let a = fixture("recovery-a");
        let b = fixture("recovery-b");
        store.hset_pairs(name, &[
            ("totpEnabled", "true".into()),
            ("totpSecret", new_secret()),
            ("recoveryVersion", "1".into()),
            ("recovery", serde_json::to_string(&[&a, &b]).unwrap()),
        ]).await.unwrap();
        let body_a = json!({"recovery": "recovery-a"});
        let body_b = json!({"recovery": "recovery-b"});
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let (one, two) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(
                CONSUME_BARRIER.scope(barrier.clone(), check_second_factor_at(&store, &body_a, name)),
                CONSUME_BARRIER.scope(barrier.clone(), check_second_factor_at(&store, &body_b, name)))
        }).await.expect("both verified snapshots must reach consumption barrier");
        assert!(matches!(one, Ok(true)) && matches!(two, Ok(true)));
        assert_eq!(store.hget(name, "recovery").await.unwrap().as_deref(), Some("[]"));
        assert!(check_second_factor_at(&store, &body_a, name).await.is_err());
        assert!(check_second_factor_at(&store, &body_b, name).await.is_err());
        store.hset_pairs(name, &[("recovery", serde_json::to_string(&[&a]).unwrap())]).await.unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let (one, two) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(
                CONSUME_BARRIER.scope(barrier.clone(), check_second_factor_at(&store, &body_a, name)),
                CONSUME_BARRIER.scope(barrier.clone(), check_second_factor_at(&store, &body_a, name)))
        }).await.expect("both verified snapshots must reach consumption barrier");
        let statuses = [one.map(|_| 200).unwrap_or_else(|r| r.status),
            two.map(|_| 200).unwrap_or_else(|r| r.status)];
        assert!(statuses == [200, 401] || statuses == [401, 200], "{statuses:?}");
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

    #[tokio::test]
    #[ignore = "requires CAP_TEST_REDIS_URL pointing to an isolated Redis"]
    async fn totp_state_and_login() {
        cap_kv::cpu::init(cap_kv::cpu::CpuConfig::default()).unwrap();
        let _guard = LOGIN_TEST_LOCK.lock().await;
        let url = std::env::var("CAP_TEST_REDIS_URL").expect("isolated Redis required");
        assert!(!url.is_empty());
        assert_eq!(std::env::var("REDIS_URL").expect("explicit REDIS_URL required"), url);
        let store = AdminStore::connect(&url).await.unwrap();
        let name = &format!("test:totp-state:{}", util::random_hex(16));
        let empty = json!({});
        assert!(matches!(check_second_factor_at(&store, &empty, name).await, Ok(true)));
        let secret = new_secret();
        store.hset_pairs(name, &[("totpPending", secret.clone())]).await.unwrap();
        assert!(matches!(check_second_factor_at(&store, &empty, name).await, Ok(true)));
        for field in ["totpSecret", "recovery", "recoveryVersion"] {
            store.hset_pairs(name, &[(field, "".into())]).await.unwrap();
            assert_eq!(check_second_factor_at(&store, &empty, name).await.err().unwrap().status, 500);
            store.hdel_fields(name, &[field]).await.unwrap();
        }
        for flag in ["", "TRUE", "0", "garbage", "true"] {
            store.hset_pairs(name, &[("totpEnabled", flag.into())]).await.unwrap();
            assert_eq!(check_second_factor_at(&store, &empty, name).await.err().unwrap().status, 500);
        }
        for bad in ["", "invalid base32"] {
            store.hset_pairs(name, &[("totpSecret", bad.into())]).await.unwrap();
            assert_eq!(check_second_factor_at(&store, &empty, name).await.err().unwrap().status, 500);
        }
        store.hset_pairs(name, &[("totpEnabled", "false".into()), ("recovery", "legacy".into())]).await.unwrap();
        assert!(matches!(check_second_factor_at(&store, &empty, name).await, Ok(true)));
        // Use the real publication primitive for initial pending -> enabled.
        assert!(store.publish_totp(name, &secret, "[]").await.unwrap());
        assert_eq!(check_second_factor_at(&store, &empty, name).await.err().unwrap().status, 401);
        let counter = (util::now_secs() / STEP) as u64;
        let code = json!({"code": hotp(&secret, counter).unwrap()});
        let (a, b) = tokio::join!(check_second_factor_at(&store, &code, name), check_second_factor_at(&store, &code, name));
        assert_ne!(matches!(a, Ok(true)), matches!(b, Ok(true)));
        assert_eq!(check_second_factor_at(&store, &code, name).await.err().unwrap().status, 401);
        // Six-digit codes can collide across counters; pick an expired code
        // that is not coincidentally also valid in today's acceptance window.
        let expired_code = (10..100).map(|age| hotp(&secret, counter - age).unwrap())
            .find(|code| !verify(&secret, code)).unwrap();
        let expired = json!({"code": expired_code});
        assert_eq!(check_second_factor_at(&store, &expired, name).await.err().unwrap().status, 401);
        store.del(&format!("2fa:totp-used:{counter}")).await.unwrap();
        // Pause the production flow after code verification, then complete
        // rotation/disable before resuming the atomic confirmation.
        let verified_counter = matching_counter(&secret, code["code"].as_str().unwrap()).unwrap();
        store.hset_pairs(name, &[("totpPending", new_secret())]).await.unwrap();
        let pending = store.hget(name, "totpPending").await.unwrap().unwrap();
        assert!(store.publish_totp(name, &pending, "[]").await.unwrap());
        assert!(matches!(confirm_totp(&store, name, &secret, verified_counter).await, Ok(false)));
        assert!(!store.exists(&format!("2fa:totp-used:{verified_counter}")).await.unwrap());
        store.del(name).await.unwrap();
        assert!(matches!(confirm_totp(&store, name, &pending, verified_counter).await, Ok(false)));
        store.set(name, "wrong type").await.unwrap();
        assert_eq!(confirm_totp(&store, name, &pending, verified_counter).await.err().unwrap().status, 500);
        assert_eq!(check_second_factor_at(&store, &empty, name).await.err().unwrap().status, 500);
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
