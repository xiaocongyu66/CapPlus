//! Tests for the admin API.
//!
//! Shared helpers live here; the cases are split by topic so each file stays
//! readable. Redis cases require matching explicit URLs for an isolated instance.
//! Run serially (`--test-threads=1`): some cases exercise global settings/CPU admission.

use super::*;

    use base64::Engine;
    use serde_json::json;

    // Both URLs must explicitly identify the same disposable test instance.
    // Never fall back to a developer's default Redis.
    fn redis_url() -> Option<String> {
        let url = std::env::var("REDIS_URL").expect("explicit isolated REDIS_URL required");
        let isolated = std::env::var("CAP_TEST_REDIS_URL").expect("explicit isolated CAP_TEST_REDIS_URL required");
        assert!(!url.is_empty() && url == isolated,
            "REDIS_URL and CAP_TEST_REDIS_URL must identify the same isolated instance");
        Some(url)
    }

    async fn setup() -> Option<(AdminStore, AdminConfig)> {
        let url = redis_url()?;
        cap_kv::cpu::init(cap_kv::cpu::CpuConfig::default()).unwrap();
        let cfg = AdminConfig {
            admin_key: "test-admin-key-1234567890".into(),
            demo: false,
        };
        let store = AdminStore::connect(&url).await
            .expect("explicit isolated test Redis must be available");
        Some((store, cfg))
    }

    fn uniq() -> String {
        format!("{}{}", util::now_ms(), util::random_hex(4))
    }

    async fn call(
        store: &AdminStore,
        cfg: &AdminConfig,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: Value,
    ) -> AdminResponse {
        let bytes = serde_json::to_vec(&body).unwrap();
        // The host server resolves the client address before calling in; the
        // tests stand in for it with a fixed `x-test-peer`, otherwise a fresh
        // address per call so unrelated tests never share a login bucket.
        let peer = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-test-peer"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| format!("test-{}", uniq()));
        let req = AdminRequest {
            method,
            path,
            query: "",
            headers: &headers,
            body: &bytes,
            peer: &peer,
        };
        handle(store, cfg, &req).await
    }

    fn bearer(token: &str, hash: &str) -> Vec<(String, String)> {
        let payload = json!({ "token": token, "hash": hash }).to_string();
        let enc = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        vec![("Authorization".into(), format!("Bearer {enc}"))]
    }

    fn bot(api_key: &str) -> Vec<(String, String)> {
        vec![("Authorization".into(), format!("Bot {api_key}"))]
    }

    async fn login(store: &AdminStore, cfg: &AdminConfig) -> (String, String) {
        let r = call(
            store,
            cfg,
            "POST",
            "/auth/login",
            vec![],
            json!({"admin_key": cfg.admin_key}),
        )
        .await;
        assert_eq!(r.status, 200, "login status");
        let token = r.body["session_token"].as_str().unwrap().to_string();
        let hash = r.body["hashed_token"].as_str().unwrap().to_string();
        (token, hash)
    }

    #[tokio::test]
    async fn cpu_busy_is_503_wrong_password_is_401_and_large_phc_is_rejected() {
        let Some((store, cfg)) = setup().await else { return; };
        let (token, hash) = login(&store, &cfg).await;
        let wrong = call(&store, &cfg, "GET", "/keys", bearer("wrong-password", &hash), json!({})).await;
        assert_eq!(wrong.status, 401);

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let held = tokio::spawn(cap_kv::cpu::run_cpu(cap_kv::cpu::CpuClass::Argon, move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        }));
        started_rx.await.unwrap();
        let busy = call(&store, &cfg, "GET", "/keys", bearer(&token, &hash), json!({})).await;
        // Release before asserting so even a failed assertion cannot strand a worker.
        release_tx.send(()).unwrap();
        held.await.unwrap().unwrap();
        assert_eq!(busy.status, 503);
        assert!(busy.headers.iter().any(|(k, v)| k == "Retry-After" && v == "1"));

        let oversized = hash.replace("m=19456,", "m=65537,");
        assert_ne!(oversized, hash);
        let key = format!("session:{oversized}");
        store.set_ex(&key, &json!({"expires": util::now_ms() + 60000}).to_string(), 60).await.unwrap();
        let rejected = call(&store, &cfg, "GET", "/keys", bearer(&token, &oversized), json!({})).await;
        store.del(&key).await.unwrap();
        assert_eq!(rejected.status, 500);
        store.del(&format!("session:{hash}")).await.unwrap();
        store.srem("sessions", &hash).await.unwrap();
    }

#[tokio::test]
async fn login_busy_preserves_second_factor_credentials() {
    use hmac::{Hmac, Mac};
    let (store, cfg) = setup().await.unwrap();
    assert!(!store.exists("settings:2fa").await.unwrap(), "requires clean isolated settings");
    let secret = crate::totp::new_secret();
    let counter = (util::now_secs() / 30) as u64;
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(
        &data_encoding::BASE32_NOPAD.decode(secret.as_bytes()).unwrap()).unwrap();
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 15) as usize;
    let number = u32::from_be_bytes(digest[offset..offset+4].try_into().unwrap()) & 0x7fffffff;
    let code = format!("{:06}", number % 1_000_000);
    let recovery = serde_json::to_string(&[util::argon2_hash_async("one-use").await.unwrap()]).unwrap();
    store.hset_pairs("settings:2fa", &[("totpEnabled", "true".into()),
        ("totpSecret", secret), ("recoveryVersion", "1".into()), ("recovery", recovery.clone())]).await.unwrap();
    let marker = format!("2fa:totp-used:{counter}");
    assert!(!store.exists(&marker).await.unwrap());
    let sessions = store.smembers("sessions").await.unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let held = tokio::spawn(cap_kv::cpu::run_cpu(cap_kv::cpu::CpuClass::Argon, move || {
        let _ = started_tx.send(());
        let _ = release_rx.recv();
    }));
    started_rx.await.unwrap();
    let totp = call(&store, &cfg, "POST", "/auth/login", vec![],
        json!({"admin_key": cfg.admin_key, "code": code})).await;
    let recovery_response = call(&store, &cfg, "POST", "/auth/login", vec![],
        json!({"admin_key": cfg.admin_key, "recovery": "one-use"})).await;
    release_tx.send(()).unwrap();
    held.await.unwrap().unwrap();
    assert_eq!(totp.status, 503);
    assert_eq!(recovery_response.status, 503);
    assert!(!store.exists(&marker).await.unwrap());
    assert_eq!(store.hget("settings:2fa", "recovery").await.unwrap().as_deref(), Some(recovery.as_str()));
    assert_eq!(store.smembers("sessions").await.unwrap(), sessions);
    store.del("settings:2fa").await.unwrap();
}

#[tokio::test]
async fn login_counter_atomic_ttl_concurrency_and_errors() {
    let (store, cfg) = setup().await.unwrap();
    let peer = format!("atomic-login-{}", uniq());
    let headers = vec![("x-test-peer".into(), peer.clone())];
    // Wrong credentials exercise counting without adding unrelated CPU work.
    let before = util::now_ms() / 20_000;
    assert_eq!(call(&store, &cfg, "POST", "/auth/login", headers.clone(),
        json!({"admin_key": "wrong"})).await.status, 401);
    let after = util::now_ms() / 20_000;
    let mut key = format!("rl:login:{peer}:20000:{before}");
    if !store.exists(&key).await.unwrap() {
        key = format!("rl:login:{peer}:20000:{after}");
    }
    // redis-cli is used only to inspect TTL; both connection URLs were checked by setup.
    let output = std::process::Command::new("redis-cli")
        .args(["-u", &redis_url().unwrap(), "--raw", "TTL", &key])
        .output().expect("Redis integration tests require redis-cli");
    assert!(output.status.success());
    let ttl: i64 = String::from_utf8(output.stdout).unwrap().trim().parse().unwrap();
    assert!((1..=21).contains(&ttl), "first login TTL: {ttl}");
    store.del(&key).await.unwrap();

    let key = format!("test:login-counter:{}", uniq());
    let (a, b) = tokio::join!(store.incr_with_expire(&key, 21), store.incr_with_expire(&key, 21));
    let mut counts = [a.unwrap(), b.unwrap()];
    counts.sort();
    assert_eq!(counts, [1, 2]);
    store.del(&key).await.unwrap();

    // Poison both possible window keys so a boundary cannot turn an error into success.
    let window = util::now_ms() / 20_000;
    for w in [window, window + 1] {
        store.set(&format!("rl:login:{peer}:20000:{w}"), "not-an-integer").await.unwrap();
    }
    let failed = call(&store, &cfg, "POST", "/auth/login", headers,
        json!({"admin_key": cfg.admin_key})).await;
    for w in [window, window + 1] {
        store.del(&format!("rl:login:{peer}:20000:{w}")).await.unwrap();
    }
    assert_eq!(failed.status, 500);
}

mod part1;
mod part2;
