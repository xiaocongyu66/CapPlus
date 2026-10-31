//! Repository layer for Cap (port of the JS server's Redis usage), backed by
//! `cap-kv` (SQLite data directory or Redis).
//!
//! Key schema (identical to the JavaScript server, so both can share one
//! instance during migration):
//!
//! | key | type | meaning |
//! |---|---|---|
//! | `key:<siteKey>` | hash | `jwtSecret`, `secretHash`, `config` (JSON) |
//! | `blocklist:<sigHex>` | string EX | nonce consumption (`SET NX EX`) |
//! | `token:<token>` | string = expiresMs EX | issued verification token |
//! | `bind:<token>` | JSON, EX | session bind captured at redeem |
//! | `verified:<token>` | "1", EX | token came from the Cap-hosted iframe |
//! | `rl:<scope>:<ip>:<windowMs>:<window>` | counter | fixed-window rate limit |
//! | `metrics:failed:<siteKey>` | hash | failure metrics |

use std::collections::HashMap;
use std::fmt;

use cap_kv::Kv;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum StoreError {
    Kv(cap_kv::KvError),
    Json(serde_json::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Kv(e) => write!(f, "{e}"),
            StoreError::Json(e) => write!(f, "json: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<cap_kv::KvError> for StoreError {
    fn from(e: cap_kv::KvError) -> Self {
        StoreError::Kv(e)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        StoreError::Json(e)
    }
}

fn d_difficulty() -> u32 {
    4
}
fn d_challenge_count() -> u32 {
    80
}
fn d_salt_size() -> u32 {
    32
}
fn d_protocol() -> String {
    "hashwx".into()
}
fn d_true() -> bool {
    true
}
fn d_obfuscation() -> u8 {
    3
}
fn d_rsw_t() -> u64 {
    75_000
}
fn d_hashwx_difficulty() -> u64 {
    1_000_000
}

/// Per-key configuration. Mirrors `keyDefaults` (+ per-key fields) from
/// `standalone/src/server.js`; unknown fields are ignored so the JS-side schema
/// can keep growing without breaking the Rust reader.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct KeyConfig {
    #[serde(default = "d_difficulty")]
    pub difficulty: u32,
    #[serde(default = "d_challenge_count")]
    pub challenge_count: u32,
    #[serde(default = "d_salt_size")]
    pub salt_size: u32,
    #[serde(default = "d_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub instrumentation: bool,
    #[serde(default = "d_obfuscation")]
    pub obfuscation_level: u8,
    #[serde(default)]
    pub block_automated_browsers: bool,
    /// bool or an explicit list of probe keys (JS allows both).
    #[serde(default)]
    pub extended_probes: serde_json::Value,
    #[serde(default)]
    pub polymorphism: f64,
    #[serde(default)]
    pub require_session_bind: bool,
    #[serde(default = "d_true")]
    pub block_on_deny: bool,
    #[serde(default)]
    pub auto_block_on_deny: bool,
    #[serde(default)]
    pub auto_block_deny_ms: Option<i64>,
    #[serde(default)]
    pub throttle_on_restrict: bool,
    #[serde(default)]
    pub throttle_restrict_ms: Option<i64>,
    #[serde(default)]
    pub ratelimit_max: Option<i64>,
    #[serde(default)]
    pub ratelimit_duration: Option<i64>,
    #[serde(default)]
    pub cors_origins: Option<Vec<String>>,
    #[serde(default)]
    pub block_non_browser_ua: Option<bool>,
    #[serde(default)]
    pub required_headers: Option<Vec<String>>,
    #[serde(default)]
    pub rsw: bool,
    #[serde(default = "d_rsw_t")]
    pub rsw_t: u64,
    #[serde(default = "d_hashwx_difficulty")]
    pub hashwx_difficulty: u64,
}

impl Default for KeyConfig {
    // Explicit construction: deriving via `serde_json::from_str("{}")` would
    // recurse forever (the container-level `default` attribute calls this).
    fn default() -> Self {
        Self {
            difficulty: d_difficulty(),
            challenge_count: d_challenge_count(),
            salt_size: d_salt_size(),
            protocol: d_protocol(),
            instrumentation: false,
            obfuscation_level: d_obfuscation(),
            block_automated_browsers: false,
            extended_probes: serde_json::Value::Bool(false),
            polymorphism: 0.0,
            require_session_bind: false,
            block_on_deny: true,
            auto_block_on_deny: false,
            auto_block_deny_ms: None,
            throttle_on_restrict: false,
            throttle_restrict_ms: None,
            ratelimit_max: None,
            ratelimit_duration: None,
            cors_origins: None,
            block_non_browser_ua: None,
            required_headers: None,
            rsw: false,
            rsw_t: d_rsw_t(),
            hashwx_difficulty: d_hashwx_difficulty(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub site_key: String,
    pub jwt_secret: String,
    pub secret_hash: String,
    pub config: KeyConfig,
}

#[derive(Clone)]
pub struct Store {
    kv: Kv,
}

impl Store {
    pub fn new(kv: Kv) -> Self {
        Self { kv }
    }

    pub async fn connect(redis_url: &str) -> Result<Self, StoreError> {
        Ok(Self { kv: Kv::connect_redis(redis_url).await? })
    }

    pub fn kv(&self) -> &Kv {
        &self.kv
    }

    /// Load the key hash. `None` when the site key does not exist.
    pub async fn key(&self, site_key: &str) -> Result<Option<KeyInfo>, StoreError> {
        let fields = self.kv.hgetall(&format!("key:{site_key}")).await?;
        if fields.is_empty() {
            return Ok(None);
        }
        let jwt_secret = fields.get("jwtSecret").cloned().unwrap_or_default();
        let secret_hash = fields.get("secretHash").cloned().unwrap_or_default();
        let config = match fields.get("config") {
            Some(raw) => serde_json::from_str(raw)?,
            None => KeyConfig::default(),
        };
        Ok(Some(KeyInfo {
            site_key: site_key.to_string(),
            jwt_secret,
            secret_hash,
            config,
        }))
    }

    /// Generic HGETALL for non-key hashes (rsw keypair, settings, …).
    pub async fn hgetall(&self, name: &str) -> Result<HashMap<String, String>, StoreError> {
        Ok(self.kv.hgetall(name).await?)
    }

    /// First-use claim for a challenge nonce. `true` = this caller won.
    pub async fn consume_nonce(&self, sig_hex: &str, ttl_ms: i64) -> Result<bool, StoreError> {
        Ok(self
            .kv
            .set_nx_ex(&format!("blocklist:{sig_hex}"), "1", ttl_ms_to_secs(ttl_ms))
            .await?)
    }

    /// Persist bind → token → verified in one atomic write. Any failure is an
    /// error so the caller can fail closed (no half-issued token).
    pub async fn issue(
        &self,
        token: &str,
        bind_json: &str,
        expires_ms: i64,
        ttl_ms: i64,
    ) -> Result<(), StoreError> {
        let items = vec![
            (format!("bind:{token}"), bind_json.to_string()),
            (format!("token:{token}"), expires_ms.to_string()),
            (format!("verified:{token}"), "1".to_string()),
        ];
        Ok(self.kv.set_many_ex(&items, ttl_ms_to_secs(ttl_ms)).await?)
    }

    pub async fn peek_token(&self, token: &str) -> Result<Option<i64>, StoreError> {
        let raw = self.kv.get(&format!("token:{token}")).await?;
        Ok(raw.and_then(|v| v.parse::<i64>().ok()))
    }

    /// Atomic single-use claim. `true` = this caller consumed the token.
    pub async fn consume_token(&self, token: &str) -> Result<bool, StoreError> {
        Ok(self.kv.del(&format!("token:{token}")).await? > 0)
    }

    /// Raw bind record JSON for a token (parsed by the caller into
    /// `cap_core::SessionBind`).
    pub async fn peek_bind(&self, token: &str) -> Result<Option<String>, StoreError> {
        Ok(self.kv.get(&format!("bind:{token}")).await?)
    }

    pub async fn has_verified(&self, token: &str) -> Result<bool, StoreError> {
        Ok(self.kv.exists(&format!("verified:{token}")).await?)
    }

    pub async fn drop_verified(&self, token: &str) -> Result<(), StoreError> {
        self.kv.del(&format!("verified:{token}")).await?;
        Ok(())
    }

    /// Fixed-window limiter. `true` = allowed.
    pub async fn rate_hit(
        &self,
        scope: &str,
        ip: &str,
        window_ms: i64,
        max: i64,
    ) -> Result<bool, StoreError> {
        if ip.is_empty() {
            return Ok(true); // no client IP → limiter disabled (JS behaviour)
        }
        let window_ms = window_ms.max(1);
        let window_secs = ((window_ms as f64) / 1000.0).ceil() as i64;
        let window = now_ms() / window_ms;
        let key = format!("rl:{scope}:{ip}:{window_ms}:{window}");
        let count = self.kv.incr(&key).await?;
        if count == 1 {
            self.kv.expire(&key, window_secs + 1).await?;
        }
        Ok(count <= max)
    }

    /// `HINCRBY <name> <bucket> 1` for failure metrics.
    pub async fn incr_metric(&self, name: &str, bucket: i64) -> Result<(), StoreError> {
        self.kv.hincrby(name, &bucket.to_string(), 1).await?;
        Ok(())
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn ttl_ms_to_secs(ttl_ms: i64) -> i64 {
    ((ttl_ms.max(1) as f64) / 1000.0).ceil() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_and_camel_case() {
        let cfg: KeyConfig = serde_json::from_str(
            r#"{"challengeCount":10,"difficulty":2,"requireSessionBind":true,"unknown":1}"#,
        )
        .expect("parse");
        assert_eq!(cfg.challenge_count, 10);
        assert_eq!(cfg.difficulty, 2);
        assert!(cfg.require_session_bind);
        assert_eq!(cfg.salt_size, 32);
        assert_eq!(cfg.protocol, "hashwx");
        assert!(cfg.block_on_deny);
        assert!(!cfg.instrumentation);
    }

    #[test]
    fn ttl_rounds_up() {
        assert_eq!(ttl_ms_to_secs(1), 1);
        assert_eq!(ttl_ms_to_secs(1_000), 1);
        assert_eq!(ttl_ms_to_secs(1_001), 2);
        assert_eq!(ttl_ms_to_secs(9_000_000), 9_000);
    }

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
    }

    fn rand_suffix() -> i64 {
        use std::time::*;
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as i64)
            .unwrap_or(0)
    }

    async fn setup() -> Option<(Store, String)> {
        match Store::connect(&redis_url()).await {
            Ok(s) => {
                let suffix = format!("{}_{}", now_ms(), rand_suffix());
                Some((s, suffix))
            }
            Err(e) => {
                eprintln!("[cap-store tests] redis unavailable, skipping: {e}");
                None
            }
        }
    }

    #[tokio::test]
    async fn key_load_and_missing() {
        let Some((store, suffix)) = setup().await else {
            return;
        };
        let site = format!("testsite{suffix}");
        store
            .kv()
            .hset_pairs(
                &format!("key:{site}"),
                &[
                    ("jwtSecret", "sekret".to_string()),
                    ("secretHash", "sha256:abc".to_string()),
                    ("config", r#"{"challengeCount":7,"difficulty":1}"#.to_string()),
                ],
            )
            .await
            .unwrap();

        let k = store.key(&site).await.unwrap().expect("key exists");
        assert_eq!(k.jwt_secret, "sekret");
        assert_eq!(k.config.challenge_count, 7);
        assert!(store
            .key(&format!("nope{suffix}"))
            .await
            .unwrap()
            .is_none());

        let _ = store.kv().del(&format!("key:{site}")).await;
    }

    #[tokio::test]
    async fn nonce_is_single_use() {
        let Some((store, suffix)) = setup().await else {
            return;
        };
        let sig = format!("sig{suffix}");
        assert!(store.consume_nonce(&sig, 60_000).await.unwrap());
        assert!(!store.consume_nonce(&sig, 60_000).await.unwrap());
    }

    #[tokio::test]
    async fn issue_then_consume_token() {
        let Some((store, suffix)) = setup().await else {
            return;
        };
        let token = format!("site1:aaaa:bbbb{suffix}");
        let expires = now_ms() + 60_000;
        store
            .issue(
                &token,
                r#"{"ip":null,"ua":"x","host":null,"ts":1}"#,
                expires,
                60_000,
            )
            .await
            .unwrap();
        assert_eq!(store.peek_token(&token).await.unwrap(), Some(expires));
        assert!(store.has_verified(&token).await.unwrap());
        assert!(store.consume_token(&token).await.unwrap());
        assert!(!store.consume_token(&token).await.unwrap());
        assert_eq!(store.peek_token(&token).await.unwrap(), None);
        store.drop_verified(&token).await.unwrap();
        assert!(!store.has_verified(&token).await.unwrap());
    }

    #[tokio::test]
    async fn rate_limit_window() {
        let Some((store, suffix)) = setup().await else {
            return;
        };
        let ip = format!("10.0.0.{}", suffix.bytes().map(|b| b as u32).sum::<u32>() % 250);
        let scope = format!("test{suffix}");
        for _ in 0..3 {
            assert!(store.rate_hit(&scope, &ip, 5_000, 3).await.unwrap());
        }
        assert!(!store.rate_hit(&scope, &ip, 5_000, 3).await.unwrap());
        // empty ip → limiter disabled
        assert!(store.rate_hit(&scope, "", 5_000, 0).await.unwrap());
    }

    #[tokio::test]
    async fn metrics_increment() {
        let Some((store, suffix)) = setup().await else {
            return;
        };
        let name = format!("metrics:failed:test{suffix}");
        let bucket = now_ms() / 3_600_000;
        store.incr_metric(&name, bucket).await.unwrap();
        store.incr_metric(&name, bucket).await.unwrap();
        let v = store.kv().hget(&name, &bucket.to_string()).await.unwrap();
        assert_eq!(v.as_deref(), Some("2"));
        let _ = store.kv().del(&name).await;
    }
}
