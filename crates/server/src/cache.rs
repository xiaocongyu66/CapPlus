//! Short-lived in-process caches for configuration reads on the hot path.
//!
//! Every challenge/redeem currently costs an HGETALL for the site key plus
//! several GETs for global settings. Those values change rarely, so a 1 second
//! TTL removes them from the request path while keeping edits visible almost
//! immediately (a rotated or revoked key stops working within a second).
//!
//! Cached entries are negative too: an unknown site key is remembered so a
//! scanner cannot turn misses into Redis load. The caches are `moka` caches:
//! concurrent misses on one key share a single load (no stampede when an entry
//! expires), storage errors are never cached, and the size bound uses
//! frequency-based admission so a flood of bogus site keys cannot evict the
//! real ones.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use cap_kv::Kv;
use cap_store::{KeyInfo, Store};
use moka::future::Cache;

const TTL: Duration = Duration::from_millis(1000);

/// Hard cap on cached site keys. Unauthenticated requests can present an
/// unlimited number of bogus site keys; the negative cache must stay bounded.
const MAX_KEYS: u64 = 10_000;
/// Settings are a fixed, small set of names chosen by the server.
const MAX_SETTINGS: u64 = 256;

/// Marker for a failed load; never stored.
#[derive(Debug)]
struct LoadError;

/// A site key's blocklist, split by kind so the request path does O(1)
/// lookups for IPs, countries and ASNs and only scans the (usually tiny) CIDR
/// list. Parsing happens once per TTL rather than once per request.
#[derive(Debug, Default)]
pub struct BlockList {
    pub ips: std::collections::HashSet<String>,
    pub cidrs: Vec<String>,
    pub countries: std::collections::HashSet<String>,
    pub asns: std::collections::HashSet<String>,
    /// Expired field/value snapshots, swept once by the cache loader via CAS.
    pub expired: Vec<(String, String)>,
}

impl BlockList {
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty()
            && self.cidrs.is_empty()
            && self.countries.is_empty()
            && self.asns.is_empty()
    }

    fn from_fields(fields: &HashMap<String, String>, now: i64) -> Self {
        let mut out = BlockList::default();
        for (field, value) in fields {
            let permanent = value == "0";
            let expires = value.parse::<i64>().unwrap_or(0);
            if !permanent && expires <= now {
                out.expired.push((field.clone(), value.clone()));
                continue;
            }
            if let Some(net) = field.strip_prefix("cidr:") {
                out.cidrs.push(net.to_string());
            } else if let Some(country) = field.strip_prefix("country:") {
                out.countries.insert(country.to_string());
            } else if let Some(asn) = field.strip_prefix("asn:") {
                out.asns.insert(asn.to_string());
            } else if let Some(ip) = crate::http_util::canonical_ip(field) {
                out.ips.insert(ip);
            }
        }
        out
    }
}

/// `None` means absent storage; an explicitly stored null is invalid.
fn settings_object(value: Option<&serde_json::Value>) -> Result<Option<&serde_json::Map<String, serde_json::Value>>, &'static str> {
    value.map(|v| v.as_object().ok_or("setting_invalid")).transpose()
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct Filtering {
    pub block_ua: bool,
    pub required_headers: Vec<String>,
}

pub(crate) fn parse_filtering(value: Option<&serde_json::Value>) -> Result<Filtering, &'static str> {
    let Some(obj) = settings_object(value)? else { return Ok(Filtering::default()); };
    let block_ua = match obj.get("blockNonBrowserUA") {
        None | Some(serde_json::Value::Null) => false,
        Some(v) => v.as_bool().ok_or("setting_invalid")?,
    };
    let required_headers = match obj.get("requiredHeaders") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(v) => v.as_array().ok_or("setting_invalid")?.iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or("setting_invalid"))
            .collect::<Result<Vec<_>, _>>()?,
    };
    Ok(Filtering { block_ua, required_headers })
}

/// Persisted limits allow signed i64 values: max <= 0 disables the limiter,
/// and the runtime clamps duration to at least 1 ms. Admin writes stay stricter.
pub(crate) fn parse_ratelimit(value: Option<&serde_json::Value>) -> Result<(i64, i64), &'static str> {
    let obj = settings_object(value)?;
    let integer = |name, default| match obj.and_then(|o| o.get(name)) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => v.as_i64().ok_or("setting_invalid"),
    };
    Ok((integer("max", crate::DEFAULT_RL_MAX)?, integer("duration", crate::DEFAULT_RL_WINDOW_MS)?))
}

pub(crate) fn effective_filtering(value: Option<&serde_json::Value>, cfg: &cap_store::KeyConfig) -> Result<Filtering, &'static str> {
    let mut global = parse_filtering(value)?;
    global.block_ua = cfg.block_non_browser_ua.unwrap_or(global.block_ua);
    if let Some(required) = &cfg.required_headers {
        global.required_headers = required.clone();
    }
    Ok(global)
}

pub(crate) fn effective_ratelimit(value: Option<&serde_json::Value>, cfg: &cap_store::KeyConfig) -> Result<(i64, i64), &'static str> {
    let (max, duration) = parse_ratelimit(value)?;
    Ok((cfg.ratelimit_max.unwrap_or(max), cfg.ratelimit_duration.unwrap_or(duration)))
}

pub struct ConfigCache {
    keys: Cache<String, Option<Arc<KeyInfo>>>,
    settings: Cache<String, Option<serde_json::Value>>,
    blocked: Cache<String, Arc<BlockList>>,
}

impl Default for ConfigCache {
    fn default() -> Self {
        Self {
            keys: Cache::builder()
                .max_capacity(MAX_KEYS)
                .time_to_live(TTL)
                .build(),
            settings: Cache::builder()
                .max_capacity(MAX_SETTINGS)
                .time_to_live(TTL)
                .build(),
            blocked: Cache::builder()
                .max_capacity(MAX_KEYS)
                .time_to_live(TTL)
                .build(),
        }
    }
}

impl ConfigCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bounded single-flight lookup. Only genuine absence is negatively cached;
    /// Redis and persisted-config failures remain errors, without diagnostics.
    pub async fn key_checked(&self, store: &Store, site_key: &str) -> Result<Option<Arc<KeyInfo>>, &'static str> {
        self.keys
            .try_get_with_by_ref(site_key, async {
                match store.key(site_key).await {
                    Ok(k) => Ok(k.map(Arc::new)),
                    // A storage error must not be cached as "missing". Do not
                    // retry either: under a Redis outage that would double
                    // the load.
                    Err(_) => Err(LoadError),
                }
            })
            .await
            .map_err(|_| "store_unavailable")
    }

    /// 非安全用途的兼容读取；安全决策应使用保留错误的 checked 接口。
    pub async fn setting(&self, kv: &Kv, name: &str) -> serde_json::Value {
        self.setting_checked(kv, name).await.unwrap_or(serde_json::Value::Null)
    }

    pub async fn setting_checked(&self, kv: &Kv, name: &str) -> Result<serde_json::Value, &'static str> {
        match self.setting_optional(kv, name).await? {
            None => Ok(serde_json::Value::Null),
            Some(value) if value.is_object() => Ok(value),
            Some(_) => Err("setting_invalid"),
        }
    }

    pub async fn setting_optional(&self, kv: &Kv, name: &str) -> Result<Option<serde_json::Value>, &'static str> {
        self.settings
            .try_get_with_by_ref(name, async {
                match kv.get(name).await {
                    Ok(Some(raw)) => serde_json::from_str::<serde_json::Value>(&raw)
                        .map(Some).map_err(|_| LoadError),
                    Ok(None) => Ok(None),
                    // A read error is NOT "the setting is absent": caching it
                    // would silently disable integrity checking for a second.
                    Err(_) => Err(LoadError),
                }
            })
            .await
            .map_err(|_| "setting_unavailable")
    }

    /// `blocked:<site_key>`, cached for [`TTL`] and pre-split by kind. A key
    /// with thousands of blocked entries would otherwise cost a full HGETALL
    /// plus an O(n) scan per challenge.
    /// `None` means the list could not be read; callers must fail closed
    /// rather than treat an outage as "nothing is blocked".
    pub async fn blocked(&self, kv: &Kv, site_key: &str) -> Option<Arc<BlockList>> {
        self.blocked
            .try_get_with_by_ref(site_key, async {
                match kv.hgetall(&format!("blocked:{site_key}")).await {
                    Ok(fields) => {
                        let now = crate::now_ms();
                        let list = BlockList::from_fields(&fields, now);
                        // Cleanup is opportunistic, once per coalesced load (not
                        // per request). Its failure must not discard live blocks.
                        let _ = kv.hdel_expired_blocks(
                            &format!("blocked:{site_key}"), &list.expired, now,
                        ).await;
                        Ok(Arc::new(list))
                    },
                    Err(_) => Err(LoadError),
                }
            })
            .await
            .ok()
    }

    /// Drop every cached entry (used after admin writes).
    pub fn clear(&self) {
        self.keys.invalidate_all();
        self.settings.invalidate_all();
        self.blocked.invalidate_all();
    }
}

#[cfg(test)]
mod security_settings_tests {
    use super::*;
    use serde_json::{json, Value};

    #[tokio::test]
    #[ignore = "requires a dedicated isolated CAP_TEST_REDIS_URL"]
    async fn blocked_cas_concurrent_cache_misses() {
        let kv = Kv::connect_redis(&std::env::var("CAP_TEST_REDIS_URL").expect("explicit isolated Redis required")).await.unwrap();
        let site = format!("test:blocked:{}", cap_core::random_hex(16));
        let name = format!("blocked:{site}");
        // Explicit invalidation, not wall-clock TTL, controls this interleaving.
        let mut config = ConfigCache::new();
        config.blocked = Cache::builder().max_capacity(MAX_KEYS).build();
        let cache = Arc::new(config);
        kv.hset_pairs(&name, &[("192.0.2.1", "1".into()), ("192.0.2.2", "0".into())]).await.unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(17));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let (cache, kv, site, barrier) = (cache.clone(), kv.clone(), site.clone(), barrier.clone());
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                cache.blocked(&kv, &site).await.unwrap()
            }));
        }
        barrier.wait().await;
        let first = tasks.remove(0).await.unwrap();
        for task in tasks {
            assert!(Arc::ptr_eq(&first, &task.await.unwrap()), "misses must share one load");
        }
        assert!(first.ips.contains("192.0.2.2"));
        assert_eq!(first.expired, vec![("192.0.2.1".into(), "1".into())]);
        assert_eq!(kv.hget(&name, "192.0.2.1").await.unwrap(), None);
        // Recreate the exact expired value: a hot hit must NOT sweep again.
        kv.hset_pairs(&name, &[("192.0.2.1", "1".into())]).await.unwrap();
        assert!(Arc::ptr_eq(&first, &cache.blocked(&kv, &site).await.unwrap()));
        assert_eq!(kv.hget(&name, "192.0.2.1").await.unwrap().as_deref(), Some("1"));
        // Deterministic old cache snapshot -> renewal -> stale cleanup.
        for renewed in ["0".to_string(), (crate::now_ms() + 60_000).to_string()] {
            kv.hset_pairs(&name, &[("192.0.2.1", renewed.clone())]).await.unwrap();
            assert_eq!(kv.hdel_expired_blocks(&name, &first.expired, crate::now_ms()).await.unwrap(), 0);
            assert_eq!(kv.hget(&name, "192.0.2.1").await.unwrap(), Some(renewed));
        }
        kv.del(&name).await.unwrap();
        kv.set(&name, "wrong type").await.unwrap();
        cache.clear();
        assert!(cache.blocked(&kv, &site).await.is_none());
        kv.del(&name).await.unwrap();
        kv.hset_pairs(&name, &[("192.0.2.2", "0".into())]).await.unwrap();
        assert!(cache.blocked(&kv, &site).await.unwrap().ips.contains("192.0.2.2"), "read failures must not be cached");
        kv.del(&name).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a dedicated isolated CAP_TEST_REDIS_URL"]
    async fn security_settings_checked_storage_errors() {
        let kv = Kv::connect_redis(&std::env::var("CAP_TEST_REDIS_URL").unwrap()).await.unwrap();
        let name = format!("test:settings:{}", cap_core::random_hex(16));
        let cache = ConfigCache::new();
        assert_eq!(cache.setting_optional(&kv, &name).await.unwrap(), None);
        for raw in ["null", "[]", "{\"max\":\"30\"}", "{\"duration\":1.5}"] {
            kv.set(&name, raw).await.unwrap();
            cache.clear();
            let value = cache.setting_optional(&kv, &name).await.unwrap();
            assert!(parse_ratelimit(value.as_ref()).is_err());
        }
        kv.set(&name, "not json").await.unwrap();
        cache.clear();
        assert!(cache.setting_optional(&kv, &name).await.is_err());
        kv.del(&name).await.unwrap();
        kv.hset_pairs(&name, &[("wrong", "type".into())]).await.unwrap();
        assert!(cache.setting_optional(&kv, &name).await.is_err());
        kv.del(&name).await.unwrap();
        kv.set(&name, "{}").await.unwrap();
        assert!(parse_ratelimit(cache.setting_optional(&kv, &name).await.unwrap().as_ref()).is_ok());
        kv.del(&name).await.unwrap();
    }

    #[test]
    fn filtering_types_defaults_and_null() {
        assert_eq!(parse_filtering(None).unwrap(), Filtering::default());
        for value in [json!({}), json!({"requiredHeaders": null}), json!({"blockNonBrowserUA": null})] {
            assert_eq!(parse_filtering(Some(&value)).unwrap(), Filtering::default());
        }
        for value in [Value::Null, json!([]), json!({"blockNonBrowserUA": "false"}),
            json!({"blockNonBrowserUA": 0}),
            json!({"requiredHeaders": ["accept", false]}), json!({"requiredHeaders": "accept"})] {
            assert!(parse_filtering(Some(&value)).is_err(), "{value}");
        }
        assert_eq!(parse_filtering(Some(&json!({"blockNonBrowserUA": true, "requiredHeaders": ["accept"]}))).unwrap(),
            Filtering { block_ua: true, required_headers: vec!["accept".into()] });
    }

    #[test]
    fn ratelimit_integer_contract_and_disabled_runtime() {
        let defaults = (crate::DEFAULT_RL_MAX, crate::DEFAULT_RL_WINDOW_MS);
        assert_eq!(parse_ratelimit(None).unwrap(), defaults);
        for value in [json!({}), json!({"max": null, "duration": null})] {
            assert_eq!(parse_ratelimit(Some(&value)).unwrap(), defaults);
        }
        for field in ["max", "duration"] {
            for bad in [json!(true), json!("30"), json!([]), json!({}), json!(30.0), json!(1.5), json!(u64::MAX)] {
                assert!(parse_ratelimit(Some(&json!({field: bad}))).is_err());
            }
            for n in [i64::MIN, -1, 0, 1, i64::MAX] {
                assert!(parse_ratelimit(Some(&json!({field: n}))).is_ok());
            }
        }
        assert!(parse_ratelimit(Some(&Value::Null)).is_err());
        let limiter = crate::ratelimit::LocalLimiter::new();
        for max in [i64::MIN, -1, 0] {
            let (max, duration) = parse_ratelimit(Some(&json!({"max": max, "duration": i64::MIN}))).unwrap();
            for _ in 0..100 { assert!(limiter.hit("disabled", "127.0.0.1", duration, max)); }
        }
        // Nonpositive duration is clamped by the unchanged runtime, not rejected.
        for duration in [i64::MIN, -1, 0, 1] {
            assert!(limiter.hit(&duration.to_string(), "127.0.0.1", duration, 1));
        }
    }

    #[test]
    fn validate_global_before_key_override() {
        let cfg = cap_store::KeyConfig {
            block_non_browser_ua: Some(false), required_headers: Some(vec![]),
            ratelimit_max: Some(0), ratelimit_duration: Some(-1),
            ..Default::default()
        };
        assert!(effective_filtering(Some(&json!({"requiredHeaders": ["accept", 1]})), &cfg).is_err());
        assert!(effective_filtering(Some(&json!({"blockNonBrowserUA": "false"})), &cfg).is_err());
        assert!(effective_ratelimit(Some(&json!({"max": 1.5})), &cfg).is_err());
        assert!(effective_ratelimit(Some(&json!({"duration": "5000"})), &cfg).is_err());
        assert_eq!(effective_filtering(Some(&json!({"blockNonBrowserUA": true, "requiredHeaders": ["accept"]})), &cfg).unwrap(), Filtering::default());
        assert_eq!(effective_ratelimit(Some(&json!({"max": 30, "duration": 5000})), &cfg).unwrap(), (0, -1));
        assert_eq!(effective_ratelimit(None, &cap_store::KeyConfig::default()).unwrap(), (crate::DEFAULT_RL_MAX, crate::DEFAULT_RL_WINDOW_MS));
    }
}
