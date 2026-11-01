//! Short-lived in-process caches for configuration reads on the hot path.
//!
//! Every challenge/redeem currently costs an HGETALL for the site key plus
//! several GETs for global settings. Those values change rarely, so a 1 second
//! TTL removes them from the request path while keeping edits visible almost
//! immediately (a rotated or revoked key stops working within a second).
//!
//! Cached entries are negative too: an unknown site key is remembered so a
//! scanner cannot turn misses into Redis load.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use cap_kv::Kv;
use cap_store::{KeyInfo, Store};

const TTL: Duration = Duration::from_millis(1000);

/// Hard cap on cached site keys. Unauthenticated requests can present an
/// unlimited number of bogus site keys; the negative cache must stay bounded.
const MAX_KEYS: usize = 10_000;

type Slot<T> = (Instant, Option<T>);

pub struct ConfigCache {
    keys: RwLock<HashMap<String, Slot<Arc<KeyInfo>>>>,
    settings: RwLock<HashMap<String, Slot<serde_json::Value>>>,
    blocked: RwLock<HashMap<String, Slot<Arc<HashMap<String, String>>>>>,
}

impl Default for ConfigCache {
    fn default() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            settings: RwLock::new(HashMap::new()),
            blocked: RwLock::new(HashMap::new()),
        }
    }
}

impl ConfigCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Site key hash, cached for [`TTL`].
    pub async fn key(&self, store: &Store, site_key: &str) -> Option<Arc<KeyInfo>> {
        if let Some((at, hit)) = self
            .keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(site_key)
        {
            if at.elapsed() < TTL {
                return hit.clone();
            }
        }
        let loaded = match store.key(site_key).await {
            Ok(k) => k.map(Arc::new),
            // A storage error must not be cached as "missing". Do not retry
            // either: under a Redis outage that would double the load.
            Err(_) => return None,
        };
        {
            let mut keys = self.keys.write().unwrap_or_else(|e| e.into_inner());
            // Do not let an attacker grow the map without bound; when full,
            // skip caching (the answer is still returned, just not remembered).
            if keys.len() < MAX_KEYS {
                keys.insert(site_key.to_string(), (Instant::now(), loaded.clone()));
            }
        }
        loaded
    }

    /// Global setting JSON (`settings:*`), cached for [`TTL`]. Missing or
    /// unparsable values are cached as `Value::Null`.
    pub async fn setting(&self, kv: &Kv, name: &str) -> serde_json::Value {
        if let Some((at, hit)) = self
            .settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
        {
            if at.elapsed() < TTL {
                return hit.clone().unwrap_or(serde_json::Value::Null);
            }
        }
        let value = match kv.get(name).await {
            // A read error is NOT "the setting is absent": caching it would
            // silently disable integrity checking for a second. Cache only a
            // real missing/parsed value.
            Ok(raw) => Some(
                raw.and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok()),
            ),
            Err(_) => None,
        };
        if value.is_none() {
            return serde_json::Value::Null;
        }
        self.settings
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name.to_string(), (Instant::now(), value.clone().flatten()));
        value.flatten().unwrap_or(serde_json::Value::Null)
    }

    /// `blocked:<site_key>`, cached for [`TTL`]. A key with thousands of
    /// blocked entries would otherwise cost a full HGETALL plus a parse per
    /// challenge.
    pub async fn blocked(
        &self,
        kv: &Kv,
        site_key: &str,
    ) -> Arc<HashMap<String, String>> {
        if let Some((at, hit)) = self
            .blocked
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(site_key)
        {
            if at.elapsed() < TTL {
                if let Some(v) = hit {
                    return v.clone();
                }
            }
        }
        let loaded = match kv.hgetall(&format!("blocked:{site_key}")).await {
            Ok(fields) => Arc::new(fields),
            // Do not cache an error; fail closed is the caller's decision.
            Err(_) => return Arc::new(HashMap::new()),
        };
        self.blocked
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(site_key.to_string(), (Instant::now(), Some(loaded.clone())));
        loaded
    }

    /// Drop entries older than a few TTLs. Called from a background task so
    /// the map cannot grow with every site key ever requested.
    pub fn sweep(&self) {
        let now = Instant::now();
        let horizon = TTL * 10;
        self.keys
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (at, _)| now.duration_since(*at) < horizon);
        self.settings
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (at, _)| now.duration_since(*at) < horizon);
        self.blocked
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (at, _)| now.duration_since(*at) < horizon);
    }

    /// Drop every cached entry (used after admin writes).
    pub fn clear(&self) {
        self.keys.write().unwrap_or_else(|e| e.into_inner()).clear();
        self.settings
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.blocked
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}
