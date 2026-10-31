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

type Slot<T> = (Instant, Option<T>);

pub struct ConfigCache {
    keys: RwLock<HashMap<String, Slot<Arc<KeyInfo>>>>,
    settings: RwLock<HashMap<String, Slot<serde_json::Value>>>,
}

impl Default for ConfigCache {
    fn default() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            settings: RwLock::new(HashMap::new()),
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
            // A storage error must not be cached as "missing"; fall through to
            // an uncached answer.
            Err(_) => return store.key(site_key).await.ok().flatten().map(Arc::new),
        };
        self.keys
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(site_key.to_string(), (Instant::now(), loaded.clone()));
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
        let value = kv
            .get(name)
            .await
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok());
        self.settings
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name.to_string(), (Instant::now(), value.clone()));
        value.unwrap_or(serde_json::Value::Null)
    }

    /// Drop every cached entry (used after admin writes).
    pub fn clear(&self) {
        self.keys.write().unwrap_or_else(|e| e.into_inner()).clear();
        self.settings
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}
