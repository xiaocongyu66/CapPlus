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
    /// Fields whose TTL has passed; the caller should drop them from Redis.
    pub expired: Vec<String>,
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
                out.expired.push(field.clone());
                continue;
            }
            if let Some(net) = field.strip_prefix("cidr:") {
                out.cidrs.push(net.to_string());
            } else if let Some(country) = field.strip_prefix("country:") {
                out.countries.insert(country.to_string());
            } else if let Some(asn) = field.strip_prefix("asn:") {
                out.asns.insert(asn.to_string());
            } else {
                out.ips.insert(field.clone());
            }
        }
        out
    }
}

pub struct ConfigCache {
    keys: Cache<String, Option<Arc<KeyInfo>>>,
    settings: Cache<String, serde_json::Value>,
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

    /// Site key hash, cached for [`TTL`].
    pub async fn key(&self, store: &Store, site_key: &str) -> Option<Arc<KeyInfo>> {
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
            .unwrap_or(None)
    }

    /// Global setting JSON (`settings:*`), cached for [`TTL`]. Missing or
    /// unparsable values are cached as `Value::Null`.
    pub async fn setting(&self, kv: &Kv, name: &str) -> serde_json::Value {
        self.settings
            .try_get_with_by_ref(name, async {
                match kv.get(name).await {
                    Ok(raw) => Ok(raw
                        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
                        .unwrap_or(serde_json::Value::Null)),
                    // A read error is NOT "the setting is absent": caching it
                    // would silently disable integrity checking for a second.
                    Err(_) => Err(LoadError),
                }
            })
            .await
            .unwrap_or(serde_json::Value::Null)
    }

    /// `blocked:<site_key>`, cached for [`TTL`] and pre-split by kind. A key
    /// with thousands of blocked entries would otherwise cost a full HGETALL
    /// plus an O(n) scan per challenge.
    pub async fn blocked(&self, kv: &Kv, site_key: &str) -> Arc<BlockList> {
        self.blocked
            .try_get_with_by_ref(site_key, async {
                match kv.hgetall(&format!("blocked:{site_key}")).await {
                    Ok(fields) => Ok(Arc::new(BlockList::from_fields(&fields, crate::now_ms()))),
                    // Do not cache an error; fail closed is the caller's decision.
                    Err(_) => Err(LoadError),
                }
            })
            .await
            .unwrap_or_default()
    }

    /// Drop every cached entry (used after admin writes).
    pub fn clear(&self) {
        self.keys.invalidate_all();
        self.settings.invalidate_all();
        self.blocked.invalidate_all();
    }
}
