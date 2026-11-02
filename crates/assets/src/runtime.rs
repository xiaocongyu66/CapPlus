//! Background refresher.
//!
//! Mirrors the JS server: refresh once at startup, then every `interval`
//! (default 24h) — or sooner when the versions stored in the Redis key
//! `asset:cache-config` change.
//!
//! The local `WIDGET_VERSION` / `WASM_VERSION` environment values are captured
//! once, when this task is spawned: changing them requires a restart. Only the
//! *remote* version record is re-read, which is what lets an instance pick up a
//! version bump published by another instance.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::fetch::http_fetcher;
use crate::refresh::{refresh_with_config, OPTIONAL_ASSETS};
use crate::{now_ms, AssetCache, AssetConfig};

/// Redis key holding the asset cache config (same key as the JS server).
pub const CACHE_CONFIG_KEY: &str = "asset:cache-config";

/// Default refresh cadence: once a day (the JS server uses the same).
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// How often we re-check Redis for version changes (cheap; also bounds how
/// long a version bump can go unnoticed).
const CONFIG_POLL: Duration = Duration::from_secs(60);

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
struct CacheConfigDoc {
    #[serde(default, rename = "lastUpdate")]
    last_update: u64,
    #[serde(default)]
    versions: VersionPair,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
struct VersionPair {
    #[serde(default)]
    widget: Option<String>,
    #[serde(default)]
    wasm: Option<String>,
}

/// `true` when the versions recorded upstream differ from the configured ones
/// (or none are recorded yet).
fn versions_differ(doc: &CacheConfigDoc, cfg: &AssetConfig) -> bool {
    doc.versions.widget.as_deref() != Some(cfg.widget_version.as_str())
        || doc.versions.wasm.as_deref() != Some(cfg.wasm_version.as_str())
}

/// Spawn a tokio task that keeps the cache fresh.
///
/// Each refresh runs on a blocking thread (via `spawn_blocking`) so the HTTP
/// fetches never block the async runtime. All failures are logged to stderr;
/// the task itself never exits and never panics.
/// `redis_url = None` (SQLite data directory): refresh on the interval only,
/// without the cross-instance version check.
pub fn spawn_refresher(
    cache: Arc<AssetCache>,
    cfg: AssetConfig,
    redis_url: Option<String>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    let interval = if interval.is_zero() {
        DEFAULT_REFRESH_INTERVAL
    } else {
        interval
    };
    tokio::spawn(async move {
        // Start from the cache's own timestamp so a synchronous initial
        // refresh is not immediately repeated by this loop.
        let mut last_refresh_ms: u64 = cache.last_update_ms();
        let mut conn: Option<redis::aio::MultiplexedConnection> = None;
        let mut last_err_log_ms: u64 = 0;

        loop {
            let changed = match &redis_url {
                Some(url) => {
                    if conn.is_none() {
                        conn = connect(url).await;
                    }
                    match conn.as_mut() {
                        Some(c) => match read_remote_config(c).await {
                            Ok(Some(doc)) => versions_differ(&doc, &cfg),
                            Ok(None) => true,
                            Err(err) => {
                                // Drop the connection so the next tick retries;
                                // log at most every 10 minutes.
                                conn = None;
                                let now = now_ms();
                                if now.saturating_sub(last_err_log_ms) >= 600_000 {
                                    eprintln!(
                                        "📦 [asset server] could not read {CACHE_CONFIG_KEY}: {err}"
                                    );
                                    last_err_log_ms = now;
                                }
                                false
                            }
                        },
                        None => false,
                    }
                }
                None => false,
            };
            let due = last_refresh_ms == 0
                || now_ms().saturating_sub(last_refresh_ms) >= interval.as_millis() as u64;

            if due || changed {
                let cache_ref = Arc::clone(&cache);
                let cfg_for_task = cfg.clone();
                let result = tokio::task::spawn_blocking(move || {
                    refresh_with_config(&cache_ref, &cfg_for_task, &http_fetcher)
                })
                .await;

                match result {
                    Ok((updated, errors)) => {
                        for (name, err) in &errors {
                            if OPTIONAL_ASSETS.contains(&name.as_str()) {
                                eprintln!(
                                    "📦 [asset server] optional asset {name} unavailable: {err}"
                                );
                            } else {
                                eprintln!("📦 [asset server] failed to fetch {name}: {err}");
                            }
                        }
                        eprintln!(
                            "📦 [asset server] refreshed {updated} asset(s), {} error(s)",
                            errors.len()
                        );
                        if updated > 0 {
                            last_refresh_ms = now_ms();
                            if conn.is_none()
                                && let Some(url) = &redis_url
                            {
                                conn = connect(url).await;
                            }
                            if let Some(c) = conn.as_mut() {
                                persist_config(c, &cfg).await;
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("📦 [asset server] refresh task failed: {err}");
                    }
                }
            }

            let sleep_for = if redis_url.is_some() {
                interval.min(CONFIG_POLL)
            } else {
                interval
            };
            tokio::time::sleep(sleep_for).await;
        }
    })
}

async fn connect(redis_url: &str) -> Option<redis::aio::MultiplexedConnection> {
    let client = match redis::Client::open(redis_url) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("📦 [asset server] invalid redis url: {err}");
            return None;
        }
    };
    match client.get_multiplexed_async_connection().await {
        Ok(c) => Some(c),
        Err(err) => {
            eprintln!("📦 [asset server] redis connect failed: {err}");
            None
        }
    }
}

async fn read_remote_config(
    conn: &mut redis::aio::MultiplexedConnection,
) -> Result<Option<CacheConfigDoc>, String> {
    let raw: Option<String> = redis::cmd("GET")
        .arg(CACHE_CONFIG_KEY)
        .query_async(conn)
        .await
        .map_err(|e| e.to_string())?;
    match raw {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        // An unparsable value is treated as "unknown versions" -> refresh.
        Some(s) => Ok(Some(serde_json::from_str(&s).unwrap_or_default())),
    }
}

async fn persist_config(
    conn: &mut redis::aio::MultiplexedConnection,
    cfg: &AssetConfig,
) {
    let doc = CacheConfigDoc {
        last_update: now_ms(),
        versions: VersionPair {
            widget: Some(cfg.widget_version.clone()),
            wasm: Some(cfg.wasm_version.clone()),
        },
    };
    let json = match serde_json::to_string(&doc) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("📦 [asset server] could not serialize {CACHE_CONFIG_KEY}: {err}");
            return;
        }
    };
    let result: redis::RedisResult<()> = redis::cmd("SET")
        .arg(CACHE_CONFIG_KEY)
        .arg(json)
        .query_async(conn)
        .await;
    if let Err(err) = result {
        eprintln!("📦 [asset server] could not persist {CACHE_CONFIG_KEY}: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(widget: &str, wasm: &str) -> AssetConfig {
        AssetConfig {
            cache_host: "https://cdn.jsdelivr.net".to_string(),
            widget_version: widget.to_string(),
            wasm_version: wasm.to_string(),
        }
    }

    #[test]
    fn missing_versions_always_differ() {
        let doc = CacheConfigDoc::default();
        assert!(versions_differ(&doc, &cfg("latest", "latest")));
        assert!(versions_differ(&doc, &cfg("1.0.0", "0.0.3")));
    }

    #[test]
    fn matching_versions_do_not_differ() {
        let doc = CacheConfigDoc {
            last_update: 42,
            versions: VersionPair {
                widget: Some("1.0.0".into()),
                wasm: Some("0.0.3".into()),
            },
        };
        assert!(!versions_differ(&doc, &cfg("1.0.0", "0.0.3")));
        assert!(versions_differ(&doc, &cfg("1.0.1", "0.0.3")));
        assert!(versions_differ(&doc, &cfg("1.0.0", "0.0.4")));
    }

    #[test]
    fn config_doc_uses_js_field_names() {
        let doc = CacheConfigDoc {
            last_update: 1700000000000,
            versions: VersionPair {
                widget: Some("1.2.3".into()),
                wasm: Some("0.4.5".into()),
            },
        };
        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"lastUpdate\":1700000000000"));
        assert!(json.contains("\"widget\":\"1.2.3\""));
        assert!(json.contains("\"wasm\":\"0.4.5\""));
        let back: CacheConfigDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(back, doc);
    }

    #[test]
    fn parses_js_shape_without_last_update() {
        let doc: CacheConfigDoc =
            serde_json::from_str(r#"{"versions":{"widget":"a","wasm":"b"}}"#).unwrap();
        assert_eq!(doc.last_update, 0);
        assert_eq!(doc.versions.widget.as_deref(), Some("a"));
    }
}
