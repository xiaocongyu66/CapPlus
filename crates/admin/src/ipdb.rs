//! IP database settings — configuration only, no downloader.
//!
//! `settings/ipdb` in `server.js` drives a full .mmdb downloader. This Rust port
//! only persists the provider/credential settings (never echoed back) and
//! reports configuration state; the download endpoint is explicitly
//! unsupported (`unsupported_in_rust_port`).

use serde_json::{Value, json};

use crate::util;
use crate::{AdminStore, bad_request, internal, ok};

const SETTINGS_KEY: &str = "settings:ipdb";
const PROVIDERS: [&str; 5] = ["none", "maxmind", "maxmind_lite", "ipinfo", "dbip"];

async fn read_settings(store: &AdminStore) -> Option<Value> {
    match store.get(SETTINGS_KEY).await {
        Ok(Some(s)) => serde_json::from_str(&s).ok(),
        _ => None,
    }
}

fn nonempty(obj: &serde_json::Map<String, Value>, field: &str) -> bool {
    obj.get(field)
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false)
}

/// `GET /settings/ipdb` — provider + configured state + which secrets are set.
/// Secrets are never echoed; only `*Set` booleans are exposed.
pub(crate) async fn get(store: &AdminStore) -> crate::AdminResponse {
    let stored = read_settings(store).await.unwrap_or(Value::Null);
    let obj = stored.as_object().cloned().unwrap_or_default();

    let provider = obj
        .get("provider")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("none");
    let updated_at = obj.get("updatedAt").and_then(|v| v.as_str()).unwrap_or("");

    // The official dashboard reads `mode`, `country`, `asn`, `loaded`,
    // `lastUpdated`, `error` and `progress`; the older fields stay for API
    // clients that already used this port.
    let mode = if provider == "none" { "" } else { provider };
    ok(json!({
        "success": true,
        "mode": mode,
        "country": { "exists": false },
        "asn": { "exists": false },
        "loaded": { "country": false, "asn": false },
        "lastUpdated": updated_at,
        "error": if mode.is_empty() {
            Value::Null
        } else {
            json!("IP geolocation databases are not available in the Rust port; set IP/country/ASN headers on your proxy instead.")
        },
        "progress": progress_doc(),
        "provider": provider,
        "configured": provider != "none",
        "updatedAt": updated_at,
        "sources": {
            "maxmind": {
                "accountIdSet": nonempty(&obj, "maxmindAccountId"),
                "keySet": nonempty(&obj, "maxmindKey"),
            },
            "ipinfo": {
                "tokenSet": nonempty(&obj, "ipinfoToken"),
            },
        },
    }))
}

/// `PUT /settings/ipdb` `{provider, maxmindAccountId?, maxmindKey?, ipinfoToken?}`
/// → persists `settings:ipdb` JSON. Secrets are stored but never returned.
pub(crate) async fn put(store: &AdminStore, body: &Value) -> crate::AdminResponse {
    let obj = match body.as_object() {
        Some(o) => o,
        None => return bad_request("Invalid body"),
    };

    let provider = match obj.get("provider").and_then(|v| v.as_str()) {
        Some(p) if PROVIDERS.contains(&p) => p.to_string(),
        _ => {
            return bad_request("provider must be one of none, maxmind, maxmind_lite, ipinfo, dbip");
        }
    };

    let mut settings = read_settings(store)
        .await
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    settings.insert("provider".into(), Value::String(provider));

    for field in ["maxmindAccountId", "maxmindKey", "ipinfoToken"] {
        if let Some(v) = obj.get(field) {
            match v {
                Value::String(s) => {
                    settings.insert(field.to_string(), Value::String(s.clone()));
                }
                Value::Null => {
                    settings.insert(field.to_string(), Value::String(String::new()));
                }
                _ => return bad_request(&format!("{field} must be a string")),
            }
        }
    }

    settings.insert(
        "updatedAt".into(),
        Value::String(util::iso_from_ms(util::now_ms())),
    );

    let payload = Value::Object(settings).to_string();
    if store.set(SETTINGS_KEY, &payload).await.is_err() {
        return internal();
    }

    ok(json!({ "success": true }))
}

/// `GET /settings/ipdb/progress` — always idle here; the downloader is absent.
pub(crate) fn progress() -> crate::AdminResponse {
    ok(progress_doc())
}

fn progress_doc() -> Value {
    json!({ "active": false, "file": "", "downloaded": 0, "total": 0, "error": Value::Null })
}

/// `DELETE /settings/ipdb` — clears stored credentials and reports what the
/// dashboard expects back (`success`), like `deleteDB()` in `ipdb.js`.
pub(crate) async fn delete(store: &AdminStore) -> crate::AdminResponse {
    let _ = store.del(SETTINGS_KEY).await;
    ok(json!({ "success": true }))
}

/// `POST /settings/ipdb/download` — the .mmdb downloader is not ported.
pub(crate) fn download() -> crate::AdminResponse {
    ok(json!({
        "success": false,
        "error": "unsupported_in_rust_port",
    }))
}
