//! Blocked-IP management for a site key: `blocked:<siteKey>` hash whose field
//! is the target (`ip`, `cidr:<net>`, `asn:<n>`, `country:<cc>`) and whose
//! value is either `"0"` (permanent) or an epoch-millisecond expiry.
//!
//! Mirrors `standalone/src/server.js` (`/keys/:siteKey/block-ip`,
//! `unblock-ip`, `blocked-ips`).

use serde_json::{Value, json};

use crate::util;
use crate::{AdminStore, bad_request, internal, ok, resp};

fn block_field(kind: &str, value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(match kind {
        "ip" => value.parse::<std::net::IpAddr>().ok()?.to_string(),
        "cidr" => {
            let (address, prefix) = value.split_once('/')?;
            let address = address.parse::<std::net::IpAddr>().ok()?;
            let prefix = prefix.parse::<u32>().ok()?;
            let max = if address.is_ipv4() { 32 } else { 128 };
            if prefix > max {
                return None;
            }
            format!("cidr:{address}/{prefix}")
        },
        // These end up rendered in the admin dashboard, so only the exact
        // shapes are accepted: a dashboard XSS must not be reachable from a
        // site-scoped bot key.
        "asn" => {
            if value.len() > 10 || !value.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            format!("asn:{value}")
        }
        "country" => {
            if value.len() != 2 || !value.bytes().all(|b| b.is_ascii_alphabetic()) {
                return None;
            }
            format!("country:{}", value.to_ascii_uppercase())
        }
        _ => return None,
    })
}

/// `POST /keys/:sk/block-ip` `{type, value|ip, duration?}` — `duration` is in
/// seconds; `0`/absent blocks permanently.
pub(crate) async fn block(store: &AdminStore, site_key: &str, body: &Value) -> crate::AdminResponse {
    let kind = body.get("type").and_then(|v| v.as_str()).unwrap_or("ip");
    let value = body
        .get("value")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("ip").and_then(|v| v.as_str()))
        .unwrap_or("");

    let Some(field) = block_field(kind, value) else {
        return bad_request("Invalid block type or missing value");
    };
    match store.exists(&format!("key:{site_key}")).await {
        Ok(true) => {}
        Ok(false) => return resp(404, json!({ "success": false, "error": "Key not found" })),
        Err(_) => return internal(),
    }

    let duration = body.get("duration").and_then(|v| v.as_i64()).unwrap_or(0);
    let expires = if duration <= 0 {
        "0".to_string()
    } else {
        // Saturate rather than wrap: an overflowing duration means "very
        // long", never "already expired".
        util::now_ms()
            .saturating_add(duration.saturating_mul(1000))
            .to_string()
    };

    match store
        .hset_pairs(&format!("blocked:{site_key}"), &[(field.as_str(), expires)])
        .await
    {
        Ok(()) => ok(json!({ "success": true })),
        Err(_) => internal(),
    }
}

/// `POST /keys/:sk/unblock-ip` `{type, value|ip}`.
pub(crate) async fn unblock(store: &AdminStore, site_key: &str, body: &Value) -> crate::AdminResponse {
    let kind = body.get("type").and_then(|v| v.as_str()).unwrap_or("ip");
    let value = body
        .get("value")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("ip").and_then(|v| v.as_str()))
        .unwrap_or("");

    let Some(field) = block_field(kind, value) else {
        return bad_request("Invalid block type or missing value");
    };
    match store.exists(&format!("key:{site_key}")).await {
        Ok(true) => {}
        Ok(false) => return resp(404, json!({ "success": false, "error": "Key not found" })),
        Err(_) => return internal(),
    }

    match store
        .hdel_fields(&format!("blocked:{site_key}"), &[field.as_str()])
        .await
    {
        Ok(()) => ok(json!({ "success": true })),
        Err(_) => internal(),
    }
}

/// `GET /keys/:sk/blocked-ips` — live entries; expired ones are swept.
pub(crate) async fn list(store: &AdminStore, site_key: &str) -> crate::AdminResponse {
    let raw = match store.hgetall(&format!("blocked:{site_key}")).await {
        Ok(h) => h,
        Err(_) => return internal(),
    };

    let now = util::now_ms();
    let mut out: Vec<Value> = Vec::new();
    let mut stale: Vec<(String, String)> = Vec::new();

    for (field, value) in raw {
        let permanent = value == "0";
        let expires = value.parse::<i64>().unwrap_or(0);
        if !permanent && expires <= now {
            stale.push((field, value));
            continue;
        }
        let (kind, target) = if let Some(rest) = field.strip_prefix("cidr:") {
            ("cidr", rest)
        } else if let Some(rest) = field.strip_prefix("asn:") {
            ("asn", rest)
        } else if let Some(rest) = field.strip_prefix("country:") {
            ("country", rest)
        } else {
            ("ip", field.as_str())
        };
        out.push(json!({
            "ip": target,
            "type": kind,
            "permanent": permanent,
            "expires": if permanent { Value::Null } else { json!(expires) },
        }));
    }

    if !stale.is_empty() {
        let _ = store.hdel_expired_blocks(&format!("blocked:{site_key}"), &stale, now).await;
    }

    ok(Value::Array(out))
}

#[cfg(test)]
mod expiry_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires CAP_TEST_REDIS_URL pointing to an isolated Redis"]
    async fn blocked_admin_expiry_cas() {
        let store = AdminStore::connect(&std::env::var("CAP_TEST_REDIS_URL").expect("explicit isolated Redis required")).await.unwrap();
        let site = format!("test:admin-expiry:{}:{}", std::process::id(), util::now_ms());
        let name = format!("blocked:{site}");
        store.hset_pairs(&name, &[("192.0.2.1", "1".into()), ("192.0.2.2", "1".into())]).await.unwrap();
        let snapshot: Vec<_> = store.hgetall(&name).await.unwrap().into_iter().collect();
        store.hset_pairs(&name, &[("192.0.2.1", "0".into())]).await.unwrap();
        assert_eq!(store.hdel_expired_blocks(&name, &snapshot, util::now_ms()).await.unwrap(), 1);
        let response = list(&store, &site).await;
        assert_eq!(response.status, 200);
        assert_eq!(response.body.as_array().unwrap().len(), 1);
        assert_eq!(store.hget(&name, "192.0.2.1").await.unwrap().as_deref(), Some("0"));
        store.del(&name).await.unwrap();
        store.set(&name, "wrong type").await.unwrap();
        assert_eq!(list(&store, &site).await.status, 500);
        store.del(&name).await.unwrap();
    }
}

/// `GET /keys/:sk/geo-stats` — country / ASN / platform / OS tallies.
pub(crate) async fn geo_stats(store: &AdminStore, site_key: &str) -> crate::AdminResponse {
    let mut groups = Vec::new();
    for (store_key, field, total_key) in [
        ("metrics:country", "countries", "totalCountry"),
        ("metrics:asn", "asns", "totalAsn"),
        ("metrics:platform", "platforms", "totalPlatform"),
        ("metrics:os", "oses", "totalOs"),
    ] {
        let hash = store
            .hgetall(&format!("{store_key}:{site_key}"))
            .await
            .unwrap_or_default();
        let mut entries: Vec<(String, i64)> = hash
            .into_iter()
            .map(|(k, v)| (k, v.parse::<i64>().unwrap_or(0)))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        groups.push((field, total_key, entries));
    }

    let mut doc = serde_json::Map::new();
    for (field, total_key, entries) in groups {
        let total: i64 = entries.iter().map(|(_, c)| c).sum();
        let key = if field == "countries" { "code" } else { "name" };
        let list: Vec<Value> = entries
            .into_iter()
            .map(|(name, count)| json!({ key: name, "count": count }))
            .collect();
        doc.insert(field.to_string(), Value::Array(list));
        doc.insert(total_key.to_string(), json!(total));
    }
    ok(Value::Object(doc))
}
