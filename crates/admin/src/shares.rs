//! Share links — `POST/GET/DELETE /shares`, public `GET /shares/:id`.
//!
//! Mirrors `standalone/src/share.js`, adapted to the framework-agnostic router:
//! the id itself (16 hex chars) is the public handle, so the public view is
//! `GET /shares/:id` rather than the JS `/share/:token`.

use serde_json::{Value, json};

use crate::util;
use crate::{AdminStore, Scope, bad_request, internal, ok, resp};

/// Stored JSON uses `0` for "no expiry" (like `share.js`), exposed as `null`.
fn expires_value(ms: i64) -> Value {
    if ms > 0 { json!(ms) } else { Value::Null }
}

fn not_found_share() -> crate::AdminResponse {
    resp(
        404,
        json!({ "success": false, "error": "Share link not found or expired" }),
    )
}

fn scope_denied() -> crate::AdminResponse {
    resp(
        403,
        json!({ "success": false, "error": "Forbidden. This API key is not scoped to this site key." }),
    )
}

/// A scoped API key may only act on keys in its scope; a session (None) or a
/// globally-scoped key may act on anything.
fn scope_allows(scope: &Option<Scope>, site_key: &str) -> bool {
    match scope {
        Some(s) => match &s.site_keys {
            Some(keys) => keys.iter().any(|k| k == site_key),
            None => true,
        },
        None => true,
    }
}

async fn sum_hash(store: &AdminStore, key: &str) -> i64 {
    match store.hgetall(key).await {
        Ok(h) => h.values().filter_map(|v| v.parse::<i64>().ok()).sum(),
        Err(_) => 0,
    }
}

fn share_doc(id: &str, site_key: &str, name: &str, created: i64, expires: i64) -> Value {
    json!({
        "id": id,
        "siteKey": site_key,
        "name": name,
        "url": format!("/share#{id}"),
        "created": created,
        "expires": expires_value(expires),
    })
}

/// `POST /shares` `{siteKey, name?, expiresInMs?}` →
/// `{success, id, url, expires}`.
pub(crate) async fn create(
    store: &AdminStore,
    body: &Value,
    scope: &Option<Scope>,
) -> crate::AdminResponse {
    let site_key = match body
        .get("siteKey")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => s.to_string(),
        None => return bad_request("siteKey is required"),
    };

    if !scope_allows(scope, &site_key) {
        return scope_denied();
    }

    match store.exists(&format!("key:{site_key}")).await {
        Ok(true) => {}
        Ok(false) => return resp(404, json!({ "success": false, "error": "Key not found" })),
        Err(_) => return internal(),
    }

    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if name.chars().count() > 64 {
        return bad_request("name must be at most 64 characters");
    }

    let expires_in_ms = match body.get("expiresInMs") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_i64() {
            Some(n) if n >= 0 => Some(n),
            _ => return bad_request("expiresInMs must be a non-negative number"),
        },
    };

    let created = util::now_ms();
    let expires = expires_in_ms.map(|e| created + e).unwrap_or(0);

    let id = loop {
        let candidate = util::random_hex(8); // 16 hex chars
        match store.exists(&format!("share:{candidate}")).await {
            Ok(false) => break candidate,
            Ok(true) => continue,
            Err(_) => return internal(),
        }
    };

    let pairs = [
        ("siteKey", site_key.clone()),
        ("name", name.clone()),
        ("created", created.to_string()),
        ("expires", expires.to_string()),
    ];
    if store
        .hset_pairs(&format!("share:{id}"), &pairs)
        .await
        .is_err()
    {
        return internal();
    }
    if store.sadd("shares", &id).await.is_err() {
        return internal();
    }
    if store
        .sadd(&format!("shares:{site_key}"), &id)
        .await
        .is_err()
    {
        return internal();
    }

    if let Some(ms) = expires_in_ms {
        let secs = ((ms as f64) / 1000.0).ceil() as i64;
        if store.expire(&format!("share:{id}"), secs).await.is_err() {
            return internal();
        }
    }

    ok(json!({
        "success": true,
        "id": id,
        "url": format!("/shares/{id}"),
        "expires": expires_value(expires),
    }))
}

/// `POST /keys/:sk/shares` `{name?, expiresIn?}` — official scheme: a
/// 32-character base64url token is handed out once, and only its SHA-256
/// (whose first 16 hex chars become the id) is stored.
pub(crate) async fn create_for_key(
    store: &AdminStore,
    site_key: &str,
    body: &Value,
) -> crate::AdminResponse {
    match store.exists(&format!("key:{site_key}")).await {
        Ok(true) => {}
        Ok(false) => return resp(404, json!({ "success": false, "error": "Key not found" })),
        Err(_) => return internal(),
    }

    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if name.chars().count() > 64 {
        return bad_request("name must be at most 64 characters");
    }
    let expires_in = match body.get("expiresIn") {
        None | Some(Value::Null) => 0,
        Some(v) => match v.as_i64() {
            Some(n) if (0..=315_360_000).contains(&n) => n,
            _ => return bad_request("expiresIn must be between 0 and 315360000"),
        },
    };

    let (token, token_hash, id) = loop {
        let token = util::b64url_nopad(&util::random_bytes(24));
        let token_hash = util::sha256_hex(&token);
        let id: String = token_hash.chars().take(16).collect();
        match store.exists(&format!("share:{id}")).await {
            Ok(false) => break (token, token_hash, id),
            Ok(true) => continue,
            Err(_) => return internal(),
        }
    };

    let created = util::now_ms();
    let expires = if expires_in > 0 { created + expires_in * 1000 } else { 0 };

    let pairs = [
        ("siteKey", site_key.to_string()),
        ("tokenHash", token_hash),
        ("name", name.clone()),
        ("created", created.to_string()),
        ("expires", expires.to_string()),
    ];
    if store
        .hset_pairs(&format!("share:{id}"), &pairs)
        .await
        .is_err()
    {
        return internal();
    }
    let _ = store.sadd("shares", &id).await;
    if store
        .sadd(&format!("shares:{site_key}"), &id)
        .await
        .is_err()
    {
        return internal();
    }
    if expires_in > 0 {
        let _ = store.expire(&format!("share:{id}"), expires_in).await;
    }

    ok(json!({
        "id": id,
        "token": token,
        "name": name,
        "created": created,
        "expires": expires_value(expires),
    }))
}

/// `GET /keys/:sk/shares` — this key's live share links.
pub(crate) async fn list_for_key(store: &AdminStore, site_key: &str) -> crate::AdminResponse {
    match store.exists(&format!("key:{site_key}")).await {
        Ok(true) => {}
        Ok(false) => return resp(404, json!({ "success": false, "error": "Key not found" })),
        Err(_) => return internal(),
    }

    let ids = store
        .smembers(&format!("shares:{site_key}"))
        .await
        .unwrap_or_default();
    let now = util::now_ms();
    let mut rows: Vec<(i64, Value)> = Vec::new();

    for id in ids {
        let fields = match store.hgetall(&format!("share:{id}")).await {
            Ok(h) => h,
            Err(_) => continue,
        };
        let created = fields
            .get("created")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let expires = fields
            .get("expires")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        if expires > 0 && expires <= now {
            let _ = store.del(&format!("share:{id}")).await;
            let _ = store.srem(&format!("shares:{site_key}"), &id).await;
            let _ = store.srem("shares", &id).await;
            continue;
        }
        let name = fields.get("name").cloned().unwrap_or_default();
        rows.push((
            created,
            json!({
                "id": id,
                "name": name,
                "created": created,
                "expires": expires_value(expires),
            }),
        ));
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0));
    ok(Value::Array(rows.into_iter().map(|(_, v)| v).collect()))
}

/// `DELETE /keys/:sk/shares/:id`.
pub(crate) async fn delete_for_key(
    store: &AdminStore,
    site_key: &str,
    id: &str,
) -> crate::AdminResponse {
    let owner = store
        .hget(&format!("share:{id}"), "siteKey")
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    if owner != site_key {
        return resp(
            404,
            json!({ "success": false, "error": "Share link not found" }),
        );
    }
    let _ = store.del(&format!("share:{id}")).await;
    let _ = store.srem(&format!("shares:{site_key}"), id).await;
    let _ = store.srem("shares", id).await;
    ok(json!({ "success": true }))
}

/// Resolve a public token: `sha256(token)` must match the stored hash and the
/// first 16 hex chars are the record id. Returns the share's site key + name.
async fn resolve_token(store: &AdminStore, token: &str) -> Option<(String, String, String)> {
    let token = token.trim();
    if token.len() != 32 || !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return None;
    }
    let token_hash = util::sha256_hex(token);
    let id: String = token_hash.chars().take(16).collect();
    let fields = store.hgetall(&format!("share:{id}")).await.ok()?;
    let stored = fields.get("tokenHash")?;
    // Constant-time-ish comparison of equal-length hex digests.
    if stored.len() != token_hash.len() {
        return None;
    }
    let diff = stored
        .bytes()
        .zip(token_hash.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return None;
    }
    let expires = fields
        .get("expires")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    if expires > 0 && expires <= util::now_ms() {
        return None;
    }
    let site_key = fields.get("siteKey").filter(|s| !s.is_empty())?.clone();
    if !matches!(store.exists(&format!("key:{site_key}")).await, Ok(true)) {
        return None;
    }
    let name = fields
        .get("name")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Shared stats".to_string());
    Some((site_key, name, id))
}

/// `GET /share/:token` — public share payload (stats + chart).
pub(crate) async fn public_for_token(
    store: &AdminStore,
    token: &str,
    chart_duration: &str,
) -> crate::AdminResponse {
    let Some((site_key, name, _id)) = resolve_token(store, token).await else {
        return resp(
            404,
            json!({ "success": false, "error": "Share link not found or expired" }),
        );
    };
    let stats = crate::keys::stats_for(store, &site_key, chart_duration).await;
    match stats {
        Ok(mut doc) => {
            if let Some(obj) = doc.as_object_mut() {
                obj.insert("name".into(), json!(name));
                obj.remove("key");
            }
            ok(doc)
        }
        Err(_) => internal(),
    }
}

/// `GET /share/:token/geo-stats` — public geo tallies for the shared key.
pub(crate) async fn public_geo_for_token(store: &AdminStore, token: &str) -> crate::AdminResponse {
    match resolve_token(store, token).await {
        Some((site_key, _, _)) => crate::blocked::geo_stats(store, &site_key).await,
        None => resp(
            404,
            json!({ "success": false, "error": "Share link not found or expired" }),
        ),
    }
}

/// `GET /shares/:id` — public; returns the share plus verified/failed totals
/// summed from `metrics:verified:<siteKey>` / `metrics:failed:<siteKey>`.
pub(crate) async fn get_public(store: &AdminStore, id: &str) -> crate::AdminResponse {
    let fields = match store.hgetall(&format!("share:{id}")).await {
        Ok(h) => h,
        Err(_) => return internal(),
    };
    let site_key = match fields.get("siteKey").filter(|s| !s.is_empty()) {
        Some(s) => s.clone(),
        None => return not_found_share(),
    };

    let created = fields
        .get("created")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let expires = fields
        .get("expires")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);

    if expires > 0 && expires <= util::now_ms() {
        let _ = store.del(&format!("share:{id}")).await;
        let _ = store.srem("shares", id).await;
        let _ = store.srem(&format!("shares:{site_key}"), id).await;
        return not_found_share();
    }

    let name = fields
        .get("name")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("Shared stats")
        .to_string();

    let verified = sum_hash(store, &format!("metrics:verified:{site_key}")).await;
    let failed = sum_hash(store, &format!("metrics:failed:{site_key}")).await;

    let mut doc = share_doc(id, &site_key, &name, created, expires);
    if let Some(obj) = doc.as_object_mut() {
        obj.insert("success".into(), Value::Bool(true));
        obj.insert(
            "stats".into(),
            json!({ "verified": verified, "failed": failed }),
        );
    }
    ok(doc)
}

/// `GET /shares` (auth) — list shares, filtered to the key's scope.
pub(crate) async fn list(store: &AdminStore, scope: &Option<Scope>) -> crate::AdminResponse {
    let ids = match store.smembers("shares").await {
        Ok(a) => a,
        Err(_) => return internal(),
    };

    let now = util::now_ms();
    let mut rows: Vec<(i64, Value)> = Vec::new();
    let mut stale: Vec<String> = Vec::new();

    for id in ids {
        let fields = match store.hgetall(&format!("share:{id}")).await {
            Ok(h) => h,
            Err(_) => return internal(),
        };
        let site_key = match fields.get("siteKey").filter(|s| !s.is_empty()) {
            Some(s) => s.clone(),
            None => {
                stale.push(id);
                continue;
            }
        };
        let created = fields
            .get("created")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let expires = fields
            .get("expires")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);

        if expires > 0 && expires <= now {
            stale.push(id);
            continue;
        }
        if !scope_allows(scope, &site_key) {
            continue;
        }

        let name = fields.get("name").cloned().unwrap_or_default();
        rows.push((created, share_doc(&id, &site_key, &name, created, expires)));
    }

    for id in &stale {
        let _ = store.del(&format!("share:{id}")).await;
        let _ = store.srem("shares", id).await;
    }

    rows.sort_by(|a, b| b.0.cmp(&a.0));
    ok(Value::Array(rows.into_iter().map(|(_, v)| v).collect()))
}

/// `DELETE /shares/:id` (auth, scope-checked).
pub(crate) async fn delete(
    store: &AdminStore,
    id: &str,
    scope: &Option<Scope>,
) -> crate::AdminResponse {
    let owner = match store.hget(&format!("share:{id}"), "siteKey").await {
        Ok(Some(o)) if !o.is_empty() => o,
        Ok(_) => {
            return resp(
                404,
                json!({ "success": false, "error": "Share link not found" }),
            );
        }
        Err(_) => return internal(),
    };

    if !scope_allows(scope, &owner) {
        return scope_denied();
    }

    let _ = store.del(&format!("share:{id}")).await;
    let _ = store.srem("shares", id).await;
    let _ = store.srem(&format!("shares:{owner}"), id).await;

    ok(json!({ "success": true }))
}
