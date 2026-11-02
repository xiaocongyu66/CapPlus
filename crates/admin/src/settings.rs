//! Settings, sessions, API keys, integrity baseline, logout and `/about`.

use serde_json::{Value, json};

use crate::util;
use crate::{AdminRequest, AdminResponse, AdminStore, bad_request, header, internal, ok, resp};

const APP_VERSION: &str = "3.1.17";

async fn read_json(store: &AdminStore, key: &str) -> Option<Value> {
    match store.get(key).await {
        Ok(Some(s)) => serde_json::from_str(&s).ok(),
        _ => None,
    }
}

fn body_object(body: &Value) -> serde_json::Map<String, Value> {
    body.as_object().cloned().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// /about
// ---------------------------------------------------------------------------

pub(crate) fn about(demo: bool) -> AdminResponse {
    ok(json!({
        "bun": "rust",
        "ver": APP_VERSION,
        "demo": demo,
        "platform": "rust",
    }))
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

pub(crate) async fn list_sessions(store: &AdminStore) -> AdminResponse {
    let hashes = match store.smembers("sessions").await {
        Ok(h) => h,
        Err(_) => return internal(),
    };

    let mut sessions: Vec<(String, i64, i64)> = Vec::new();
    let mut stale: Vec<String> = Vec::new();

    for hash in hashes {
        match store.get(&format!("session:{hash}")).await {
            Ok(Some(data)) => {
                if let Ok(v) = serde_json::from_str::<Value>(&data) {
                    let created = v.get("created").and_then(|x| x.as_i64()).unwrap_or(0);
                    let expires = v.get("expires").and_then(|x| x.as_i64()).unwrap_or(0);
                    sessions.push((hash, created, expires));
                } else {
                    stale.push(hash);
                }
            }
            _ => stale.push(hash),
        }
    }

    for h in stale {
        let _ = store.srem("sessions", &h).await;
    }

    let out: Vec<Value> = sessions
        .into_iter()
        .map(|(hash, created, expires)| {
            json!({
                "token": util::last_chars(&hash, 14),
                "expires": util::iso_from_ms(expires),
                "created": util::iso_from_ms(created),
            })
        })
        .collect();

    ok(Value::Array(out))
}

pub(crate) async fn logout(
    store: &AdminStore,
    req: &AdminRequest<'_>,
    body: &Value,
) -> AdminResponse {
    let authorization = match header(req.headers, "authorization") {
        Some(a) => a,
        None => return resp(401, json!({ "success": false, "error": "Unauthorized" })),
    };

    let decoded = authorization
        .strip_prefix("Bearer ")
        .map(|t| t.trim())
        .and_then(util::b64_decode)
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let hash = match decoded.and_then(|v| v.get("hash").and_then(|h| h.as_str().map(String::from)))
    {
        Some(h) => h,
        None => return resp(401, json!({ "success": false, "error": "Unauthorized" })),
    };

    let mut session = hash.clone();

    let obj = body_object(body);
    if let Some(code) = obj.get("session").and_then(|v| v.as_str()) {
        if code.chars().count() < 14 {
            return ok(json!({ "success": false, "error": "Session code too short" }));
        }
        let all = match store.smembers("sessions").await {
            Ok(a) => a,
            Err(_) => return internal(),
        };
        let matches: Vec<String> = all.into_iter().filter(|h| h.ends_with(code)).collect();
        match matches.len() {
            0 => {
                return resp(
                    404,
                    json!({ "success": false, "error": "Session not found" }),
                );
            }
            1 => session = matches.into_iter().next().unwrap(),
            _ => {
                return resp(
                    409,
                    json!({ "success": false, "error": "Session code is ambiguous, use a longer code" }),
                );
            }
        }
    }

    // Revocation must not report success while the session still resolves.
    if store.del(&format!("session:{session}")).await.is_err() {
        return internal();
    }
    let _ = store.srem("sessions", &session).await; // index only

    let mut r = ok(json!({ "success": true }));
    // The cookie is HttpOnly, so the dashboard's JS cannot clear it; do it
    // here, and only when the session being revoked is the caller's own.
    if session == hash {
        let https = crate::auth::request_is_https_pub(req.headers);
        let value = crate::auth::cookie_value(&hash);
        let _ = store.del(&crate::auth::cookie_session_key(&value)).await;
        r.headers.push((
            "Set-Cookie".into(),
            crate::auth::auth_cookie(None, None, https),
        ));
    }
    r
}

// ---------------------------------------------------------------------------
// API keys (bot tokens)
// ---------------------------------------------------------------------------

pub(crate) async fn apikeys_list(store: &AdminStore) -> AdminResponse {
    let ids = match store.smembers("apikeys").await {
        Ok(i) => i,
        Err(_) => return internal(),
    };

    let mut rows: Vec<(String, Option<String>, i64, Option<String>, bool)> = Vec::new();
    for id in ids {
        let fields = match store
            .hmget(
                &format!("apikey:{id}"),
                &["name", "created", "siteKeys", "readonly"],
            )
            .await
        {
            Ok(f) => f,
            Err(_) => return internal(),
        };
        let name = fields.first().cloned().flatten();
        let created = fields
            .get(1)
            .and_then(|v| v.as_deref())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let site_keys = fields.get(2).cloned().flatten();
        let readonly = fields.get(3).and_then(|v| v.as_deref()) == Some("true");
        rows.push((id, name, created, site_keys, readonly));
    }
    rows.sort_by(|a, b| b.2.cmp(&a.2));

    let out: Vec<Value> = rows
        .into_iter()
        .map(|(id, name, created, site_keys, readonly)| {
            let parsed_site_keys = match site_keys {
                Some(s) => serde_json::from_str::<Value>(&s).unwrap_or(Value::Null),
                None => Value::Null,
            };
            json!({
                "name": name,
                "id": id,
                "created": util::iso_from_ms(created),
                "siteKeys": parsed_site_keys,
                "readonly": readonly,
            })
        })
        .collect();

    ok(Value::Array(out))
}

pub(crate) async fn apikeys_create(store: &AdminStore, body: &Value) -> AdminResponse {
    let obj = body_object(body);
    let name = match obj.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return bad_request("name is required"),
    };

    // Unique site keys (JS: [...new Set(body.siteKeys || [])]).
    let mut site_keys: Vec<String> = Vec::new();
    if let Some(v) = obj.get("siteKeys") {
        if !v.is_null() {
            let arr = match v.as_array() {
                Some(a) => a,
                None => return bad_request("siteKeys must be an array"),
            };
            for item in arr {
                if let Some(s) = item.as_str() {
                    if !site_keys.iter().any(|k| k == s) {
                        site_keys.push(s.to_string());
                    }
                }
            }
        }
    }

    for sk in &site_keys {
        match store.exists(&format!("key:{sk}")).await {
            Ok(true) => {}
            Ok(false) => return bad_request(&format!("Unknown site key: {sk}")),
            Err(_) => return internal(),
        }
    }

    let id = util::random_hex(16);
    let token = util::b64_strip(&util::random_bytes(32));
    let token_hash = match util::argon2_hash_async(&token).await {
        Ok(h) => h,
        Err(e) => return util::argon2_error_response(e),
    };
    let created = util::now_ms();
    let readonly = obj.get("readonly").and_then(|v| v.as_bool()) == Some(true);

    let mut pairs: Vec<(&str, String)> = vec![
        ("name", name),
        ("tokenHash", token_hash),
        ("created", created.to_string()),
    ];
    // Persist the field whenever the caller supplied it (possibly empty):
    // "absent" means an all-sites key, while an explicit empty list must stay
    // a key with no site access.
    if obj.get("siteKeys").is_some() {
        pairs.push((
            "siteKeys",
            Value::Array(site_keys.iter().cloned().map(Value::String).collect()).to_string(),
        ));
    }
    if readonly {
        pairs.push(("readonly", "true".into()));
    }

    if store
        .hset_pairs(&format!("apikey:{id}"), &pairs)
        .await
        .is_err()
    {
        return internal();
    }
    if store.sadd("apikeys", &id).await.is_err() {
        return internal();
    }

    ok(json!({ "apiKey": format!("{id}_{token}") }))
}

pub(crate) async fn apikeys_delete(store: &AdminStore, id: &str) -> AdminResponse {
    match store.exists(&format!("apikey:{id}")).await {
        Ok(true) => {}
        Ok(false) => {
            return resp(
                404,
                json!({ "success": false, "error": "API key not found" }),
            );
        }
        Err(_) => return internal(),
    }
    if store.del(&format!("apikey:{id}")).await.is_err() {
        return internal();
    }
    let _ = store.srem("apikeys", id).await; // index only
    ok(json!({ "success": true }))
}

// ---------------------------------------------------------------------------
// Settings: headers / ratelimit / cors / filtering
// ---------------------------------------------------------------------------

pub(crate) async fn get_headers(store: &AdminStore) -> AdminResponse {
    match read_json(store, "settings:headers").await {
        Some(v) if v.is_object() => ok(v),
        _ => ok(json!({ "ipHeader": "", "countryHeader": "", "asnHeader": "" })),
    }
}

pub(crate) async fn put_headers(store: &AdminStore, body: &Value) -> AdminResponse {
    let obj = body_object(body);
    let get = |k: &str| {
        obj.get(k)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default()
    };
    let new_settings = json!({
        "ipHeader": get("ipHeader"),
        "countryHeader": get("countryHeader"),
        "asnHeader": get("asnHeader"),
    });
    if store
        .set("settings:headers", &new_settings.to_string())
        .await
        .is_err()
    {
        return internal();
    }
    ok(json!({ "success": true }))
}

pub(crate) async fn get_ratelimit(store: &AdminStore) -> AdminResponse {
    match read_json(store, "settings:ratelimit").await {
        Some(v) if v.is_object() => ok(v),
        _ => ok(json!({ "max": 30, "duration": 5000 })),
    }
}

fn parse_ratelimit(body: &Value) -> Result<Value, &'static str> {
    let obj = body.as_object().ok_or("settings must be an object")?;

    if let Some(v) = obj.get("max").filter(|v| !v.is_null()) {
        match v.as_i64() {
            Some(n) if (1..=10_000).contains(&n) => {}
            _ => return Err("max must be an integer between 1 and 10000"),
        }
    }
    if let Some(v) = obj.get("duration").filter(|v| !v.is_null()) {
        match v.as_i64() {
            Some(n) if (1_000..=3_600_000).contains(&n) => {}
            _ => return Err("duration must be an integer between 1000 and 3600000"),
        }
    }

    let max = obj.get("max").cloned().unwrap_or_else(|| json!(30));
    let duration = obj.get("duration").cloned().unwrap_or_else(|| json!(5000));
    Ok(json!({ "max": max, "duration": duration }))
}

pub(crate) async fn put_ratelimit(store: &AdminStore, body: &Value) -> AdminResponse {
    let new_settings = match parse_ratelimit(body) {
        Ok(value) => value,
        Err(reason) => return bad_request(reason),
    };
    if store
        .set("settings:ratelimit", &new_settings.to_string())
        .await
        .is_err()
    {
        return internal();
    }
    ok(json!({ "success": true }))
}

pub(crate) async fn get_cors(store: &AdminStore) -> AdminResponse {
    match read_json(store, "settings:cors").await {
        Some(v) if v.is_object() => ok(v),
        _ => ok(json!({ "origins": null })),
    }
}

pub(crate) async fn put_cors(store: &AdminStore, body: &Value) -> AdminResponse {
    let obj = body_object(body);
    let origins = match obj.get("origins") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::Array(a)) if a.iter().all(|v| v.is_string()) => Value::Array(a.clone()),
        Some(_) => return bad_request("origins must be an array of strings or null"),
    };
    let new_settings = json!({ "origins": origins });
    if store
        .set("settings:cors", &new_settings.to_string())
        .await
        .is_err()
    {
        return internal();
    }
    ok(json!({ "success": true }))
}

pub(crate) async fn get_filtering(store: &AdminStore) -> AdminResponse {
    match read_json(store, "settings:filtering").await {
        Some(v) if v.is_object() => ok(v),
        _ => ok(json!({ "blockNonBrowserUA": false, "requiredHeaders": [] })),
    }
}

fn parse_filtering(body: &Value) -> Result<Value, &'static str> {
    let obj = body.as_object().ok_or("settings must be an object")?;
    let block = match obj.get("blockNonBrowserUA") {
        None | Some(Value::Null) => false,
        Some(v) => v.as_bool().ok_or("blockNonBrowserUA must be a boolean")?,
    };
    let required_headers = match obj.get("requiredHeaders") {
        None | Some(Value::Null) => json!([]),
        Some(Value::Array(a)) if a.iter().all(|v| v.is_string()) => Value::Array(a.clone()),
        Some(_) => return Err("requiredHeaders must be an array of strings"),
    };
    Ok(json!({
        "blockNonBrowserUA": block,
        "requiredHeaders": required_headers,
    }))
}

pub(crate) async fn put_filtering(store: &AdminStore, body: &Value) -> AdminResponse {
    let new_settings = match parse_filtering(body) {
        Ok(value) => value,
        Err(reason) => return bad_request(reason),
    };
    if store
        .set("settings:filtering", &new_settings.to_string())
        .await
        .is_err()
    {
        return internal();
    }
    ok(json!({ "success": true }))
}

// ---------------------------------------------------------------------------
// Integrity baseline
// ---------------------------------------------------------------------------

fn baseline_from_settings(obj: &Value) -> Value {
    json!({
        "widget": util::norm_hash(obj.get("widget").unwrap_or(&Value::Null)),
        "capWasm": util::norm_hash(obj.get("capWasm").unwrap_or(&Value::Null)),
        "hashwxWasm": util::norm_hash(obj.get("hashwxWasm").unwrap_or(&Value::Null)),
        "source": "settings",
        "versions": { "widget": "latest", "wasm": "latest" },
    })
}

async fn current_baseline(store: &AdminStore) -> Value {
    match read_json(store, "settings:integrity").await {
        Some(v) if v.is_object() => {
            let b = baseline_from_settings(&v);
            let any = ["widget", "capWasm", "hashwxWasm"]
                .iter()
                .any(|k| b.get(*k).map(|x| !x.is_null()).unwrap_or(false));
            if any { b } else { Value::Null }
        }
        _ => Value::Null,
    }
}

pub(crate) async fn integrity_get(store: &AdminStore) -> AdminResponse {
    ok(json!({ "success": true, "baseline": current_baseline(store).await }))
}

pub(crate) async fn integrity_post(store: &AdminStore, body: &Value) -> AdminResponse {
    if !body.is_object() {
        return resp(400, json!({ "success": false, "error": "Invalid body" }));
    }

    if body.get("refetch") == Some(&Value::Bool(true)) {
        return ok(json!({
            "success": true,
            "baseline": current_baseline(store).await,
            "refetch": "unsupported_in_rust_port",
        }));
    }

    let has_hash = ["widget", "capWasm", "hashwxWasm"].iter().any(|k| {
        body.get(*k)
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    });
    if !has_hash {
        return resp(
            400,
            json!({
                "success": false,
                "error": "Provide at least one sha256 hash, or { refetch: true }",
            }),
        );
    }

    let base = json!({
        "widget": util::norm_hash(body.get("widget").unwrap_or(&Value::Null)),
        "capWasm": util::norm_hash(body.get("capWasm").unwrap_or(&Value::Null)),
        "hashwxWasm": util::norm_hash(body.get("hashwxWasm").unwrap_or(&Value::Null)),
    });
    if store
        .set("settings:integrity", &base.to_string())
        .await
        .is_err()
    {
        return internal();
    }

    let baseline = json!({
        "widget": base.get("widget").cloned().unwrap_or(Value::Null),
        "capWasm": base.get("capWasm").cloned().unwrap_or(Value::Null),
        "hashwxWasm": base.get("hashwxWasm").cloned().unwrap_or(Value::Null),
        "source": "settings",
        "versions": { "widget": "latest", "wasm": "latest" },
    });
    ok(json!({ "success": true, "baseline": baseline }))
}

#[cfg(test)]
mod security_settings_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires a dedicated isolated CAP_TEST_REDIS_URL"]
    async fn security_settings_write_status_and_persistence() {
        let store = AdminStore::connect(&std::env::var("CAP_TEST_REDIS_URL").unwrap()).await.unwrap();
        for bad in [json!(null), json!({"max": 30.0}), json!({"duration": "5000"}), json!({"max": 0})] {
            assert_eq!(put_ratelimit(&store, &bad).await.status, 400);
        }
        for bad in [json!(null), json!({"blockNonBrowserUA": "false"}), json!({"requiredHeaders": ["accept", 1]})] {
            assert_eq!(put_filtering(&store, &bad).await.status, 400);
        }
        let rl = json!({"max": 30, "duration": 5000});
        assert_eq!(put_ratelimit(&store, &rl).await.status, 200);
        assert_eq!(read_json(&store, "settings:ratelimit").await.unwrap(), rl);
        let filtering = json!({"blockNonBrowserUA": true, "requiredHeaders": ["accept-language"]});
        assert_eq!(put_filtering(&store, &filtering).await.status, 200);
        assert_eq!(read_json(&store, "settings:filtering").await.unwrap(), filtering);
        assert_eq!(put_filtering(&store, &json!({"blockNonBrowserUA": null})).await.status, 200);
        assert_eq!(read_json(&store, "settings:filtering").await.unwrap(),
            json!({"blockNonBrowserUA": false, "requiredHeaders": []}));
    }

    #[test]
    fn filtering_write_contract() {
        for value in [json!(null), json!([]), json!({"blockNonBrowserUA": "false"}),
            json!({"blockNonBrowserUA": 1}),
            json!({"requiredHeaders": ["accept", 1]}), json!({"requiredHeaders": false})] {
            assert!(parse_filtering(&value).is_err(), "{value}");
        }
        for value in [json!({}), json!({"requiredHeaders": null}), json!({"blockNonBrowserUA": null})] {
            assert_eq!(parse_filtering(&value).unwrap(), json!({"blockNonBrowserUA": false, "requiredHeaders": []}));
        }
        let dashboard = json!({"blockNonBrowserUA": true, "requiredHeaders": ["accept-language"]});
        assert_eq!(parse_filtering(&dashboard).unwrap(), dashboard);
    }

    #[test]
    fn ratelimit_write_integer_bounds_and_null() {
        assert_eq!(parse_ratelimit(&json!({})).unwrap(), json!({"max": 30, "duration": 5000}));
        let nulls = json!({"max": null, "duration": null});
        assert_eq!(parse_ratelimit(&nulls).unwrap(), nulls);
        for value in [json!(null), json!([]), json!(true)] { assert!(parse_ratelimit(&value).is_err()); }
        for (field, min, max) in [("max", 1, 10000), ("duration", 1000, 3600000)] {
            for n in [min, max] { assert!(parse_ratelimit(&json!({field: n})).is_ok()); }
            for bad in [json!(min - 1), json!(max + 1), json!(i64::MIN), json!(u64::MAX),
                json!(1.5), json!(5000.0), json!("5000"), json!(false), json!([]), json!({})] {
                assert!(parse_ratelimit(&json!({field: bad})).is_err(), "{field}: {bad}");
            }
        }
    }
}
