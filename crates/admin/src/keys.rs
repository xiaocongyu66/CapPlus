//! `/keys` endpoints: create, list, get, update, delete, rotate-secret.
//! Config defaults + validation ranges mirror `server.js` (`keyDefaults` plus
//! the Elysia `t.Object` schemas).

use std::collections::{BTreeMap, HashMap};

use serde_json::{Map, Value, json};

use crate::util;
use crate::{AdminStore, Scope, bad_request, internal, ok, resp};

const DAY: i64 = 86_400;

fn num_value(f: f64) -> Value {
    if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
        Value::Number((f as i64).into())
    } else {
        Value::Number(serde_json::Number::from_f64(f).unwrap_or_else(|| 0.into()))
    }
}

fn defaults_map() -> Map<String, Value> {
    json!({
        "difficulty": 4,
        "challengeCount": 80,
        "saltSize": 32,
        "instrumentation": false,
        "obfuscationLevel": 3,
        "blockAutomatedBrowsers": false,
        "rsw": false,
        "rswT": 75_000,
        "protocol": "hashwx",
        "hashwxDifficulty": 1_000_000,
    })
    .as_object()
    .cloned()
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn check_number(obj: &Map<String, Value>, key: &str, min: f64, max: f64) -> Result<(), String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(()),
        Some(v) => match v.as_f64() {
            Some(n) if n >= min && n <= max => Ok(()),
            _ => Err(format!("{key} must be a number between {min} and {max}")),
        },
    }
}

fn check_bool(obj: &Map<String, Value>, key: &str) -> Result<(), String> {
    match obj.get(key) {
        None | Some(Value::Null) | Some(Value::Bool(_)) => Ok(()),
        Some(_) => Err(format!("{key} must be a boolean")),
    }
}

fn check_string_array(
    obj: &Map<String, Value>,
    key: &str,
    max_items: usize,
    allow_null: bool,
) -> Result<(), String> {
    match obj.get(key) {
        None => Ok(()),
        Some(Value::Null) if allow_null => Ok(()),
        Some(Value::Array(a)) => {
            if a.len() > max_items {
                return Err(format!("{key} may contain at most {max_items} items"));
            }
            if !a.iter().all(|v| v.is_string()) {
                return Err(format!("{key} must be an array of strings"));
            }
            Ok(())
        }
        Some(_) => Err(format!("{key} must be an array")),
    }
}

fn check_extended_probes(obj: &Map<String, Value>) -> Result<(), String> {
    match obj.get("extendedProbes") {
        None | Some(Value::Bool(_)) => Ok(()),
        Some(Value::Array(a)) => {
            if a.len() > 50 {
                return Err("extendedProbes may contain at most 50 items".into());
            }
            if !a.iter().all(|v| v.is_string()) {
                return Err("extendedProbes must be an array of strings".into());
            }
            Ok(())
        }
        Some(_) => Err("extendedProbes must be a boolean or array".into()),
    }
}

fn check_protocol(obj: &Map<String, Value>) -> Result<(), String> {
    match obj.get("protocol") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) if ["sha256-pow", "rsw", "hashwx"].contains(&s.as_str()) => Ok(()),
        Some(_) => Err("protocol must be one of sha256-pow, rsw, hashwx".into()),
    }
}

fn check_name(obj: &Map<String, Value>, max: usize) -> Result<(), String> {
    match obj.get("name") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) if s.chars().count() <= max => Ok(()),
        Some(_) => Err(format!("name must be at most {max} characters")),
    }
}

fn validate_create(obj: &Map<String, Value>) -> Result<(), String> {
    check_name(obj, 200)?;
    check_number(obj, "saltSize", 16.0, 128.0)?;
    check_number(obj, "polymorphism", 0.0, 1.0)?;
    check_number(obj, "autoBlockDenyMs", 0.0, 86_400_000.0)?;
    check_number(obj, "throttleRestrictMs", 0.0, 86_400_000.0)?;
    check_number(obj, "rswT", 10_000.0, 300_000.0)?;
    check_number(obj, "hashwxDifficulty", 50_000.0, 5_000_000.0)?;
    check_number(obj, "ratelimitMax", 1.0, 10_000.0)?;
    check_number(obj, "ratelimitDuration", 1_000.0, 3_600_000.0)?;
    for key in [
        "instrumentation",
        "blockAutomatedBrowsers",
        "requireSessionBind",
        "blockOnDeny",
        "autoBlockOnDeny",
        "throttleOnRestrict",
        "rsw",
    ] {
        check_bool(obj, key)?;
    }
    check_string_array(obj, "corsOrigins", 50, false)?;
    check_extended_probes(obj)?;
    check_protocol(obj)?;
    Ok(())
}

fn validate_update(obj: &Map<String, Value>) -> Result<(), String> {
    check_name(obj, 600)?;
    check_number(obj, "difficulty", 1.0, 8.0)?;
    check_number(obj, "challengeCount", 1.0, 500.0)?;
    check_number(obj, "obfuscationLevel", 1.0, 10.0)?;
    check_number(obj, "saltSize", 16.0, 128.0)?;
    check_number(obj, "polymorphism", 0.0, 1.0)?;
    check_number(obj, "autoBlockDenyMs", 0.0, 86_400_000.0)?;
    check_number(obj, "throttleRestrictMs", 0.0, 86_400_000.0)?;
    check_number(obj, "rswT", 10_000.0, 300_000.0)?;
    check_number(obj, "hashwxDifficulty", 50_000.0, 5_000_000.0)?;
    check_number(obj, "ratelimitMax", 1.0, 10_000.0)?;
    check_number(obj, "ratelimitDuration", 1_000.0, 3_600_000.0)?;
    for key in [
        "instrumentation",
        "blockAutomatedBrowsers",
        "requireSessionBind",
        "blockOnDeny",
        "autoBlockOnDeny",
        "throttleOnRestrict",
        "rsw",
        "blockNonBrowserUA",
    ] {
        check_bool(obj, key)?;
    }
    check_string_array(obj, "corsOrigins", 50, true)?;
    check_string_array(obj, "requiredHeaders", 20, true)?;
    check_extended_probes(obj)?;
    check_protocol(obj)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Config building (create) / merging (update)
// ---------------------------------------------------------------------------

pub(crate) fn build_create_config(body: &Value) -> Result<Value, String> {
    let empty = Map::new();
    let obj = body.as_object().unwrap_or(&empty);
    validate_create(obj)?;

    let mut cfg = defaults_map();

    if let Some(v) = obj.get("instrumentation").filter(|v| v.is_boolean()) {
        cfg.insert("instrumentation".into(), v.clone());
    }
    if let Some(v) = obj.get("saltSize").filter(|v| v.is_number()) {
        cfg.insert("saltSize".into(), v.clone());
    }
    if let Some(v) = obj.get("blockAutomatedBrowsers").filter(|v| v.is_boolean()) {
        cfg.insert("blockAutomatedBrowsers".into(), v.clone());
    }

    cfg.insert(
        "extendedProbes".into(),
        obj.get("extendedProbes")
            .cloned()
            .unwrap_or(Value::Bool(false)),
    );
    cfg.insert(
        "polymorphism".into(),
        match obj.get("polymorphism") {
            Some(v) if v.is_number() => v.clone(),
            _ => json!(0),
        },
    );
    cfg.insert(
        "requireSessionBind".into(),
        Value::Bool(obj.get("requireSessionBind").and_then(|v| v.as_bool()) == Some(true)),
    );
    cfg.insert(
        "blockOnDeny".into(),
        Value::Bool(!matches!(obj.get("blockOnDeny"), Some(Value::Bool(false)))),
    );
    cfg.insert(
        "ratelimitMax".into(),
        number_or_null(obj.get("ratelimitMax")),
    );
    cfg.insert(
        "ratelimitDuration".into(),
        number_or_null(obj.get("ratelimitDuration")),
    );
    cfg.insert(
        "autoBlockOnDeny".into(),
        Value::Bool(obj.get("autoBlockOnDeny").and_then(|v| v.as_bool()) == Some(true)),
    );
    // `Number(x) || null` — a present zero collapses to null.
    cfg.insert(
        "autoBlockDenyMs".into(),
        obj.get("autoBlockDenyMs")
            .and_then(|v| v.as_f64())
            .filter(|n| *n != 0.0)
            .map(num_value)
            .unwrap_or(Value::Null),
    );
    cfg.insert(
        "throttleOnRestrict".into(),
        Value::Bool(obj.get("throttleOnRestrict").and_then(|v| v.as_bool()) == Some(true)),
    );
    cfg.insert(
        "throttleRestrictMs".into(),
        obj.get("throttleRestrictMs")
            .and_then(|v| v.as_f64())
            .filter(|n| *n != 0.0)
            .map(num_value)
            .unwrap_or(Value::Null),
    );

    if let Some(v) = obj.get("rsw").filter(|v| v.is_boolean()) {
        cfg.insert("rsw".into(), v.clone());
    }
    if let Some(v) = obj.get("rswT").filter(|v| v.is_number()) {
        cfg.insert("rswT".into(), v.clone());
    }
    if let Some(v) = obj.get("protocol").filter(|v| v.is_string()) {
        cfg.insert("protocol".into(), v.clone());
    }
    if let Some(v) = obj.get("hashwxDifficulty").filter(|v| v.is_number()) {
        cfg.insert("hashwxDifficulty".into(), v.clone());
    }

    if let Some(arr) = obj.get("corsOrigins").and_then(|v| v.as_array()) {
        if !arr.is_empty() {
            cfg.insert("corsOrigins".into(), Value::Array(arr.clone()));
        }
    }

    Ok(Value::Object(cfg))
}

fn number_or_null(v: Option<&Value>) -> Value {
    match v {
        Some(x) if x.is_number() => x.clone(),
        _ => Value::Null,
    }
}

fn set_present_or_default(
    b: &Map<String, Value>,
    cfg: &mut Map<String, Value>,
    key: &str,
    default: Value,
) {
    if let Some(v) = b.get(key) {
        cfg.insert(key.into(), v.clone());
    } else if !cfg.contains_key(key) {
        cfg.insert(key.into(), default);
    }
}

fn set_tri_bool_true(b: &Map<String, Value>, cfg: &mut Map<String, Value>, key: &str) {
    if let Some(v) = b.get(key) {
        cfg.insert(key.into(), Value::Bool(v.as_bool() == Some(true)));
    } else if !cfg.contains_key(key) {
        cfg.insert(key.into(), Value::Bool(false));
    }
}

pub(crate) fn merge_update_config(existing: &Value, body: &Value) -> Result<Value, String> {
    let empty = Map::new();
    let b = body.as_object().unwrap_or(&empty);
    validate_update(b)?;

    let mut cfg = defaults_map();
    if let Some(ex) = existing.as_object() {
        for (k, v) in ex {
            cfg.insert(k.clone(), v.clone());
        }
    }

    // Scalar overrides that map 1:1 onto the body when present.
    for key in [
        "difficulty",
        "challengeCount",
        "saltSize",
        "instrumentation",
        "obfuscationLevel",
        "blockAutomatedBrowsers",
        "rswT",
        "hashwxDifficulty",
        "rsw",
    ] {
        if let Some(v) = b.get(key) {
            cfg.insert(key.into(), v.clone());
        }
    }

    // name: body.name ?? existing.name (dropped when both absent)
    match b.get("name").cloned().or_else(|| cfg.get("name").cloned()) {
        Some(v) if !v.is_null() => {
            cfg.insert("name".into(), v);
        }
        _ => {
            cfg.remove("name");
        }
    }

    set_present_or_default(b, &mut cfg, "extendedProbes", Value::Bool(false));
    set_tri_bool_true(b, &mut cfg, "requireSessionBind");
    match b.get("blockOnDeny") {
        Some(v) => {
            cfg.insert(
                "blockOnDeny".into(),
                Value::Bool(!matches!(v, Value::Bool(false))),
            );
        }
        None => {
            cfg.entry("blockOnDeny").or_insert(Value::Bool(true));
        }
    }
    set_tri_bool_true(b, &mut cfg, "autoBlockOnDeny");
    set_present_or_default(b, &mut cfg, "autoBlockDenyMs", Value::Null);
    set_tri_bool_true(b, &mut cfg, "throttleOnRestrict");
    set_present_or_default(b, &mut cfg, "throttleRestrictMs", Value::Null);
    set_present_or_default(b, &mut cfg, "polymorphism", json!(0));
    set_present_or_default(b, &mut cfg, "ratelimitMax", Value::Null);
    set_present_or_default(b, &mut cfg, "ratelimitDuration", Value::Null);
    set_present_or_default(b, &mut cfg, "corsOrigins", Value::Null);
    set_present_or_default(b, &mut cfg, "blockNonBrowserUA", Value::Null);
    set_present_or_default(b, &mut cfg, "requiredHeaders", Value::Null);

    if let Some(v) = b.get("protocol") {
        cfg.insert("protocol".into(), v.clone());
    } else if !cfg.contains_key("protocol") {
        let rsw = cfg.get("rsw").and_then(|v| v.as_bool()).unwrap_or(false);
        cfg.insert("protocol".into(), json!(if rsw { "rsw" } else { "hashwx" }));
    }

    Ok(Value::Object(cfg))
}

// ---------------------------------------------------------------------------
// Stats (port of the relevant part of stats.js)
// ---------------------------------------------------------------------------

fn sum_range(h: &HashMap<String, String>, start: i64, end: Option<i64>) -> i64 {
    let mut sum = 0;
    for (k, v) in h {
        if let (Ok(bucket), Ok(count)) = (k.parse::<i64>(), v.parse::<i64>()) {
            if bucket >= start && end.map_or(true, |e| bucket < e) {
                sum += count;
            }
        }
    }
    sum
}

fn aggregate_daily(h: &HashMap<String, String>, start: i64, end: i64) -> BTreeMap<i64, i64> {
    let mut m: BTreeMap<i64, i64> = BTreeMap::new();
    for (k, v) in h {
        if let (Ok(bucket), Ok(count)) = (k.parse::<i64>(), v.parse::<i64>()) {
            if bucket >= start && bucket < end {
                let day_bucket = (bucket / DAY) * DAY;
                *m.entry(day_bucket).or_insert(0) += count;
            }
        }
    }
    m
}

fn empty() -> HashMap<String, String> {
    HashMap::new()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn key_stats(
    duration: &str,
    verified: &HashMap<String, String>,
    failed: &HashMap<String, String>,
    ratelimited: &HashMap<String, String>,
    lat_sum: &HashMap<String, String>,
    lat_count: &HashMap<String, String>,
    now: i64,
) -> Value {
    let (bucket_size, start, end) = match duration {
        "today" => (3600i64, (now / DAY) * DAY, (now / 3600) * 3600 + 3600),
        "yesterday" => {
            let s = (now / DAY) * DAY - DAY;
            (3600, s, s + DAY)
        }
        "last7days" => (DAY, ((now - 7 * DAY) / DAY) * DAY, (now / DAY) * DAY + DAY),
        "last28days" => (DAY, ((now - 28 * DAY) / DAY) * DAY, (now / DAY) * DAY + DAY),
        "last91days" => (DAY, ((now - 91 * DAY) / DAY) * DAY, (now / DAY) * DAY + DAY),
        "alltime" => (DAY, 0, now + DAY),
        _ => (3600, now - DAY, now + 3600),
    };

    let prev = if duration != "alltime" {
        let period = end - start;
        Some((start - period, start))
    } else {
        None
    };

    let mut chart_data: Vec<Value> = Vec::new();
    if bucket_size == DAY {
        let ve_m = aggregate_daily(verified, start, end);
        let fa_m = aggregate_daily(failed, start, end);
        let rl_m = aggregate_daily(ratelimited, start, end);
        let num_days = match duration {
            "last7days" => Some(7),
            "last28days" => Some(28),
            "last91days" => Some(91),
            _ => None,
        };
        if let Some(n) = num_days {
            let current_day_start = (now / DAY) * DAY;
            for i in 0..n {
                let b = current_day_start - (n - 1 - i) * DAY;
                let v = *ve_m.get(&b).unwrap_or(&0);
                let f = *fa_m.get(&b).unwrap_or(&0);
                let r = *rl_m.get(&b).unwrap_or(&0);
                chart_data.push(json!({
                    "bucket": b,
                    "challenges": v + f,
                    "verified": v,
                    "failed": f,
                    "rateLimited": r,
                }));
            }
        } else {
            let mut buckets: std::collections::BTreeSet<i64> = std::collections::BTreeSet::new();
            buckets.extend(ve_m.keys().copied());
            buckets.extend(fa_m.keys().copied());
            buckets.extend(rl_m.keys().copied());
            for b in buckets {
                let v = *ve_m.get(&b).unwrap_or(&0);
                let f = *fa_m.get(&b).unwrap_or(&0);
                let r = *rl_m.get(&b).unwrap_or(&0);
                chart_data.push(json!({
                    "bucket": b,
                    "challenges": v + f,
                    "verified": v,
                    "failed": f,
                    "rateLimited": r,
                }));
            }
        }
    } else {
        let start_hour = start / 3600;
        let end_hour = (end - 1) / 3600;
        let mut h = start_hour;
        while h <= end_hour {
            let b = h * 3600;
            let bs = b.to_string();
            let v: i64 = verified.get(&bs).and_then(|x| x.parse().ok()).unwrap_or(0);
            let f: i64 = failed.get(&bs).and_then(|x| x.parse().ok()).unwrap_or(0);
            let r: i64 = ratelimited
                .get(&bs)
                .and_then(|x| x.parse().ok())
                .unwrap_or(0);
            chart_data.push(json!({
                "bucket": b,
                "challenges": v + f,
                "verified": v,
                "failed": f,
                "rateLimited": r,
            }));
            h += 1;
        }
    }

    let total_verified = sum_range(verified, start, Some(end));
    let total_failed = sum_range(failed, start, Some(end));
    let total_ratelimited = sum_range(ratelimited, start, Some(end));
    let total_lat_sum = sum_range(lat_sum, start, Some(end));
    let total_lat_count = sum_range(lat_count, start, Some(end));
    let avg_latency = if total_lat_count > 0 {
        (total_lat_sum as f64 / total_lat_count as f64).round() as i64
    } else {
        0
    };

    let prev_stats = prev.map(|(ps, pe)| {
        let pv = sum_range(verified, ps, Some(pe));
        let pf = sum_range(failed, ps, Some(pe));
        let pr = sum_range(ratelimited, ps, Some(pe));
        let pls = sum_range(lat_sum, ps, Some(pe));
        let plc = sum_range(lat_count, ps, Some(pe));
        json!({
            "challenges": pv + pf,
            "verified": pv,
            "failed": pf,
            "avgLatency": if plc > 0 { (pls as f64 / plc as f64).round() as i64 } else { 0 },
            "rateLimited": pr,
        })
    });

    json!({
        "stats": {
            "challenges": total_verified + total_failed,
            "verified": total_verified,
            "failed": total_failed,
            "avgLatency": avg_latency,
            "rateLimited": total_ratelimited,
        },
        "prevStats": prev_stats,
        "chartData": {
            "duration": duration,
            "bucketSize": bucket_size,
            "data": chart_data,
        },
    })
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn with_config_or_default(raw: Option<&String>) -> Value {
    match raw {
        Some(s) => serde_json::from_str(s).unwrap_or_else(|_| json!({})),
        None => json!({}),
    }
}

pub(crate) async fn list(store: &AdminStore, scope: &Option<Scope>) -> crate::AdminResponse {
    let mut site_keys = match store.smembers("keys").await {
        Ok(v) => v,
        Err(_) => return internal(),
    };
    if let Some(s) = scope {
        if let Some(allowed) = &s.site_keys {
            site_keys.retain(|k| allowed.contains(k));
        }
    }

    let now = util::now_secs();
    let current_start = now - DAY;
    let previous_start = now - 2 * DAY;

    let mut keys: Vec<(String, Option<String>, Option<String>, i64)> = Vec::new();
    for sk in &site_keys {
        let fields = match store
            .hmget(&format!("key:{sk}"), &["name", "config", "created"])
            .await
        {
            Ok(f) => f,
            Err(_) => return internal(),
        };
        let created = fields
            .get(2)
            .and_then(|v| v.as_deref())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        keys.push((
            sk.clone(),
            fields.first().cloned().flatten(),
            fields.get(1).cloned().flatten(),
            created,
        ));
    }
    keys.sort_by(|a, b| b.3.cmp(&a.3));

    let mut out = Vec::with_capacity(keys.len());
    for (site_key, name, config, created) in keys {
        let metrics = store
            .hgetall(&format!("metrics:verified:{site_key}"))
            .await
            .unwrap_or_else(|_| empty());
        let current = sum_range(&metrics, current_start, None);
        let previous = sum_range(&metrics, previous_start, Some(current_start));

        let mut change = 0.0f64;
        let mut direction = String::new();
        if previous > 0 {
            change = ((current - previous) as f64 / previous as f64) * 100.0;
            direction = if current > previous {
                "up".into()
            } else if current < previous {
                "down".into()
            } else {
                String::new()
            };
        } else if current > 0 {
            change = 100.0;
            direction = "up".into();
        }

        out.push(json!({
            "siteKey": site_key,
            "name": name,
            "created": created,
            "config": with_config_or_default(config.as_ref()),
            "solvesLast24h": current,
            "difference": {
                "value": format!("{change:.2}"),
                "direction": direction,
            },
        }));
    }

    ok(Value::Array(out))
}

/// Stats block for one key, in the shape `GET /keys/:sk` returns
/// (`stats`, `prevStats`, `chartData`). Shared with public share views.
pub(crate) async fn stats_for(
    store: &AdminStore,
    site_key: &str,
    chart_duration: &str,
) -> Result<Value, String> {
    let verified = store
        .hgetall(&format!("metrics:verified:{site_key}"))
        .await
        .unwrap_or_else(|_| empty());
    let failed = store
        .hgetall(&format!("metrics:failed:{site_key}"))
        .await
        .unwrap_or_else(|_| empty());
    let ratelimited = store
        .hgetall(&format!("metrics:ratelimited:{site_key}"))
        .await
        .unwrap_or_else(|_| empty());
    let lat_sum = store
        .hgetall(&format!("metrics:latency_sum:{site_key}"))
        .await
        .unwrap_or_else(|_| empty());
    let lat_count = store
        .hgetall(&format!("metrics:latency_count:{site_key}"))
        .await
        .unwrap_or_else(|_| empty());

    Ok(key_stats(
        chart_duration,
        &verified,
        &failed,
        &ratelimited,
        &lat_sum,
        &lat_count,
        util::now_secs(),
    ))
}

pub(crate) async fn get_with_duration(
    store: &AdminStore,
    site_key: &str,
    chart_duration: &str,
) -> crate::AdminResponse {
    let fields = match store
        .hmget(&format!("key:{site_key}"), &["name", "config", "created"])
        .await
    {
        Ok(f) => f,
        Err(_) => return internal(),
    };
    let name = match fields.first().cloned().flatten() {
        Some(n) if !n.is_empty() => n,
        _ => return ok(json!({ "success": false, "error": "Key not found" })),
    };
    let config = with_config_or_default(fields.get(1).and_then(|v| v.as_ref()));
    let created = fields
        .get(2)
        .and_then(|v| v.as_deref())
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);

    let stats = match stats_for(store, site_key, chart_duration).await {
        Ok(s) => s,
        Err(_) => return internal(),
    };
    let mut obj = stats.as_object().cloned().unwrap_or_default();
    obj.insert(
        "key".into(),
        json!({
            "siteKey": site_key,
            "name": name,
            "created": created,
            "config": config,
        }),
    );
    ok(Value::Object(obj))
}

pub(crate) async fn create(
    store: &AdminStore,
    body: &Value,
) -> crate::AdminResponse {
    let config = match build_create_config(body) {
        Ok(c) => c,
        Err(e) => return bad_request(&e),
    };

    let site_key = util::random_hex(5);
    let secret_key = format!("sk-{}", util::b64_strip(&util::random_bytes(32)));
    let jwt_secret = util::b64url_nopad(&util::random_bytes(32));
    let secret_hash = format!("sha256:{}", util::sha256_hex(&secret_key));

    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| site_key.clone());
    let created = util::now_ms();

    let pairs: [(&str, String); 5] = [
        ("name", name),
        ("secretHash", secret_hash),
        ("jwtSecret", jwt_secret),
        ("config", config.to_string()),
        ("created", created.to_string()),
    ];
    if store
        .hset_pairs(&format!("key:{site_key}"), &pairs)
        .await
        .is_err()
    {
        return internal();
    }
    if store.sadd("keys", &site_key).await.is_err() {
        return internal();
    }

    ok(json!({ "siteKey": site_key, "secretKey": secret_key }))
}

pub(crate) async fn update(
    store: &AdminStore,
    site_key: &str,
    body: &Value,
) -> crate::AdminResponse {
    let config_str = match store.hget(&format!("key:{site_key}"), "config").await {
        Ok(c) => c,
        Err(_) => return internal(),
    };
    let config_str = match config_str {
        Some(c) => c,
        None => return ok(json!({ "success": false, "error": "Key not found" })),
    };

    let existing: Value = serde_json::from_str(&config_str).unwrap_or_else(|_| json!({}));
    let merged = match merge_update_config(&existing, body) {
        Ok(c) => c,
        Err(e) => return bad_request(&e),
    };

    let new_name = merged
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let current_name = match store.hget(&format!("key:{site_key}"), "name").await {
        Ok(n) => n,
        Err(_) => return internal(),
    };

    let mut pairs: Vec<(&str, String)> = Vec::new();
    if let Some(n) = new_name.or(current_name) {
        pairs.push(("name", n));
    }
    pairs.push(("config", merged.to_string()));

    if store
        .hset_pairs(&format!("key:{site_key}"), &pairs)
        .await
        .is_err()
    {
        return internal();
    }

    ok(json!({ "success": true }))
}

pub(crate) async fn delete(store: &AdminStore, site_key: &str) -> crate::AdminResponse {
    let exists = match store.exists(&format!("key:{site_key}")).await {
        Ok(e) => e,
        Err(_) => return internal(),
    };
    if !exists {
        return resp(404, json!({ "success": false, "error": "Key not found" }));
    }

    let keys: Vec<String> = [
        format!("key:{site_key}"),
        format!("metrics:verified:{site_key}"),
        format!("metrics:failed:{site_key}"),
        format!("metrics:ratelimited:{site_key}"),
        format!("metrics:latency_sum:{site_key}"),
        format!("metrics:latency_count:{site_key}"),
        format!("metrics:country:{site_key}"),
        format!("metrics:asn:{site_key}"),
        format!("metrics:platform:{site_key}"),
        format!("metrics:os:{site_key}"),
        format!("blocked:{site_key}"),
    ]
    .to_vec();
    if store.del_many(&keys).await.is_err() {
        return internal();
    }
    if store.srem("keys", site_key).await.is_err() {
        return internal();
    }

    // Clean up share links for this key (mirrors deleteSharesForKey in share.js).
    if let Ok(share_ids) = store.smembers(&format!("shares:{site_key}")).await {
        for id in &share_ids {
            let _ = store.del(&format!("share:{id}")).await;
            let _ = store.srem("shares", id).await;
        }
        let _ = store.del(&format!("shares:{site_key}")).await;
    }

    ok(json!({ "success": true }))
}

pub(crate) async fn rotate_secret(store: &AdminStore, site_key: &str) -> crate::AdminResponse {
    let exists = match store.exists(&format!("key:{site_key}")).await {
        Ok(e) => e,
        Err(_) => return internal(),
    };
    if !exists {
        return ok(json!({ "success": false, "error": "Key not found" }));
    }

    let new_secret = format!("sk-{}", util::b64_strip(&util::random_bytes(32)));
    let secret_hash = format!("sha256:{}", util::sha256_hex(&new_secret));
    if store
        .hset_pairs(&format!("key:{site_key}"), &[("secretHash", secret_hash)])
        .await
        .is_err()
    {
        return internal();
    }

    ok(json!({ "secretKey": new_secret }))
}
