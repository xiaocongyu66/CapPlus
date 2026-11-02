//! Key-config validation (create/update payloads) and defaults.

use serde_json::{Map, Value, json};

pub(crate) fn normalized_domains(value: Option<&Value>) -> Result<Value, String> {
    let values = value.and_then(Value::as_array)
        .ok_or("corsOrigins is required and must be an array of 1–50 bare domains")?;
    let domains = values.iter().map(|v| v.as_str().map(str::to_owned)
        .ok_or_else(|| "corsOrigins must contain only strings".to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    cap_embed::normalize_domains(&domains).map(|domains| json!(domains))
}

pub(crate) fn num_value(f: f64) -> Value {
    if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
        Value::Number((f as i64).into())
    } else {
        Value::Number(serde_json::Number::from_f64(f).unwrap_or_else(|| 0.into()))
    }
}

pub(crate) fn defaults_map() -> Map<String, Value> {
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

pub(crate) fn check_number(obj: &Map<String, Value>, key: &str, min: f64, max: f64) -> Result<(), String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(()),
        Some(v) => match v.as_f64() {
            Some(n) if n >= min && n <= max => Ok(()),
            _ => Err(format!("{key} must be a number between {min} and {max}")),
        },
    }
}

pub(crate) fn check_bool(obj: &Map<String, Value>, key: &str) -> Result<(), String> {
    match obj.get(key) {
        None | Some(Value::Null) | Some(Value::Bool(_)) => Ok(()),
        Some(_) => Err(format!("{key} must be a boolean")),
    }
}

pub(crate) fn check_string_array(
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
            // Each entry is scanned on every request and can end up inside
            // signed challenge payloads, so bound the individual strings too.
            const MAX_ITEM: usize = 255;
            if a.iter().any(|v| v.as_str().map(str::len).unwrap_or(0) > MAX_ITEM) {
                return Err(format!("{key} entries may be at most {MAX_ITEM} characters"));
            }
            Ok(())
        }
        Some(_) => Err(format!("{key} must be an array")),
    }
}

pub(crate) fn check_extended_probes(obj: &Map<String, Value>) -> Result<(), String> {
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

pub(crate) fn check_protocol(obj: &Map<String, Value>) -> Result<(), String> {
    match obj.get("protocol") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) if ["sha256-pow", "rsw", "hashwx"].contains(&s.as_str()) => Ok(()),
        Some(_) => Err("protocol must be one of sha256-pow, rsw, hashwx".into()),
    }
}

pub(crate) fn check_name(obj: &Map<String, Value>, max: usize) -> Result<(), String> {
    match obj.get("name") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) if s.chars().count() <= max => Ok(()),
        Some(_) => Err(format!("name must be at most {max} characters")),
    }
}

pub(crate) fn validate_create(obj: &Map<String, Value>) -> Result<(), String> {
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
    normalized_domains(obj.get("corsOrigins"))?;
    check_extended_probes(obj)?;
    check_protocol(obj)?;
    Ok(())
}

pub(crate) fn validate_update(obj: &Map<String, Value>) -> Result<(), String> {
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
    if obj.contains_key("corsOrigins") {
        normalized_domains(obj.get("corsOrigins"))?;
    }
    check_string_array(obj, "requiredHeaders", 20, true)?;
    check_extended_probes(obj)?;
    check_protocol(obj)?;
    Ok(())
}

pub(crate) fn number_or_null(v: Option<&Value>) -> Value {
    match v {
        Some(x) if x.is_number() => x.clone(),
        _ => Value::Null,
    }
}

pub(crate) fn set_present_or_default(
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

pub(crate) fn set_tri_bool_true(b: &Map<String, Value>, cfg: &mut Map<String, Value>, key: &str) {
    if let Some(v) = b.get(key) {
        cfg.insert(key.into(), Value::Bool(v.as_bool() == Some(true)));
    } else if !cfg.contains_key(key) {
        cfg.insert(key.into(), Value::Bool(false));
    }
}
