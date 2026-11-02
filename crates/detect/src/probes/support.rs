//! Parsing, sanitising and signal-collection helpers for probe vectors.
//!
//! Kept separate from the detection rules in `probes.rs`; everything here is
//! pure and operates on attacker-controlled JSON, so every string/array is
//! bounded before it reaches a regex or a formatted detail.

use super::*;

pub(crate) fn field<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    match v {
        Value::Object(m) => m.get(k),
        _ => None,
    }
}

pub(crate) fn as_obj(v: Option<&Value>) -> Option<&Map<String, Value>> {
    match v {
        Some(Value::Object(m)) => Some(m),
        _ => None,
    }
}

pub(crate) fn as_arr(v: Option<&Value>) -> Option<&Vec<Value>> {
    match v {
        Some(Value::Array(a)) => Some(a),
        _ => None,
    }
}

pub(crate) fn as_str(v: Option<&Value>) -> Option<&str> {
    match v {
        Some(Value::String(s)) => Some(s.as_str()),
        _ => None,
    }
}

pub(crate) fn as_bool(v: Option<&Value>) -> Option<bool> {
    match v {
        Some(Value::Bool(b)) => Some(*b),
        _ => None,
    }
}

/// `isNum`: a finite JSON number.
pub(crate) fn as_num(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64().filter(|x| x.is_finite()),
        _ => None,
    }
}

pub(crate) fn is_true(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(true)))
}

pub(crate) fn is_false(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(false)))
}

/// JS truthiness of a JSON value.
pub(crate) fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|x| x != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// `String(x)` for a JSON value (JS formatting, roughly).
pub(crate) fn js_string(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(a) => a
            .iter()
            .map(|x| match x {
                Value::Null => String::new(),
                other => js_string(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

/// `String(x)` for an optional value (`undefined` when absent).
pub(crate) fn js_string_opt(v: Option<&Value>) -> String {
    match v {
        None => "undefined".to_string(),
        Some(x) => js_string(x),
    }
}

/// `String(x || "")`.
pub(crate) fn or_empty_string(v: Option<&Value>) -> String {
    match v {
        Some(x) if truthy(x) => js_string(x),
        _ => String::new(),
    }
}

/// `Number(x)` approximation (NaN included so comparisons fail like in JS).
pub(crate) fn to_number(v: &Value) -> f64 {
    match v {
        Value::Null => 0.0,
        Value::Bool(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else {
                t.parse::<f64>().unwrap_or(f64::NAN)
            }
        }
        Value::Array(a) => to_number(&Value::String(
            a.iter()
                .map(|x| match x {
                    Value::Null => String::new(),
                    other => js_string(other),
                })
                .collect::<Vec<_>>()
                .join(","),
        )),
        Value::Object(_) => f64::NAN,
    }
}

/// `(x || 0)` as a number.
pub(crate) fn truthy_number(v: Option<&Value>) -> f64 {
    match v {
        Some(x) if truthy(x) => to_number(x),
        _ => 0.0,
    }
}

/// Case-insensitive ASCII substring search (the JS regexes are all plain
/// literals, so this is equivalent to their `/i` behaviour on ASCII text).
pub(crate) fn ci(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let n = needle.as_bytes();
    let h = hay.as_bytes();
    h.len() >= n.len() && h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

pub(crate) fn any_ci(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| ci(hay, n))
}

pub(crate) fn dnum(x: f64) -> String {
    if x.is_finite() && x.fract() == 0.0 && x.abs() < 1e21 {
        format!("{}", x as i64)
    } else {
        format!("{x}")
    }
}

pub(crate) fn clip_str(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        s.chars().take(n).collect()
    } else {
        s.to_string()
    }
}

pub(crate) fn is_mobile_vector(s: &Value) -> bool {
    if is_true(field(s, "uaData").and_then(|u| field(u, "mobile"))) {
        return true;
    }
    any_ci(
        &or_empty_string(field(s, "ua")),
        &[
            "android",
            "iphone",
            "ipad",
            "ipod",
            "iemobile",
            "blackberry",
            "mobile safari",
            "; mobile",
            "silk",
            "kindle",
            "tizen",
            "opera mini",
        ],
    )
}

pub(crate) fn declared_os(s: &Value) -> Option<&'static str> {
    let hay = format!(
        "{} {}",
        or_empty_string(field(s, "ua")),
        or_empty_string(field(s, "platform"))
    );
    if ci(&hay, "android") {
        return Some("android");
    }
    if any_ci(&hay, &["iphone", "ipad", "ipod"]) {
        return Some("ios");
    }
    if any_ci(&hay, &["macintosh", "mac os x", "macintel", "macos"]) {
        return Some("macos");
    }
    if any_ci(&hay, &["windows", "win32", "win64"]) {
        return Some("windows");
    }
    if ci(&hay, "cros") {
        return Some("chromeos");
    }
    if any_ci(&hay, &["linux", "x11", "ubuntu", "fedora"]) {
        return Some("linux");
    }
    None
}

/// `vendorOf` in the WebGPU block.
pub(crate) fn gpu_vendor(s: &str) -> Option<&'static str> {
    if any_ci(s, &["swiftshader", "llvmpipe", "softpipe", "software", "basic render"]) {
        return Some("software");
    }
    if any_ci(s, &["nvidia", "geforce", "quadro", "rtx"]) {
        return Some("nvidia");
    }
    if any_ci(s, &["amd", "radeon"]) {
        return Some("amd");
    }
    if any_ci(s, &["intel", "arc"]) {
        return Some("intel");
    }
    if any_ci(s, &["apple", "metal"]) {
        return Some("apple");
    }
    if any_ci(s, &["qualcomm", "adreno"]) {
        return Some("qualcomm");
    }
    if any_ci(s, &["imagination", "powervr"]) {
        return Some("imagination");
    }
    None
}

/// Software / virtualized rasterizers (`SOFTWARE_GPU`).
pub(crate) fn is_software_gpu(s: &str) -> bool {
    any_ci(
        s,
        &[
            "swiftshader",
            "llvmpipe",
            "softpipe",
            "mesa offscreen",
            "vmware",
            "virtualbox",
            "qemu",
            "parallels",
            "virgl",
            "microsoft basic render",
            "swangle",
            "angle (google, vulkan (swiftshader",
        ],
    )
}

// ---------------------------------------------------------------------------
// sanitizer (JS `sanitizeVector`)
// ---------------------------------------------------------------------------

pub(crate) fn clip_field(obj: &mut Value, key: &str, n: usize) {
    if let Value::Object(m) = obj
        && let Some(Value::String(s)) = m.get_mut(key)
        && s.chars().count() > n
    {
        *s = s.chars().take(n).collect();
    }
}

pub(crate) fn truncate_array(obj: &mut Value, key: &str, n: usize) {
    if let Value::Object(m) = obj
        && let Some(Value::Array(a)) = m.get_mut(key)
    {
        a.truncate(n);
    }
}

pub(crate) fn truncate_nested_array(obj: &mut Value, parent: &str, key: &str, n: usize) {
    if let Value::Object(m) = obj
        && let Some(child) = m.get_mut(parent)
    {
        truncate_array(child, key, n);
    }
}

pub(crate) fn clip_nested(obj: &mut Value, parent: &str, key: &str, n: usize) {
    if let Value::Object(m) = obj
        && let Some(child) = m.get_mut(parent)
        && child.is_object()
    {
        clip_field(child, key, n);
    }
}

pub(crate) fn truncate_plugins(obj: &mut Value) {
    if let Value::Object(m) = obj
        && let Some(Value::Object(p)) = m.get_mut("plugins")
        && p.len() > 64
    {
        let kept: Vec<(String, Value)> = p
            .iter()
            .take(64)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        *p = kept.into_iter().collect();
    }
}

/// Port of `sanitizeVector`: bound every string that later feeds a regex or a
/// detail message, and cap collection sizes. Mutates in place.
pub fn sanitize_vector(v: &mut Value) {
    clip_field(v, "ua", 512);
    clip_field(v, "workerUA", 512);
    clip_field(v, "platform", 64);
    clip_field(v, "oscpu", 64);
    clip_field(v, "productSub", 64);
    truncate_nested_array(v, "uaData", "brands", 16);
    clip_nested(v, "webgl", "renderer", 512);
    clip_nested(v, "webgl", "vendor", 256);
    truncate_array(v, "languages", 32);
    truncate_array(v, "fontWidths", 64);
    truncate_array(v, "automationGlobals", 32);
    truncate_plugins(v);
    if let Value::Object(m) = v
        && let Some(top) = m.get_mut("top")
    {
        truncate_plugins(top);
    }
}

// ---------------------------------------------------------------------------
// completeness / geometry
// ---------------------------------------------------------------------------

pub(super) fn type_ok(v: Option<&Value>, kind: Kind) -> bool {
    match kind {
        Kind::Str => matches!(v, Some(Value::String(_))),
        Kind::Bool => matches!(v, Some(Value::Bool(_))),
        Kind::Object => matches!(v, Some(Value::Object(_))),
        Kind::Array => matches!(v, Some(Value::Array(_))),
        Kind::NullableStr => matches!(v, Some(Value::Null) | Some(Value::String(_))),
        Kind::NullableNumber => matches!(v, Some(Value::Null)) || as_num(v).is_some(),
        Kind::NullableObject => matches!(v, Some(Value::Null) | Some(Value::Object(_))),
        Kind::NullableBool => matches!(v, Some(Value::Null) | Some(Value::Bool(_))),
    }
}

/// Port of `probeCompleteness`: the list of missing / malformed base fields
/// (plus malformed returned optional fields and a wrong `fontWidths` length).
/// OPTIONAL_FIELD_TYPES is the single schema: requesting an API does not
/// require the browser to provide it.
pub fn probe_completeness(
    vector: &Value,
    font_stack_count: Option<usize>,
    optional_fields: &[String],
) -> Vec<String> {
    let obj = match vector {
        Value::Object(m) => m,
        _ => return vec!["probe".to_string()],
    };
    let mut bad: Vec<String> = Vec::new();
    for (name, kind) in PROBE_FIELD_TYPES {
        if !type_ok(obj.get(*name), *kind) {
            bad.push((*name).to_string());
        }
    }
    for name in optional_fields {
        if let Some((_, kind)) = OPTIONAL_FIELD_TYPES.iter().find(|(k, _)| k == name) {
            // Requested browser APIs may be unavailable. Absence is not an
            // observation; a returned value must still have the declared type.
            if obj.contains_key(name.as_str()) && !type_ok(obj.get(name.as_str()), *kind) {
                bad.push(name.clone());
            }
        }
    }
    if let (Some(Value::Array(fw)), Some(count)) = (obj.get("fontWidths"), font_stack_count)
        && fw.len() != count
    {
        bad.push("fontWidths.length".to_string());
    }
    bad
}

/// Result of `geometryStats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeometryStats {
    pub count: usize,
    pub distinct: usize,
    pub n: usize,
}

/// Port of `geometryStats`: whole-pixel width count and distinct values over at
/// most 64 samples; `None` when fewer than six numeric samples exist.
pub fn geometry_stats(font_widths: Option<&Value>) -> Option<GeometryStats> {
    let arr = as_arr(font_widths)?;
    let w: Vec<f64> = arr
        .iter()
        .take(MAX_FONT_WIDTHS)
        .filter_map(|v| as_num(Some(v)))
        .collect();
    if w.len() < 6 {
        return None;
    }
    let mut count = 0usize;
    let mut distinct: Vec<f64> = Vec::new();
    for &x in &w {
        if x.fract() == 0.0 {
            count += 1;
            if !distinct.contains(&x) {
                distinct.push(x);
            }
        }
    }
    Some(GeometryStats {
        count,
        distinct: distinct.len(),
        n: w.len(),
    })
}

// ---------------------------------------------------------------------------
// signals
// ---------------------------------------------------------------------------

pub(crate) fn dep_field(id: &str) -> Option<&'static str> {
    CHECK_DEP_FIELD
        .iter()
        .find(|(k, _)| *k == id)
        .map(|(_, v)| *v)
}

/// Port of `collectSignals`: flatten failed checks into a signal list, dropping
/// failures whose backing optional field was neither requested nor returned.
/// Completeness already distinguishes unavailable APIs from malformed values.
pub fn collect_signals(
    checks: &[Check],
    optional_fields: &[String],
    vector: &Value,
) -> Vec<OwnedSignal> {
    let mut out = Vec::new();
    for c in checks.iter().filter(|c| !c.passed) {
        if let Some(dep) = dep_field(&c.id) {
            let requested = optional_fields.iter().any(|f| f == dep);
            let returned = field(vector, dep).is_some_and(|v| !v.is_null());
            if !requested && !returned {
                continue;
            }
        }
        out.push(OwnedSignal {
            id: c.id.clone(),
            gating: c.gating,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// detector
// ---------------------------------------------------------------------------

/// Copy only supported top-frame supplements, with detector input bounds.
pub fn capture_top(top: &Value) -> Value {
    let mut selected = Map::new();
    if let Some(top) = top.as_object() {
        for key in ALLOW_TOP {
            if let Some(value) = top.get(*key) {
                selected.insert((*key).to_string(), value.clone());
            }
        }
    }
    let mut vector = Value::Object(selected);
    sanitize_vector(&mut vector);
    vector
}

/// Merge allowlisted `top` supplements beneath the signed probe.
pub(crate) fn merge_top(s: &Value) -> Option<Value> {
    let base = match s {
        Value::Object(m) => m,
        _ => return None,
    };
    let top = match base.get("top") {
        Some(Value::Object(t)) => t,
        _ => return None,
    };
    let mut merged = Map::new();
    for k in ALLOW_TOP {
        if let Some(v) = top.get(*k) {
            merged.insert((*k).to_string(), v.clone());
        }
    }
    for (k, v) in base {
        merged.insert(k.clone(), v.clone());
    }
    Some(Value::Object(merged))
}

pub(crate) fn add(checks: &mut Vec<Check>, id: &str, passed: bool, detail: impl Into<String>, gating: bool) {
    checks.push(Check {
        id: id.to_string(),
        passed,
        detail: detail.into(),
        gating,
    });
}
