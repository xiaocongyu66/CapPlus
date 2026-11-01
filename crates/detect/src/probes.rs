//! Server-side automation probe detector — port of `core/src/detect.js`.
//!
//! Input is the (attacker-controlled) client probe object, optionally
//! supplemented with a viewport (`innerWH`, injected by the caller the same way
//! `verifyInstrumentationResult` does) and a `top` object read from the parent
//! document. Output is the ordered list of [`Check`]s, the gating failures
//! (`blocked_by`), the weak findings (`risk_flags`) and the flattened
//! [`OwnedSignal`] list consumed by the trust scorer.
//!
//! The JS reference never throws on hostile input: elements are accessed with
//! `?.`, types are re-checked before use and every loop is bounded. This port
//! keeps that property by working on a sanitized clone (see
//! [`sanitize_vector`]) and by treating "missing" (`undefined`) and `null`
//! distinctly, exactly like the JS does.

use crate::Signal;
use serde::Serialize;
use serde_json::{Map, Value};

/// Number of font stacks the client measures (mirrors `PROBE_FONT_STACK_COUNT`
/// in `core/src/instrumentation.js`).
pub const PROBE_FONT_STACK_COUNT: usize = 17;

const MAX_FONT_WIDTHS: usize = 64;
const MAX_TAMPER_KEYS: usize = 8;
const MAX_TAMPER_KEY_LENGTH: usize = 32;
const MAX_DETAIL_FIELDS: usize = 6;
const OUTER_HEIGHT_SLACK: f64 = 16.0;

/// Options for [`detect_automation`] (the JS `opts` bag).
#[derive(Debug, Clone, Copy)]
pub struct DetectOpts<'a> {
    /// Expected length of `fontWidths` (the challenge's font stack count).
    pub font_stack_count: Option<usize>,
    /// Optional consistency probes the challenge asked for. An empty slice is
    /// equivalent to the JS `undefined`.
    pub optional_fields: &'a [String],
    /// Raw `Accept-Language` request header, when known to the server.
    pub accept_language: Option<&'a str>,
}

impl Default for DetectOpts<'_> {
    fn default() -> Self {
        DetectOpts {
            font_stack_count: None,
            optional_fields: &[],
            accept_language: None,
        }
    }
}

impl<'a> DetectOpts<'a> {
    fn wants(&self, field: &str) -> bool {
        self.optional_fields.iter().any(|f| f == field)
    }
}

/// One detector check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub id: String,
    pub passed: bool,
    pub detail: String,
    /// `true` ⇒ failing this check blocks the client (unless exempted).
    pub gating: bool,
}

/// Owned twin of [`Signal`] (which borrows its id). The detector owns the check
/// ids, so the signal list must own them too. Use [`OwnedSignal::as_signal`] to
/// hand signals to `compute_trust_signals`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnedSignal {
    pub id: String,
    pub gating: bool,
}

impl OwnedSignal {
    /// Borrowed view, as accepted by `compute_trust_signals`.
    pub fn as_signal(&self) -> Signal<'_> {
        Signal {
            id: &self.id,
            gating: self.gating,
        }
    }
}

/// Result of [`detect_automation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectOutcome {
    pub pass: bool,
    pub checks: Vec<Check>,
    pub blocked_by: Vec<String>,
    pub risk_flags: Vec<String>,
    pub signals: Vec<OwnedSignal>,
}

// ---------------------------------------------------------------------------
// field type tables (JS `PROBE_FIELD_TYPES` / `OPTIONAL_FIELD_TYPES`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Str,
    Bool,
    Object,
    Array,
    NullableStr,
    NullableNumber,
    NullableObject,
    NullableBool,
}

/// Fields that are always collected.
const PROBE_FIELD_TYPES: &[(&str, Kind)] = &[
    ("ua", Kind::Str),
    ("productSub", Kind::Str),
    ("oscpu", Kind::Str),
    ("uaDataPresent", Kind::Bool),
    ("uaData", Kind::NullableObject),
    ("plugins", Kind::Object),
    ("engine", Kind::Object),
    ("screen", Kind::Object),
    ("outerWH", Kind::Array),
    ("isExtended", Kind::NullableBool),
    ("fontWidths", Kind::Array),
    ("tamper", Kind::NullableObject),
];

/// Optional consistency fields, only probed when the challenge opts in.
const OPTIONAL_FIELD_TYPES: &[(&str, Kind)] = &[
    ("workerUA", Kind::NullableStr),
    ("webgl", Kind::NullableObject),
    ("canvas", Kind::NullableStr),
    ("audio", Kind::NullableNumber),
    ("emoji", Kind::NullableObject),
    ("platform", Kind::NullableStr),
    ("hardwareConcurrency", Kind::NullableNumber),
    ("storageQuota", Kind::NullableNumber),
    ("cdp", Kind::NullableObject),
    ("active", Kind::NullableObject),
    ("evalShape", Kind::NullableObject),
    ("nativeShape", Kind::NullableObject),
    ("notifPerm", Kind::NullableStr),
    ("mimeCount", Kind::NullableNumber),
    ("languages", Kind::NullableObject),
    ("chromeShape", Kind::NullableObject),
    ("workerInfo", Kind::NullableObject),
    ("canvasStable", Kind::NullableBool),
    ("webgpu", Kind::NullableObject),
];

/// Optional fields whose absence is a transport gap, not a client lie — used by
/// [`collect_signals`] to drop spurious `probe_incomplete` entries.
const OPTIONAL_FIELD_NAMES: &[&str] = &[
    "workerUA",
    "webgl",
    "canvas",
    "audio",
    "emoji",
    "platform",
    "hardwareConcurrency",
    "storageQuota",
];

/// Which optional field backs each consistency check (`CHECK_DEP_FIELD`).
const CHECK_DEP_FIELD: &[(&str, &str)] = &[
    ("cdp_console_trap", "cdp"),
    ("cdp_debugger_pause", "cdp"),
    ("cdp_stack_tamper", "cdp"),
    ("cdp_automation_globals", "cdp"),
    ("cdp_console_object_trap", "cdp"),
    ("cdp_stack_getter", "cdp"),
    ("cdp_proto_getter", "cdp"),
    ("worker_hw_mismatch", "workerInfo"),
    ("worker_mem_mismatch", "workerInfo"),
    ("worker_platform_mismatch", "workerInfo"),
    ("worker_engine_mismatch", "workerInfo"),
    ("notif_perm_mismatch", "active"),
    ("crypto_tampered", "tamper"),
    ("language_header_mismatch", "languages"),
    ("canvas_unstable", "canvasStable"),
    ("webgpu_webgl_mismatch", "webgpu"),
    ("webgpu_absent", "webgpu"),
    ("active_media_api_missing", "active"),
    ("active_no_media_devices", "active"),
    ("active_no_video_codecs", "active"),
    ("active_no_rtc", "active"),
    ("active_permissions_error", "active"),
    ("active_no_fine_pointer", "active"),
    ("worker_ua_mismatch", "workerUA"),
    ("platform_gpu_mismatch", "webgl"),
    ("webgl_software_renderer", "webgl"),
    ("webgl_absent_desktop", "webgl"),
    ("webgl_render_probe", "webgl"),
    ("webgl2_absent_on_chromium", "webgl"),
    ("canvas_degenerate", "canvas"),
    ("audio_silent", "audio"),
    ("emoji_no_render", "emoji"),
    ("emoji_os_mismatch", "emoji"),
    ("hardware_shape", "hardwareConcurrency"),
    ("hw_mem_mismatch", "hardwareConcurrency"),
    ("storage_quota_tiny", "storageQuota"),
];

/// `top` keys the sandboxed iframe genuinely cannot read; only these are merged
/// into the probe (and the signed probe always wins on conflicts).
const ALLOW_TOP: &[&str] = &[
    "automationGlobals",
    "innerWH",
    "webgl",
    "canvas",
    "emoji",
    "audio",
    "storageQuota",
];

// ---------------------------------------------------------------------------
// small JS-semantics helpers
// ---------------------------------------------------------------------------

/// `v[k]` (or `undefined` when `v` is not an object).
fn field<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    match v {
        Value::Object(m) => m.get(k),
        _ => None,
    }
}

fn as_obj(v: Option<&Value>) -> Option<&Map<String, Value>> {
    match v {
        Some(Value::Object(m)) => Some(m),
        _ => None,
    }
}

fn as_arr(v: Option<&Value>) -> Option<&Vec<Value>> {
    match v {
        Some(Value::Array(a)) => Some(a),
        _ => None,
    }
}

fn as_str(v: Option<&Value>) -> Option<&str> {
    match v {
        Some(Value::String(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn as_bool(v: Option<&Value>) -> Option<bool> {
    match v {
        Some(Value::Bool(b)) => Some(*b),
        _ => None,
    }
}

/// `isNum`: a finite JSON number.
fn as_num(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64().filter(|x| x.is_finite()),
        _ => None,
    }
}

fn is_true(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(true)))
}

fn is_false(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(false)))
}

/// JS truthiness of a JSON value.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map_or(false, |x| x != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// `String(x)` for a JSON value (JS formatting, roughly).
fn js_string(v: &Value) -> String {
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
fn js_string_opt(v: Option<&Value>) -> String {
    match v {
        None => "undefined".to_string(),
        Some(x) => js_string(x),
    }
}

/// `String(x || "")`.
fn or_empty_string(v: Option<&Value>) -> String {
    match v {
        Some(x) if truthy(x) => js_string(x),
        _ => String::new(),
    }
}

/// `Number(x)` approximation (NaN included so comparisons fail like in JS).
fn to_number(v: &Value) -> f64 {
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
fn truthy_number(v: Option<&Value>) -> f64 {
    match v {
        Some(x) if truthy(x) => to_number(x),
        _ => 0.0,
    }
}

/// Case-insensitive ASCII substring search (the JS regexes are all plain
/// literals, so this is equivalent to their `/i` behaviour on ASCII text).
fn ci(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let n = needle.as_bytes();
    let h = hay.as_bytes();
    h.len() >= n.len() && h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

fn any_ci(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| ci(hay, n))
}

fn dnum(x: f64) -> String {
    if x.is_finite() && x.fract() == 0.0 && x.abs() < 1e21 {
        format!("{}", x as i64)
    } else {
        format!("{x}")
    }
}

fn clip_str(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        s.chars().take(n).collect()
    } else {
        s.to_string()
    }
}

fn is_mobile_vector(s: &Value) -> bool {
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

fn declared_os(s: &Value) -> Option<&'static str> {
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
fn gpu_vendor(s: &str) -> Option<&'static str> {
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
fn is_software_gpu(s: &str) -> bool {
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

fn clip_field(obj: &mut Value, key: &str, n: usize) {
    if let Value::Object(m) = obj {
        if let Some(Value::String(s)) = m.get_mut(key) {
            if s.chars().count() > n {
                *s = s.chars().take(n).collect();
            }
        }
    }
}

fn truncate_array(obj: &mut Value, key: &str, n: usize) {
    if let Value::Object(m) = obj {
        if let Some(Value::Array(a)) = m.get_mut(key) {
            a.truncate(n);
        }
    }
}

fn truncate_nested_array(obj: &mut Value, parent: &str, key: &str, n: usize) {
    if let Value::Object(m) = obj {
        if let Some(child) = m.get_mut(parent) {
            truncate_array(child, key, n);
        }
    }
}

fn clip_nested(obj: &mut Value, parent: &str, key: &str, n: usize) {
    if let Value::Object(m) = obj {
        if let Some(child) = m.get_mut(parent) {
            if child.is_object() {
                clip_field(child, key, n);
            }
        }
    }
}

fn truncate_plugins(obj: &mut Value) {
    if let Value::Object(m) = obj {
        if let Some(Value::Object(p)) = m.get_mut("plugins") {
            if p.len() > 64 {
                let kept: Vec<(String, Value)> = p
                    .iter()
                    .take(64)
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                *p = kept.into_iter().collect();
            }
        }
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
    if let Value::Object(m) = v {
        if let Some(top) = m.get_mut("top") {
            truncate_plugins(top);
        }
    }
}

// ---------------------------------------------------------------------------
// completeness / geometry
// ---------------------------------------------------------------------------

fn type_ok(v: Option<&Value>, kind: Kind) -> bool {
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
/// (plus requested optional fields and a wrong `fontWidths` length).
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
            if !type_ok(obj.get(name.as_str()), *kind) {
                bad.push(name.clone());
            }
        }
    }
    if let (Some(Value::Array(fw)), Some(count)) = (obj.get("fontWidths"), font_stack_count) {
        if fw.len() != count {
            bad.push("fontWidths.length".to_string());
        }
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

fn dep_field(id: &str) -> Option<&'static str> {
    CHECK_DEP_FIELD
        .iter()
        .find(|(k, _)| *k == id)
        .map(|(_, v)| *v)
}

/// Port of `collectSignals`: flatten failed checks into a signal list, dropping
/// failures whose backing optional field was never returned, and suppressing
/// `probe_incomplete` entries caused only by absent optional probes.
pub fn collect_signals(
    checks: &[Check],
    optional_fields: &[String],
    vector: &Value,
) -> Vec<OwnedSignal> {
    let mut out = Vec::new();
    for c in checks.iter().filter(|c| !c.passed) {
        if let Some(dep) = dep_field(&c.id) {
            let requested = optional_fields.iter().any(|f| f == dep);
            let returned = field(vector, dep).map_or(false, |v| !v.is_null());
            if !requested && !returned {
                continue;
            }
        }
        if c.id == "probe_incomplete" && !c.detail.is_empty() {
            let rest = c
                .detail
                .strip_prefix("missing or malformed:")
                .map(str::trim)
                .unwrap_or(c.detail.as_str());
            let real_missing = rest
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .filter(|f| !OPTIONAL_FIELD_NAMES.contains(f))
                .count();
            if real_missing == 0 {
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

/// Merge allowlisted `top` supplements beneath the signed probe.
fn merge_top(s: &Value) -> Option<Value> {
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

fn add(checks: &mut Vec<Check>, id: &str, passed: bool, detail: impl Into<String>, gating: bool) {
    checks.push(Check {
        id: id.to_string(),
        passed,
        detail: detail.into(),
        gating,
    });
}

/// Port of `detectAutomation`.
pub fn detect_automation(vector: &Value, opts: &DetectOpts<'_>) -> DetectOutcome {
    if !matches!(vector, Value::Object(_) | Value::Array(_)) {
        return DetectOutcome {
            pass: false,
            checks: Vec::new(),
            blocked_by: vec!["probe_missing".to_string()],
            risk_flags: Vec::new(),
            signals: Vec::new(),
        };
    }

    // Only objects carry probes; anything else fails closed without cloning.
    if !vector.is_object() {
        return DetectOutcome {
            pass: false,
            checks: vec![Check {
                id: "probe_incomplete".to_string(),
                passed: false,
                gating: true,
                detail: "probe payload is not an object".to_string(),
            }],
            blocked_by: vec!["probe_incomplete".to_string()],
            risk_flags: Vec::new(),
            signals: Vec::new(),
        };
    }

    // Bound hostile strings/arrays before any regex or detail formatting.
    let mut sanitized = vector.clone();
    sanitize_vector(&mut sanitized);
    let merged = merge_top(&sanitized);
    let s: &Value = merged.as_ref().unwrap_or(&sanitized);

    let mut checks: Vec<Check> = Vec::new();

    let incomplete = probe_completeness(s, opts.font_stack_count, opts.optional_fields);
    add(
        &mut checks,
        "probe_incomplete",
        incomplete.is_empty(),
        if incomplete.is_empty() {
            "all fields present".to_string()
        } else {
            format!(
                "missing or malformed: {}",
                incomplete
                    .iter()
                    .take(MAX_DETAIL_FIELDS)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
        true,
    );

    let gecko = {
        let moz = field(s, "engine").and_then(|e| field(e, "hasMozInnerScreenX"));
        let subs = as_str(field(s, "productSub")) == Some("20100101")
            && is_false(field(s, "uaDataPresent"));
        let oscpu = matches!(field(s, "oscpu"), Some(Value::String(x)) if x != "__undefined");
        is_true(moz) || subs || oscpu
    };
    let chromium =
        is_true(field(s, "uaDataPresent")) || is_true(field(s, "engine").and_then(|e| field(e, "hasChrome")));
    let mobile = is_mobile_vector(s);

    let geo = geometry_stats(field(s, "fontWidths"));
    let quantized = geo.map_or(false, |g| g.count >= 5 && g.distinct >= 3);
    add(
        &mut checks,
        "geometry_quantized",
        !quantized,
        match geo {
            Some(g) => format!("{}/{} whole-px, {} distinct", g.count, g.n, g.distinct),
            None => "not measured".to_string(),
        },
        true,
    );

    add(
        &mut checks,
        "webdriver_true",
        !is_true(field(s, "webdriver")),
        format!("webdriver={}", js_string_opt(field(s, "webdriver"))),
        true,
    );

    let stripped = chromium && field(s, "webdriver").is_none();
    add(
        &mut checks,
        "webdriver_stripped",
        !stripped,
        if chromium {
            if stripped {
                "removed".to_string()
            } else {
                "ok".to_string()
            }
        } else {
            "not a chromium engine".to_string()
        },
        true,
    );

    let contradiction = gecko && (as_num(field(s, "deviceMemory")).is_some() || is_true(field(s, "uaDataPresent")));
    add(
        &mut checks,
        "gecko_contradiction",
        !contradiction,
        if gecko { "gecko engine" } else { "n/a" },
        true,
    );

    // --- declared identity vs observed engine shape ----------------------
    let ua_str = or_empty_string(field(s, "ua"));
    let chromium_ua = ci(&ua_str, "chrome/") || ci(&ua_str, "chromium/");
    let firefox_ua = ci(&ua_str, "firefox/");
    let webkit_ua = ci(&ua_str, "safari/") && !chromium_ua && !firefox_ua;
    let want_shape = opts.wants("evalShape") || opts.wants("nativeShape");

    let eval_obj = as_obj(field(s, "evalShape"));
    let eval_nl = as_bool(field(s, "evalShape").and_then(|e| field(e, "nl")));
    let native_obj = as_obj(field(s, "nativeShape"));
    let native_nl = as_bool(field(s, "nativeShape").and_then(|e| field(e, "nl")));

    if want_shape && !(eval_obj.is_some() && eval_nl.is_some()) {
        add(
            &mut checks,
            "shape_probe_missing",
            false,
            "eval/native shape probe missing",
            true,
        );
    }
    if eval_obj.is_some() && eval_nl.is_some() {
        let v8 = eval_nl == Some(false);
        let bad = (chromium_ua && !v8) || ((firefox_ua || webkit_ua) && v8);
        add(
            &mut checks,
            "engine_eval_mismatch",
            !bad,
            if bad {
                format!(
                    "eval newline={} len={}",
                    js_string_opt(field(s, "evalShape").and_then(|e| field(e, "nl"))),
                    js_string_opt(field(s, "evalShape").and_then(|e| field(e, "len")))
                )
            } else {
                "ok".to_string()
            },
            false,
        );
    }
    if eval_obj.is_some() && native_obj.is_some() && eval_nl.is_some() && native_nl.is_some() {
        let bad = eval_nl != native_nl;
        add(
            &mut checks,
            "native_shape_inconsistent",
            !bad,
            if bad {
                "eval/native format differ".to_string()
            } else {
                "ok".to_string()
            },
            false,
        );
    }
    if let Some(ps) = as_str(field(s, "productSub")).filter(|p| !p.is_empty()) {
        let expect = if firefox_ua {
            Some("20100101")
        } else if chromium_ua || ci(&ua_str, "safari/") || ci(&ua_str, "opr/") {
            Some("20030107")
        } else {
            None
        };
        if let Some(expect) = expect {
            let ok = ps == expect;
            add(
                &mut checks,
                "productsub_mismatch",
                ok,
                if ok {
                    "ok".to_string()
                } else {
                    format!("productSub={ps}")
                },
                false,
            );
        }
    }
    if let (Some(plen), Some(mime), true) = (
        as_num(field(s, "plugins").and_then(|p| field(p, "length"))),
        as_num(field(s, "mimeCount")),
        as_obj(field(s, "plugins")).is_some(),
    ) {
        let bad = plen > 0.0 && mime == 0.0;
        add(
            &mut checks,
            "plugins_mime_mismatch",
            !bad,
            if bad {
                format!("plugins={}, mimeTypes=0", dnum(plen))
            } else {
                "ok".to_string()
            },
            false,
        );
    }
    if let Some(langs_obj) = as_obj(field(s, "languages")) {
        let lang_v = langs_obj.get("lang");
        let langs: &[Value] = langs_obj
            .get("langs")
            .and_then(|v| as_arr(Some(v)))
            .map(|a| a.as_slice())
            .unwrap_or(&[]);
        let lang_truthy = lang_v.map_or(false, truthy);
        if lang_truthy && !langs.is_empty() {
            let ok = langs.iter().any(|x| Some(x) == lang_v);
            add(
                &mut checks,
                "language_not_in_languages",
                ok,
                if ok {
                    "ok".to_string()
                } else {
                    format!("{} not in languages", js_string_opt(lang_v))
                },
                false,
            );
        }
        if let Some(al) = opts.accept_language.filter(|x| !x.is_empty()) {
            let base = |t: &str| t.split('-').next().unwrap_or("").to_string();
            let header: Vec<String> = al
                .split(',')
                .map(|x| {
                    x.split(';')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_lowercase()
                })
                .filter(|x| !x.is_empty() && x != "*")
                .collect();
            let mut client: Vec<String> = Vec::new();
            if let Some(l) = as_str(lang_v) {
                client.push(l.to_lowercase());
            }
            for l in langs.iter().filter_map(|l| as_str(Some(l))) {
                client.push(l.to_lowercase());
            }
            if !header.is_empty() && !client.is_empty() {
                let ok = client
                    .iter()
                    .any(|c| header.iter().any(|h| h == c || base(h) == base(c)));
                add(
                    &mut checks,
                    "language_header_mismatch",
                    ok,
                    if ok {
                        "ok".to_string()
                    } else {
                        format!("header={} client={}", header[0], client[0])
                    },
                    false,
                );
            }
        }
    }
    if chromium_ua {
        if let Some(cs) = as_obj(field(s, "chromeShape")) {
            let any = ["runtime", "loadTimes", "csi", "app"]
                .iter()
                .filter_map(|k| cs.get(*k))
                .any(truthy);
            add(
                &mut checks,
                "chrome_shape_hollow",
                any,
                if any {
                    "ok".to_string()
                } else {
                    "window.chrome is hollow".to_string()
                },
                false,
            );
        }
    }

    // --- cross-realm (worker) consistency --------------------------------
    if opts.wants("workerInfo") && as_obj(field(s, "workerInfo")).is_none() {
        add(&mut checks, "worker_probe_missing", false, "worker probe missing", false);
    }
    if let Some(wi) = as_obj(field(s, "workerInfo")) {
        if let (Some(a), Some(b)) = (
            as_num(wi.get("hardwareConcurrency")),
            as_num(field(s, "hardwareConcurrency")),
        ) {
            if a != b {
                add(
                    &mut checks,
                    "worker_hw_mismatch",
                    false,
                    format!("main={} worker={}", dnum(b), dnum(a)),
                    false,
                );
            }
        }
        if let (Some(a), Some(b)) = (as_num(wi.get("deviceMemory")), as_num(field(s, "deviceMemory"))) {
            if a != b {
                add(
                    &mut checks,
                    "worker_mem_mismatch",
                    false,
                    format!("main={} worker={}", dnum(b), dnum(a)),
                    false,
                );
            }
        }
        if let (Some(a), Some(b)) = (
            as_str(wi.get("platform")).filter(|p| !p.is_empty()),
            as_str(field(s, "platform")).filter(|p| !p.is_empty()),
        ) {
            if a != b {
                add(
                    &mut checks,
                    "worker_platform_mismatch",
                    false,
                    "main≠worker platform",
                    false,
                );
            }
        }
        if let (Some(a), Some(b)) = (
            as_bool(wi.get("evalShape").and_then(|e| field(e, "nl"))),
            as_bool(field(s, "evalShape").and_then(|e| field(e, "nl"))),
        ) {
            let bad = a != b;
            add(
                &mut checks,
                "worker_engine_mismatch",
                !bad,
                if bad {
                    "main≠worker native format".to_string()
                } else {
                    "ok".to_string()
                },
                false,
            );
        }
    }
    if is_false(field(s, "canvasStable")) {
        add(
            &mut checks,
            "canvas_unstable",
            false,
            "canvas output drifts across renders",
            false,
        );
    }

    // --- WebGPU ↔ WebGL ↔ platform cross-validation ----------------------
    if let Some(gpu) = as_obj(field(s, "webgpu")) {
        if is_false(gpu.get("ok")) && chromium_ua {
            add(&mut checks, "webgpu_absent", false, "requestAdapter returned null", false);
        } else if is_true(gpu.get("ok")) {
            let raw = ["vendor", "description", "device"]
                .iter()
                .filter_map(|k| gpu.get(*k))
                .find(|v| truthy(v))
                .map(js_string)
                .unwrap_or_default();
            let wgpu = gpu_vendor(&raw);
            let wgl = as_obj(field(s, "webgl")).map(|m| {
                gpu_vendor(&format!(
                    "{} {}",
                    or_empty_string(m.get("vendor")),
                    or_empty_string(m.get("renderer"))
                ))
            });
            if let (Some(a), Some(Some(b))) = (wgpu, wgl) {
                let ok = a == b;
                add(
                    &mut checks,
                    "webgpu_webgl_mismatch",
                    ok,
                    if ok {
                        "ok".to_string()
                    } else {
                        format!("webgpu={a} webgl={b}")
                    },
                    false,
                );
            }
        }
    }

    // --- window vs screen geometry ---------------------------------------
    let sc = field(s, "screen");
    let scw = sc.and_then(|x| as_num(field(x, "width")));
    let sch = sc.and_then(|x| as_num(field(x, "height")));
    let ow: &[Value] = as_arr(field(s, "outerWH"))
        .map(|a| a.as_slice())
        .unwrap_or(&[]);
    let ow0 = as_num(ow.first());
    let ow1 = as_num(ow.get(1));
    let mut iw0 = as_num(as_arr(field(s, "innerWH")).and_then(|a| a.first()));
    let mut iw1 = as_num(as_arr(field(s, "innerWH")).and_then(|a| a.get(1)));

    // innerWH is an unsigned supplement: drop it unless it is consistent with
    // the signed outer/screen dimensions.
    if let (Some(x), Some(y)) = (iw0, iw1) {
        if ow0.map_or(false, |o| x > o + OUTER_HEIGHT_SLACK)
            || ow1.map_or(false, |o| y > o + OUTER_HEIGHT_SLACK)
            || scw.map_or(false, |w| x > w + OUTER_HEIGHT_SLACK)
            || sch.map_or(false, |h| y > h + OUTER_HEIGHT_SLACK)
        {
            iw0 = None;
            iw1 = None;
        }
    }

    let single_monitor = is_false(field(s, "isExtended"));
    let outer_taller = match (ow1, sch) {
        (Some(o), Some(h)) => o > h + OUTER_HEIGHT_SLACK,
        _ => false,
    };
    let exceeds = outer_taller && single_monitor;
    add(
        &mut checks,
        "window_exceeds_screen",
        !exceeds,
        if single_monitor {
            if exceeds {
                format!(
                    "outerHeight {} > screen.height {}",
                    dnum(ow1.unwrap_or_default()),
                    dnum(sch.unwrap_or_default())
                )
            } else {
                "ok".to_string()
            }
        } else {
            "monitor layout unknown".to_string()
        },
        true,
    );

    let viewport_is_screen = !mobile
        && match (iw0, iw1, scw, sch, ow1) {
            (Some(a), Some(b), Some(w), Some(h), Some(o)) => a == w && b == h && o > b,
            _ => false,
        };
    add(
        &mut checks,
        "viewport_override",
        !viewport_is_screen,
        if viewport_is_screen {
            format!(
                "viewport {}x{} == screen, window {} tall",
                dnum(iw0.unwrap_or_default()),
                dnum(iw1.unwrap_or_default()),
                dnum(ow1.unwrap_or_default())
            )
        } else {
            "ok".to_string()
        },
        false,
    );

    let brands = as_arr(field(s, "uaData").and_then(|u| field(u, "brands")))
        .map(|a| a.iter().map(js_string).collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    let headless = ci(&brands, "headlesschrome") || ci(&ua_str, "headlesschrome");
    add(
        &mut checks,
        "headless_token",
        !headless,
        if headless {
            "HeadlessChrome present".to_string()
        } else {
            "absent".to_string()
        },
        true,
    );

    // --- tamper / WebCrypto ----------------------------------------------
    let t_obj = as_obj(field(s, "tamper"));
    let want_tamper = opts.wants("tamper");
    if want_tamper && t_obj.is_none() {
        add(
            &mut checks,
            "tamper_probe_missing",
            false,
            "tamper probe missing or malformed",
            true,
        );
    }
    let tampered: Vec<String> = match t_obj {
        Some(t) => t
            .iter()
            .filter(|(_, v)| is_false(Some(v)))
            .map(|(k, _)| k.clone())
            .collect(),
        None => Vec::new(),
    };
    add(
        &mut checks,
        "native_tamper",
        tampered.is_empty(),
        if tampered.is_empty() {
            "native".to_string()
        } else {
            format!(
                "JS-overridden: {}",
                tampered
                    .iter()
                    .take(MAX_TAMPER_KEYS)
                    .map(|k| clip_str(k, MAX_TAMPER_KEY_LENGTH))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
        false,
    );

    let crypto_keys = ["cryptoSign", "cryptoImportKey", "cryptoDigest"];
    let has_crypto_verdict = match t_obj {
        Some(t) => crypto_keys
            .iter()
            .any(|k| as_bool(t.get(*k)).is_some()),
        None => false,
    };
    if has_crypto_verdict {
        let patched: Vec<&str> = crypto_keys
            .iter()
            .copied()
            .filter(|k| is_false(t_obj.and_then(|t| t.get(*k))))
            .collect();
        add(
            &mut checks,
            "crypto_tampered",
            patched.is_empty(),
            if patched.is_empty() {
                "native".to_string()
            } else {
                format!("WebCrypto overridden: {}", patched.join(", "))
            },
            true,
        );
    } else if want_tamper {
        add(
            &mut checks,
            "crypto_probe_missing",
            false,
            "no WebCrypto tamper verdict (probe stripped)",
            true,
        );
    }

    // --- CDP / DevTools attachment ---------------------------------------
    let want_cdp = opts.wants("cdp");
    let cdp = as_obj(field(s, "cdp"));
    if want_cdp && cdp.is_none() {
        add(&mut checks, "cdp_probe_missing", false, "cdp probe missing or malformed", true);
    }
    if let Some(cdp) = cdp {
        let tapped = as_num(cdp.get("tap")).map_or(false, |x| x > 0.0);
        add(
            &mut checks,
            "cdp_console_trap",
            !tapped,
            if tapped {
                format!(
                    "console read externally ({}x)",
                    dnum(as_num(cdp.get("tap")).unwrap_or_default())
                )
            } else {
                "no external read".to_string()
            },
            true,
        );
        let paused = is_true(cdp.get("dbgPause"));
        add(
            &mut checks,
            "cdp_debugger_pause",
            !paused,
            if paused {
                "debugger; caused a pause (>50ms)".to_string()
            } else {
                "no pause".to_string()
            },
            true,
        );
        let prep = is_true(cdp.get("errPrep"));
        add(
            &mut checks,
            "cdp_stack_tamper",
            !prep,
            if prep {
                "Error.prepareStackTrace overridden".to_string()
            } else {
                "clean".to_string()
            },
            false,
        );
        let aut = as_num(cdp.get("aut")) == Some(1.0);
        add(
            &mut checks,
            "cdp_automation_globals",
            !aut,
            if aut {
                "automation global present".to_string()
            } else {
                "none".to_string()
            },
            false,
        );
        let obj_tap = as_num(cdp.get("objTap")).map_or(false, |x| x > 0.0);
        add(
            &mut checks,
            "cdp_console_object_trap",
            !obj_tap,
            if obj_tap {
                format!(
                    "console object getter fired ({}x)",
                    dnum(as_num(cdp.get("objTap")).unwrap_or_default())
                )
            } else {
                "no object read".to_string()
            },
            false,
        );
        let stack_tap = as_num(cdp.get("stackTap")).map_or(false, |x| x > 0.0);
        add(
            &mut checks,
            "cdp_stack_getter",
            !stack_tap,
            if stack_tap {
                format!(
                    "Error.stack getter fired ({}x)",
                    dnum(as_num(cdp.get("stackTap")).unwrap_or_default())
                )
            } else {
                "no stack read".to_string()
            },
            false,
        );
        let proto_tap = as_num(cdp.get("protoTap")).map_or(false, |x| x > 0.0);
        add(
            &mut checks,
            "cdp_proto_getter",
            !proto_tap,
            if proto_tap {
                format!(
                    "prototype getter fired ({}x)",
                    dnum(as_num(cdp.get("protoTap")).unwrap_or_default())
                )
            } else {
                "no proto read".to_string()
            },
            false,
        );
    }

    // --- active capability probes ---------------------------------------
    if let Some(act) = as_obj(field(s, "active")) {
        if chromium_ua {
            if let Some(dev) = as_obj(act.get("devices")) {
                let total = truthy_number(dev.get("audioin"))
                    + truthy_number(dev.get("videoin"))
                    + truthy_number(dev.get("audioout"));
                add(
                    &mut checks,
                    "active_no_media_devices",
                    total > 0.0,
                    if total > 0.0 {
                        format!("devices={}", dnum(total))
                    } else {
                        "enumerateDevices returned 0".to_string()
                    },
                    false,
                );
            }
            if let Some(codecs) = as_obj(act.get("codecs")) {
                let has = ["mp4", "webm"]
                    .iter()
                    .any(|k| codecs.get(*k).map_or(false, truthy));
                add(
                    &mut checks,
                    "active_no_video_codecs",
                    has,
                    if has {
                        "ok".to_string()
                    } else {
                        "no mp4/webm codec support".to_string()
                    },
                    false,
                );
            }
            let desktop_ua = !any_ci(&ua_str, &["mobi", "android", "iphone", "ipad"]);
            if let Some(media) = as_obj(act.get("media")) {
                if is_false(media.get("pointerFine"))
                    && is_false(media.get("hoverHover"))
                    && desktop_ua
                {
                    add(
                        &mut checks,
                        "active_no_fine_pointer",
                        false,
                        "desktop UA but no fine pointer/hover",
                        false,
                    );
                }
            }
        }
        if firefox_ua {
            if let Some(api) = as_obj(act.get("mediaApi")) {
                if as_str(api.get("md")) == Some("object") {
                    let ok = as_str(api.get("ed")) == Some("function");
                    add(
                        &mut checks,
                        "active_media_api_missing",
                        ok,
                        if ok {
                            "ok".to_string()
                        } else {
                            "enumerateDevices missing".to_string()
                        },
                        false,
                    );
                }
            }
        }
        if is_false(act.get("rtc")) {
            add(
                &mut checks,
                "active_no_rtc",
                false,
                "RTCPeerConnection unavailable",
                false,
            );
        }
        if is_true(act.get("permError")) && (chromium_ua || firefox_ua) {
            add(
                &mut checks,
                "active_permissions_error",
                false,
                "permissions.query failed",
                false,
            );
        }
        if let (Some(np), Some(ps)) = (
            as_str(field(s, "notifPerm")),
            as_str(act.get("permState")),
        ) {
            let norm = |p: &str| -> String {
                if p == "prompt" { "default".to_string() } else { p.to_string() }
            };
            let bad = norm(ps) != np;
            add(
                &mut checks,
                "notif_perm_mismatch",
                !bad,
                if bad {
                    format!("Notification={np} vs query={ps}")
                } else {
                    "ok".to_string()
                },
                false,
            );
        }
    }

    // Automation globals detected in the MAIN document.
    if let Some(globals) = as_arr(field(s, "automationGlobals")).filter(|g| !g.is_empty()) {
        add(
            &mut checks,
            "automation_globals_main",
            false,
            format!(
                "found: {}",
                globals
                    .iter()
                    .take(5)
                    .map(js_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            true,
        );
    }

    // --- extended consistency checks -------------------------------------
    let os = declared_os(s);

    if let (Some(wua), Some(ua)) = (as_str(field(s, "workerUA")), as_str(field(s, "ua"))) {
        if !ua.is_empty() {
            let mismatch = wua != ua;
            add(
                &mut checks,
                "worker_ua_mismatch",
                !mismatch,
                if mismatch {
                    format!("main≠worker ({}:{})", MAX_DETAIL_FIELDS, clip_str(wua, 48))
                } else {
                    "consistent".to_string()
                },
                true,
            );
        }
    }

    // WebGL renderer sanity.
    if let Some(gl) = as_obj(field(s, "webgl")) {
        let renderer = or_empty_string(gl.get("renderer"));
        let vendor = or_empty_string(gl.get("vendor"));
        if is_false(gl.get("ok")) && !mobile {
            add(
                &mut checks,
                "webgl_absent_desktop",
                false,
                "no webgl context on desktop UA",
                false,
            );
        }
        let generic = is_software_gpu(&renderer) || is_software_gpu(&vendor);
        add(
            &mut checks,
            "webgl_software_renderer",
            !generic,
            if generic {
                format!("renderer={}", clip_str(&renderer, 64))
            } else if renderer.is_empty() {
                "no webgl".to_string()
            } else {
                renderer.clone()
            },
            false,
        );

        let hash_ok = as_str(gl.get("hash")).map_or(false, |h| h.chars().count() >= 8 && h != "0");
        let no_context = is_false(gl.get("ok"));
        add(
            &mut checks,
            "webgl_render_probe",
            hash_ok || !no_context,
            if no_context {
                "no webgl context".to_string()
            } else if hash_ok {
                format!(
                    "hash={}",
                    clip_str(as_str(gl.get("hash")).unwrap_or(""), 12)
                )
            } else {
                "empty render".to_string()
            },
            false,
        );

        let webgl2_phantom = is_false(gl.get("webgl2")) && chromium && !mobile;
        add(
            &mut checks,
            "webgl2_absent_on_chromium",
            !webgl2_phantom,
            if webgl2_phantom {
                "webgl2 missing on chromium desktop".to_string()
            } else {
                "ok".to_string()
            },
            false,
        );

        let combo = format!("{vendor} {renderer}");
        let gpu_apple = any_ci(&combo, &["apple", "metal", "m1", "m2", "m3", "m4"]);
        let gpu_linux = any_ci(&combo, &["mesa", "llvmpipe", "amdgpu", "nouveau"]);
        let gpu_windows = any_ci(
            &combo,
            &["direct3d", "d3d11", "angle (nvidia", "geforce", "quadro", "rtx"],
        );
        let gpu_android = any_ci(&combo, &["adreno", "mali", "powervr", "tegra"]);
        let mut platform_gpu_mismatch = false;
        let mut pg_detail = "";
        match os {
            Some("android") | Some("ios") => {
                if gpu_apple && os == Some("android") {
                    platform_gpu_mismatch = true;
                    pg_detail = "android declared, Apple GPU";
                } else if (gpu_windows || any_ci(&combo, &["geforce", "quadro", "rtx"]))
                    && !gpu_android
                {
                    platform_gpu_mismatch = true;
                    pg_detail = if os == Some("android") {
                        "android declared, desktop GPU"
                    } else {
                        "ios declared, desktop GPU"
                    };
                }
            }
            Some("windows") => {
                if gpu_linux && !ci(&combo, "swiftshader") {
                    platform_gpu_mismatch = true;
                    pg_detail = "windows declared, Linux GL stack";
                }
            }
            Some("macos") | Some("linux") => {
                if gpu_windows && !gpu_apple && os == Some("macos") {
                    platform_gpu_mismatch = true;
                    pg_detail = "macos declared, D3D backend";
                }
            }
            _ => {}
        }
        if !combo.trim().is_empty() {
            add(
                &mut checks,
                "platform_gpu_mismatch",
                !platform_gpu_mismatch,
                if platform_gpu_mismatch {
                    pg_detail.to_string()
                } else {
                    "consistent".to_string()
                },
                true,
            );
        }
    }

    // Canvas read-back sanity.
    if let Some(canvas) = as_str(field(s, "canvas")) {
        let degenerate = canvas.is_empty() || canvas.chars().all(|c| c == '0');
        add(
            &mut checks,
            "canvas_degenerate",
            !degenerate,
            if degenerate {
                "empty canvas hash".to_string()
            } else {
                format!("hash={}", clip_str(canvas, 12))
            },
            false,
        );
    }

    // AudioContext fingerprint.
    if let Some(audio) = as_num(field(s, "audio")) {
        let silent = audio == 0.0;
        add(
            &mut checks,
            "audio_silent",
            !silent,
            if silent { "silent output" } else { "ok" },
            false,
        );
    }

    // Emoji rendering.
    if let Some(emoji) = as_obj(field(s, "emoji")) {
        let style = or_empty_string(emoji.get("style"));
        let width = as_num(emoji.get("width"));
        let renders = matches!(width, Some(w) if w != 0.0);
        add(
            &mut checks,
            "emoji_no_render",
            renders,
            if renders {
                format!("width={}", dnum(width.unwrap_or_default()))
            } else {
                "no glyph metrics".to_string()
            },
            false,
        );

        let mobile_os = matches!(os, Some("android") | Some("ios"));
        if let Some(os) = os.filter(|_| !mobile_os) {
            let apple_like = match width {
                Some(w) => w >= 110.0,
                None => style == "apple-like",
            };
            let mismatched = if os == "macos" {
                !apple_like
            } else if os == "windows" || os == "linux" {
                apple_like
            } else {
                false
            };
            add(
                &mut checks,
                "emoji_os_mismatch",
                !mismatched,
                if mismatched {
                    format!(
                        "declared {os}, width {}",
                        width.map(dnum).unwrap_or_else(|| "null".to_string())
                    )
                } else {
                    "match".to_string()
                },
                false,
            );
        }
    }

    // Hardware shape.
    if let Some(hc) = as_num(field(s, "hardwareConcurrency")) {
        let odd = hc > 0.0 && hc % 2.0 == 1.0 && hc != 1.0;
        let too_small = hc == 1.0 && !mobile;
        let too_many = hc > 12.0 && mobile;
        let bad = odd || too_small || too_many;
        add(
            &mut checks,
            "hardware_shape",
            !bad,
            if bad {
                format!(
                    "hardwareConcurrency={}{}",
                    dnum(hc),
                    if mobile { " (mobile)" } else { "" }
                )
            } else {
                "ok".to_string()
            },
            false,
        );
    }

    // Core count vs device memory.
    let mem = as_num(field(s, "deviceMemory"));
    if let (Some(hc), Some(mem)) = (as_num(field(s, "hardwareConcurrency")), mem) {
        let mismatched = (hc >= 8.0 && mem <= 1.0) || (hc <= 2.0 && mem >= 16.0);
        add(
            &mut checks,
            "hw_mem_mismatch",
            !mismatched,
            if mismatched {
                format!("cores={}, deviceMemory={}", dnum(hc), dnum(mem))
            } else {
                "ok".to_string()
            },
            false,
        );
    }

    // Rendering pipeline availability.
    let render_probes: Vec<&str> = opts
        .optional_fields
        .iter()
        .map(|f| f.as_str())
        .filter(|f| ["webgl", "canvas", "audio", "emoji"].contains(f))
        .collect();
    if render_probes.len() >= 2 {
        let ran: Vec<&str> = render_probes
            .iter()
            .copied()
            .filter(|f| match field(s, f) {
                None => false,
                Some(v) => !v.is_null(),
            })
            .collect();
        let failed = |f: &str| -> bool {
            match (f, field(s, f)) {
                ("webgl", Some(v)) => as_obj(Some(v)).is_some() && is_false(field(v, "ok")),
                ("canvas", Some(Value::String(c))) => c.is_empty(),
                ("emoji", Some(v)) => as_obj(Some(v)).is_some() && as_num(field(v, "width")) == Some(0.0),
                _ => false,
            }
        };
        let all_ran_failed =
            ran.len() >= 2 && ran.contains(&"webgl") && ran.iter().all(|f| failed(f));
        add(
            &mut checks,
            "render_pipeline_absent",
            !all_ran_failed,
            if all_ran_failed {
                format!("all failed: {}", render_probes.join("/"))
            } else if ran.is_empty() {
                "probes not executed".to_string()
            } else {
                format!("{}/{} ran", ran.len(), render_probes.len())
            },
            false,
        );
    }

    // Storage quota rounding.
    if let Some(quota) = as_num(field(s, "storageQuota")) {
        let tiny = quota > 0.0 && quota < 1024.0 * 1024.0;
        add(
            &mut checks,
            "storage_quota_tiny",
            !tiny,
            if tiny {
                format!("quota={}", dnum(quota))
            } else {
                "ok".to_string()
            },
            false,
        );
    }

    let blocked_by: Vec<String> = checks
        .iter()
        .filter(|c| c.gating && !c.passed)
        .map(|c| c.id.clone())
        .collect();
    let risk_flags: Vec<String> = checks
        .iter()
        .filter(|c| !c.gating && !c.passed)
        .map(|c| c.id.clone())
        .collect();
    // Must see the same data the checks did: a field supplied only by the
    // top frame (merged into `s`) would otherwise be treated as "missing" and
    // its signal dropped, under-scoring the client.
    let signals = collect_signals(&checks, opts.optional_fields, s);

    DetectOutcome {
        pass: blocked_by.is_empty(),
        checks,
        blocked_by,
        risk_flags,
        signals,
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------


/// JS parity tests are the only check that the Rust port matches the reference
/// implementation. A missing toolchain must fail the suite, not silently pass:
/// set `CAP_SKIP_JS_PARITY=1` to skip deliberately (e.g. on a machine without
/// bun or the reference tree).
fn parity_required(reason: &str) {
    if std::env::var("CAP_SKIP_JS_PARITY").as_deref() == Ok("1") {
        eprintln!("SKIP (CAP_SKIP_JS_PARITY=1): {reason}");
        return;
    }
    panic!("{reason}; install bun and the reference tree, or set CAP_SKIP_JS_PARITY=1");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn opts(fonts: Option<usize>) -> DetectOpts<'static> {
        DetectOpts {
            font_stack_count: fonts,
            optional_fields: &[],
            accept_language: None,
        }
    }

    fn full_fields() -> Vec<String> {
        [
            "platform",
            "workerUA",
            "hardwareConcurrency",
            "webgl",
            "canvas",
            "audio",
            "emoji",
            "storageQuota",
            "active",
            "canvasStable",
            "webgpu",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn frac(n: usize) -> Value {
        json!((0..n).map(|i| 1200.88 + i as f64 * 3.17).collect::<Vec<_>>())
    }

    fn ints(n: usize) -> Value {
        json!((0..n).map(|i| 1200 + i * 3).collect::<Vec<_>>())
    }

    fn chrome_human() -> Value {
        json!({
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
            "productSub": "20030107",
            "webdriver": false,
            "oscpu": "__undefined",
            "deviceMemory": 8,
            "uaDataPresent": true,
            "uaData": { "mobile": false, "brands": ["Google Chrome/151", "Chromium/151", "Not.A/Brand/99"] },
            "plugins": { "length": 5 },
            "pdfViewerEnabled": true,
            "engine": { "hasMozInnerScreenX": false, "hasChrome": true },
            "screen": { "width": 1920, "height": 1080 },
            "innerWH": [945, 868],
            "outerWH": [945, 1060],
            "isExtended": false,
            "fontWidths": frac(17),
            "tamper": {
                "getParameterWebGL": true, "toDataURL": true, "getImageData": true,
                "permissionsQuery": true, "fnToString": true
            }
        })
    }

    fn firefox_human() -> Value {
        json!({
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:154.0) Gecko/20100101 Firefox/154.0",
            "productSub": "20100101",
            "webdriver": false,
            "oscpu": "Intel Mac OS X 10.15",
            "uaDataPresent": false,
            "uaData": null,
            "plugins": { "length": 5 },
            "pdfViewerEnabled": true,
            "engine": { "hasMozInnerScreenX": true, "hasChrome": false },
            "screen": { "width": 1920, "height": 1080 },
            "innerWH": [1200, 900],
            "outerWH": [1200, 985],
            "isExtended": false,
            "fontWidths": frac(17),
            "tamper": {
                "getParameterWebGL": true, "toDataURL": true, "getImageData": true,
                "permissionsQuery": true, "fnToString": true
            }
        })
    }

    fn safari_human() -> Value {
        json!({
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Safari/605.1.15",
            "productSub": "20030107",
            "webdriver": false,
            "oscpu": "__undefined",
            "uaDataPresent": false,
            "uaData": null,
            "plugins": { "length": 2 },
            "pdfViewerEnabled": true,
            "engine": { "hasMozInnerScreenX": false, "hasChrome": false },
            "screen": { "width": 1728, "height": 1117 },
            "innerWH": [1200, 900],
            "outerWH": [1200, 980],
            "isExtended": false,
            "fontWidths": frac(17),
            "tamper": {
                "getParameterWebGL": true, "toDataURL": true, "getImageData": true,
                "permissionsQuery": true, "fnToString": true
            }
        })
    }

    fn find<'a>(o: &'a DetectOutcome, id: &str) -> Option<&'a Check> {
        o.checks.iter().find(|c| c.id == id)
    }

    fn ids(v: &[String]) -> Vec<&str> {
        v.iter().map(|s| s.as_str()).collect()
    }

    // ---- geometryStats --------------------------------------------------

    #[test]
    fn geometry_stats_null_under_six_samples() {
        assert_eq!(geometry_stats(Some(&json!([1, 2, 3]))), None);
        assert_eq!(geometry_stats(None), None);
    }

    #[test]
    fn geometry_stats_counts_whole_pixels() {
        let g = geometry_stats(Some(&json!([1200, 1200, 1200, 1300, 1.5, 2.5]))).unwrap();
        assert_eq!(
            g,
            GeometryStats {
                count: 4,
                distinct: 2,
                n: 6
            }
        );
    }

    // ---- humans pass ----------------------------------------------------

    #[test]
    fn desktop_chrome_passes() {
        let r = detect_automation(&chrome_human(), &opts(None));
        assert!(r.pass, "blocked: {:?}", r.blocked_by);
        assert!(r.blocked_by.is_empty());
        assert!(r.risk_flags.is_empty(), "flags: {:?}", r.risk_flags);
    }

    #[test]
    fn firefox_passes() {
        assert!(detect_automation(&firefox_human(), &opts(None)).pass);
    }

    #[test]
    fn ungoogled_chromium_passes() {
        let mut s = chrome_human();
        s["uaData"]["brands"] = json!(["Chromium/141", "Not.A/Brand/99"]);
        assert!(detect_automation(&s, &opts(None)).pass);
    }

    #[test]
    fn android_webview_passes() {
        let mut s = chrome_human();
        s["ua"] = json!("Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/151.0.0.0 Mobile Safari/537.36");
        s["uaData"] = json!({ "mobile": true, "brands": ["Chromium/151"] });
        s["plugins"] = json!({ "length": 0 });
        s["pdfViewerEnabled"] = json!(false);
        s["engine"]["hasChrome"] = json!(false);
        s["screen"] = json!({ "width": 412, "height": 915 });
        s["innerWH"] = json!([412, 915]);
        s["outerWH"] = json!([412, 915]);
        assert!(detect_automation(&s, &opts(None)).pass);
    }

    #[test]
    fn single_font_system_passes() {
        let mut s = chrome_human();
        s["fontWidths"] = json!(vec![1200; 17]);
        assert!(detect_automation(&s, &opts(None)).pass);
    }

    #[test]
    fn multi_monitor_taller_window_passes() {
        let mut s = chrome_human();
        s["isExtended"] = json!(true);
        s["outerWH"] = json!([1600, 1400]);
        assert!(detect_automation(&s, &opts(None)).pass);
    }

    #[test]
    fn safari_without_webdriver_passes() {
        let mut s = safari_human();
        s.as_object_mut().unwrap().remove("webdriver");
        let r = detect_automation(&s, &opts(Some(17)));
        assert!(r.pass, "blocked: {:?}", r.blocked_by);
        assert!(r.blocked_by.is_empty());
    }

    #[test]
    fn edge_on_ios_passes() {
        let s = json!({
            "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/120.0.0.0 Mobile/15E148 Safari/604.1",
            "productSub": "20030107",
            "oscpu": "__undefined",
            "uaDataPresent": false,
            "uaData": null,
            "plugins": { "length": 0 },
            "pdfViewerEnabled": true,
            "engine": { "hasMozInnerScreenX": false, "hasChrome": false },
            "screen": { "width": 390, "height": 844 },
            "innerWH": [390, 664],
            "outerWH": [390, 844],
            "isExtended": null,
            "fontWidths": frac(17),
            "tamper": {
                "getParameterWebGL": true, "toDataURL": true, "getImageData": true,
                "permissionsQuery": true, "fnToString": true
            }
        });
        let r = detect_automation(&s, &opts(Some(17)));
        assert!(r.pass, "blocked: {:?}", r.blocked_by);
        assert!(r.blocked_by.is_empty());
    }

    #[test]
    fn ios_overshooting_outer_height_passes() {
        let mut s = safari_human();
        s["ua"] = json!("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/120.0.0.0 Mobile/15E148 Safari/604.1");
        s.as_object_mut().unwrap().remove("webdriver");
        s["isExtended"] = json!(null);
        s["screen"] = json!({ "width": 390, "height": 844 });
        s["outerWH"] = json!([390, 900]);
        assert!(detect_automation(&s, &opts(Some(17))).pass);
    }

    #[test]
    fn old_webkit_webview_passes() {
        let mut s = safari_human();
        s["ua"] = json!("Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148");
        s.as_object_mut().unwrap().remove("webdriver");
        assert!(detect_automation(&s, &opts(Some(17))).pass);
    }

    #[test]
    fn firefox_taller_second_monitor_passes() {
        let mut s = firefox_human();
        s["isExtended"] = json!(null);
        s["screen"] = json!({ "width": 1920, "height": 1080 });
        s["outerWH"] = json!([1200, 1400]);
        let r = detect_automation(&s, &opts(Some(17)));
        assert!(r.pass);
        assert!(r.blocked_by.is_empty());
    }

    #[test]
    fn safari_taller_second_monitor_passes() {
        let mut s = safari_human();
        s["isExtended"] = json!(null);
        s["outerWH"] = json!([1200, 1600]);
        assert!(detect_automation(&s, &opts(Some(17))).pass);
    }

    #[test]
    fn maximized_window_overhang_passes() {
        let mut s = chrome_human();
        s["screen"] = json!({ "width": 1920, "height": 1080 });
        s["outerWH"] = json!([1920, 1088]);
        assert!(detect_automation(&s, &opts(Some(17))).pass);
    }

    #[test]
    fn font_poor_two_integer_fallbacks_passes() {
        let mut s = firefox_human();
        let mut w = frac(17).as_array().unwrap().clone();
        for (i, item) in w.iter_mut().enumerate().take(9) {
            *item = json!(if i % 2 == 0 { 1200 } else { 1400 });
        }
        s["fontWidths"] = Value::Array(w);
        assert!(detect_automation(&s, &opts(Some(17))).pass);
    }

    #[test]
    fn complete_probe_reports_no_completeness_failure() {
        for s in [chrome_human(), firefox_human(), safari_human()] {
            let r = detect_automation(&s, &opts(Some(17)));
            assert!(!r.blocked_by.iter().any(|b| b == "probe_incomplete"));
        }
    }

    #[test]
    fn dropped_undefined_fields_pass() {
        // firefox_human() omits deviceMemory (undefined) — must not fail.
        let s = firefox_human();
        assert!(s.get("deviceMemory").is_none());
        assert!(detect_automation(&s, &opts(Some(17))).pass);
    }

    #[test]
    fn privacy_extension_canvas_patch_is_a_risk_flag() {
        let mut s = chrome_human();
        s["tamper"]["toDataURL"] = json!(false);
        let r = detect_automation(&s, &opts(None));
        assert!(r.pass);
        assert_eq!(ids(&r.risk_flags), vec!["native_tamper"]);
    }

    #[test]
    fn missing_viewport_does_not_block() {
        let mut s = chrome_human();
        s.as_object_mut().unwrap().remove("innerWH");
        assert!(detect_automation(&s, &opts(None)).pass);
    }

    // ---- bots -----------------------------------------------------------

    #[test]
    fn camoufox_quantized_geometry() {
        let mut s = firefox_human();
        s["fontWidths"] = ints(17);
        let r = detect_automation(&s, &opts(None));
        assert!(!r.pass);
        assert_eq!(ids(&r.blocked_by), vec!["geometry_quantized"]);
    }

    #[test]
    fn playwright_webdriver_true() {
        let mut s = chrome_human();
        s["webdriver"] = json!(true);
        assert!(detect_automation(&s, &opts(None))
            .blocked_by
            .iter()
            .any(|b| b == "webdriver_true"));
    }

    #[test]
    fn webdriver_deleted_on_blink() {
        let mut s = chrome_human();
        s.as_object_mut().unwrap().remove("webdriver");
        assert!(detect_automation(&s, &opts(None))
            .blocked_by
            .iter()
            .any(|b| b == "webdriver_stripped"));
    }

    #[test]
    fn gecko_exposing_chromium_apis() {
        let mut s = firefox_human();
        s["deviceMemory"] = json!(8);
        assert!(detect_automation(&s, &opts(None))
            .blocked_by
            .iter()
            .any(|b| b == "gecko_contradiction"));
    }

    #[test]
    fn patchright_window_taller_than_screen_and_viewport_override() {
        let mut s = chrome_human();
        s["screen"] = json!({ "width": 1280, "height": 720 });
        s["innerWH"] = json!([1280, 720]);
        s["outerWH"] = json!([1288, 805]);
        let r = detect_automation(&s, &opts(None));
        assert_eq!(ids(&r.blocked_by), vec!["window_exceeds_screen"]);
        assert!(r.risk_flags.iter().any(|f| f == "viewport_override"));
    }

    #[test]
    fn headless_token_in_brands() {
        let mut s = chrome_human();
        s["uaData"]["brands"] = json!(["HeadlessChrome/151", "Chromium/151"]);
        assert!(detect_automation(&s, &opts(None))
            .blocked_by
            .iter()
            .any(|b| b == "headless_token"));
    }

    #[test]
    fn stripped_probe_is_rejected() {
        let r = detect_automation(&json!({}), &opts(Some(17)));
        assert!(!r.pass);
        assert!(r.blocked_by.iter().any(|b| b == "probe_incomplete"));
    }

    #[test]
    fn partially_stripped_probe_is_rejected() {
        let mut s = chrome_human();
        s["fontWidths"] = json!([1, 2, 3, 4, 5]);
        let r = detect_automation(&s, &opts(Some(17)));
        assert!(!r.pass);
        assert!(r.blocked_by.iter().any(|b| b == "probe_incomplete"));
    }

    #[test]
    fn dropping_a_single_field_is_rejected() {
        for field_name in [
            "ua",
            "screen",
            "outerWH",
            "fontWidths",
            "isExtended",
            "uaDataPresent",
        ] {
            let mut s = chrome_human();
            s.as_object_mut().unwrap().remove(field_name);
            let r = detect_automation(&s, &opts(Some(17)));
            assert!(
                r.blocked_by.iter().any(|b| b == "probe_incomplete"),
                "field {field_name} not rejected"
            );
        }
    }

    #[test]
    fn wrong_field_types_are_rejected() {
        let mut s = chrome_human();
        s["screen"] = json!([]);
        s["fontWidths"] = json!("abc");
        s["isExtended"] = json!("no");
        let r = detect_automation(&s, &opts(Some(17)));
        assert!(!r.pass);
        assert!(r.blocked_by.iter().any(|b| b == "probe_incomplete"));
    }

    #[test]
    fn array_vector_is_rejected() {
        let r = detect_automation(&json!([]), &opts(Some(17)));
        assert!(!r.pass);
        assert!(r.blocked_by.iter().any(|b| b == "probe_incomplete"));
    }

    #[test]
    fn headless_chromium_hiding_webdriver_is_caught() {
        let mut s = chrome_human();
        s.as_object_mut().unwrap().remove("webdriver");
        assert!(detect_automation(&s, &opts(Some(17)))
            .blocked_by
            .iter()
            .any(|b| b == "webdriver_stripped"));
    }

    #[test]
    fn window_taller_than_known_single_screen() {
        let mut s = chrome_human();
        s["isExtended"] = json!(false);
        s["screen"] = json!({ "width": 1280, "height": 720 });
        s["outerWH"] = json!([1288, 805]);
        assert!(detect_automation(&s, &opts(Some(17)))
            .blocked_by
            .iter()
            .any(|b| b == "window_exceeds_screen"));
    }

    #[test]
    fn hostile_tamper_keys_are_bounded() {
        let mut s = chrome_human();
        let mut t = serde_json::Map::new();
        for i in 0..2000 {
            t.insert("k".repeat(50) + &i.to_string(), json!(false));
        }
        s["tamper"] = Value::Object(t);
        let r = detect_automation(&s, &opts(Some(17)));
        let native = find(&r, "native_tamper").expect("native_tamper present");
        assert!(native.detail.chars().count() < 400);
    }

    #[test]
    fn oversized_font_widths_are_bounded() {
        let mut s = chrome_human();
        s["fontWidths"] = json!(vec![1200; 20_000]);
        let r = detect_automation(&s, &opts(Some(17)));
        assert!(r.blocked_by.iter().any(|b| b == "probe_incomplete"));
    }

    #[test]
    fn missing_vector_fails_closed() {
        let r = detect_automation(&Value::Null, &opts(None));
        assert!(!r.pass);
        assert_eq!(ids(&r.blocked_by), vec!["probe_missing"]);
    }

    // ---- CDP traps ------------------------------------------------------

    fn cdp_base() -> Value {
        let mut s = chrome_human();
        s["cdp"] = json!({
            "tap": 0, "objTap": 0, "stackTap": 0, "protoTap": 0,
            "dbgPause": false, "errPrep": false, "aut": 0, "webdriver": false
        });
        s
    }

    #[test]
    fn clean_cdp_probe_passes() {
        let r = detect_automation(&cdp_base(), &opts(None));
        assert!(r
            .checks
            .iter()
            .filter(|c| c.id.starts_with("cdp"))
            .all(|c| c.passed));
    }

    #[test]
    fn cdp_object_and_stack_and_proto_taps_flagged() {
        for (key, id) in [
            ("objTap", "cdp_console_object_trap"),
            ("stackTap", "cdp_stack_getter"),
            ("protoTap", "cdp_proto_getter"),
        ] {
            let mut s = cdp_base();
            s["cdp"][key] = json!(3);
            assert!(!find(&detect_automation(&s, &opts(None)), id).unwrap().passed);
        }
    }

    #[test]
    fn cdp_console_trap_is_gating() {
        let mut s = cdp_base();
        s["cdp"]["tap"] = json!(1);
        let r = detect_automation(&s, &opts(None));
        assert!(!r.pass);
        assert!(r.blocked_by.iter().any(|b| b == "cdp_console_trap"));
    }

    // ---- active capability probes ---------------------------------------

    fn active_base() -> Value {
        let mut s = chrome_human();
        s["active"] = json!({
            "devices": { "audioin": 1, "videoin": 1, "audioout": 2 },
            "codecs": { "mp4": "probably", "webm": "probably" },
            "rtc": true,
            "media": { "pointerFine": true, "hoverHover": true },
            "permState": "prompt"
        });
        s
    }

    #[test]
    fn healthy_active_probe_passes() {
        let r = detect_automation(&active_base(), &opts(None));
        assert!(r
            .checks
            .iter()
            .filter(|c| c.id.starts_with("active"))
            .all(|c| c.passed));
    }

    #[test]
    fn active_probe_failures_flagged() {
        let mutate: [(&str, Value, &str); 4] = [
            ("devices", json!({ "audioin": 0, "videoin": 0, "audioout": 0 }), "active_no_media_devices"),
            ("codecs", json!({ "mp4": "", "webm": "" }), "active_no_video_codecs"),
            ("rtc", json!(false), "active_no_rtc"),
            ("media", json!({ "pointerFine": false, "hoverHover": false }), "active_no_fine_pointer"),
        ];
        for (key, val, id) in mutate {
            let mut s = active_base();
            s["active"][key] = val;
            assert!(!find(&detect_automation(&s, &opts(None)), id).unwrap().passed, "{id}");
        }
    }

    // ---- identity consistency -------------------------------------------

    fn identity_base() -> Value {
        let mut s = chrome_human();
        s["evalShape"] = json!({ "nl": false, "len": 33 });
        s["nativeShape"] = json!({ "nl": false, "len": 40 });
        s["mimeCount"] = json!(2);
        s["plugins"] = json!({ "length": 2 });
        s["languages"] = json!({ "lang": "en-US", "langs": ["en-US", "en"] });
        s["chromeShape"] = json!({ "runtime": true, "loadTimes": true, "csi": true, "app": true });
        s["canvasStable"] = json!(true);
        s
    }

    #[test]
    fn healthy_identity_consistency_passes() {
        let r = detect_automation(&identity_base(), &opts(None));
        for id in [
            "engine_eval_mismatch",
            "native_shape_inconsistent",
            "plugins_mime_mismatch",
            "language_not_in_languages",
            "chrome_shape_hollow",
            "canvas_unstable",
        ] {
            assert!(find(&r, id).map_or(true, |c| c.passed), "{id}");
        }
    }

    #[test]
    fn identity_mismatches_flagged() {
        let cases: Vec<(&str, Value, &str)> = vec![
            ("evalShape", json!({ "nl": true, "len": 45 }), "engine_eval_mismatch"),
            ("plugins", json!({ "length": 3 }), "plugins_mime_mismatch"),
            ("languages", json!({ "lang": "fr-FR", "langs": ["en-US", "en"] }), "language_not_in_languages"),
            ("chromeShape", json!({ "runtime": false, "loadTimes": false, "csi": false, "app": false }), "chrome_shape_hollow"),
            ("canvasStable", json!(false), "canvas_unstable"),
        ];
        for (key, val, id) in cases {
            let mut s = identity_base();
            s[key] = val;
            if id == "plugins_mime_mismatch" {
                s["mimeCount"] = json!(0);
            }
            let r = detect_automation(&s, &opts(None));
            assert!(!find(&r, id).unwrap().passed, "{id}");
        }
    }

    #[test]
    fn worker_hardware_mismatch_flagged() {
        let mut s = identity_base();
        s["hardwareConcurrency"] = json!(8);
        s["workerInfo"] = json!({ "hardwareConcurrency": 4 });
        assert!(!find(&detect_automation(&s, &opts(None)), "worker_hw_mismatch")
            .unwrap()
            .passed);
    }

    #[test]
    fn firefox_empty_enumerate_devices_not_flagged() {
        let mut s = chrome_human();
        s["ua"] = json!("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0");
        s["productSub"] = json!("20100101");
        s["uaDataPresent"] = json!(false);
        s["engine"] = json!({ "hasMozInnerScreenX": true, "hasChrome": false });
        s.as_object_mut().unwrap().remove("deviceMemory");
        s["active"] = json!({ "devices": { "audioin": 0, "videoin": 0, "audioout": 0 } });
        let r = detect_automation(&s, &opts(None));
        assert!(find(&r, "active_no_media_devices").map_or(true, |c| c.passed));
    }

    fn ff() -> Value {
        let mut s = chrome_human();
        s["ua"] = json!("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0");
        s["productSub"] = json!("20100101");
        s["uaDataPresent"] = json!(false);
        s["engine"] = json!({ "hasMozInnerScreenX": true, "hasChrome": false });
        s.as_object_mut().unwrap().remove("deviceMemory");
        s["evalShape"] = json!({ "nl": true, "len": 45 });
        s["nativeShape"] = json!({ "nl": true, "len": 45 });
        s
    }

    #[test]
    fn chromium_engine_behind_firefox_ua_is_caught() {
        let mut s = ff();
        s["evalShape"] = json!({ "nl": false, "len": 33 });
        assert!(!find(&detect_automation(&s, &opts(None)), "engine_eval_mismatch")
            .unwrap()
            .passed);
    }

    #[test]
    fn firefox_stubbed_enumerate_devices_flagged() {
        let mut s = ff();
        s["active"] = json!({
            "mediaApi": { "md": "object", "ed": "undefined" },
            "devices": { "audioin": 0, "videoin": 0, "audioout": 0 }
        });
        assert!(!find(&detect_automation(&s, &opts(None)), "active_media_api_missing")
            .unwrap()
            .passed);
    }

    #[test]
    fn firefox_real_media_api_with_empty_devices_not_flagged() {
        let mut s = ff();
        s["active"] = json!({
            "mediaApi": { "md": "object", "ed": "function" },
            "devices": { "audioin": 0, "videoin": 0, "audioout": 0 }
        });
        let r = detect_automation(&s, &opts(None));
        assert!(find(&r, "active_no_media_devices").is_none());
        assert!(find(&r, "active_media_api_missing").unwrap().passed);
    }

    #[test]
    fn firefox_live_shaped_probe_has_no_false_positives() {
        let mut s = firefox_human();
        s["evalShape"] = json!({ "nl": true, "len": 45 });
        s["nativeShape"] = json!({ "nl": true, "len": 45 });
        s["mimeCount"] = json!(5);
        s["languages"] = json!({ "lang": "en-US", "langs": ["en-US", "en"] });
        s["chromeShape"] = json!(null);
        s["workerInfo"] = json!({ "ua": s["ua"], "platform": "MacIntel", "hardwareConcurrency": 8 });
        s["platform"] = json!("MacIntel");
        s["active"] = json!({
            "mediaApi": { "md": "object", "ed": "function" },
            "devices": { "audioin": 0, "videoin": 0, "audioout": 0 },
            "rtc": true,
            "media": { "pointerFine": true, "hoverHover": true },
            "permState": "prompt"
        });
        let r = detect_automation(&s, &opts(None));
        assert!(r.pass, "blocked: {:?}", r.blocked_by);
        assert!(r.risk_flags.is_empty(), "flags: {:?}", r.risk_flags);
    }

    #[test]
    fn safari_live_shaped_probe_has_no_false_positives() {
        let mut s = safari_human();
        s["evalShape"] = json!({ "nl": true, "len": 45 });
        s["nativeShape"] = json!({ "nl": true, "len": 45 });
        s["mimeCount"] = json!(2);
        s["languages"] = json!({ "lang": "en-US", "langs": ["en-US", "en"] });
        s["chromeShape"] = json!(null);
        s["workerInfo"] = json!({ "ua": s["ua"], "platform": "MacIntel", "hardwareConcurrency": 8 });
        s["platform"] = json!("MacIntel");
        s["active"] = json!({
            "mediaApi": { "md": "object", "ed": "function" },
            "devices": { "audioin": 0, "videoin": 0, "audioout": 0 },
            "rtc": true,
            "media": { "pointerFine": true, "hoverHover": true }
        });
        assert!(detect_automation(&s, &opts(None)).pass);
    }

    #[test]
    fn chromium_engine_behind_safari_ua_is_caught() {
        let mut s = safari_human();
        s["evalShape"] = json!({ "nl": true, "len": 45 });
        s["nativeShape"] = json!({ "nl": true, "len": 45 });
        s["evalShape"] = json!({ "nl": false, "len": 33 });
        assert!(!find(&detect_automation(&s, &opts(None)), "engine_eval_mismatch")
            .unwrap()
            .passed);
    }

    #[test]
    fn worker_engine_mismatch_and_permission_consistency() {
        let mut s = chrome_human();
        s["evalShape"] = json!({ "nl": false, "len": 33 });
        s["workerInfo"] = json!({ "evalShape": { "nl": true, "len": 45 } });
        assert!(!find(&detect_automation(&s, &opts(None)), "worker_engine_mismatch")
            .unwrap()
            .passed);

        let mut s = chrome_human();
        s["evalShape"] = json!({ "nl": false, "len": 33 });
        s["workerInfo"] = json!({ "evalShape": { "nl": false, "len": 33 } });
        assert!(find(&detect_automation(&s, &opts(None)), "worker_engine_mismatch")
            .unwrap()
            .passed);

        let mut s = chrome_human();
        s["evalShape"] = json!({ "nl": false, "len": 33 });
        s["notifPerm"] = json!("denied");
        s["active"] = json!({ "permState": "prompt" });
        assert!(!find(&detect_automation(&s, &opts(None)), "notif_perm_mismatch")
            .unwrap()
            .passed);

        let mut s = chrome_human();
        s["evalShape"] = json!({ "nl": false, "len": 33 });
        s["notifPerm"] = json!("default");
        s["active"] = json!({ "permState": "prompt" });
        assert!(find(&detect_automation(&s, &opts(None)), "notif_perm_mismatch")
            .unwrap()
            .passed);
    }

    // ---- accept-language -------------------------------------------------

    #[test]
    fn accept_language_cross_check() {
        let mut s = chrome_human();
        s["languages"] = json!({ "lang": "en-US", "langs": ["en-US", "en"] });
        let ok = DetectOpts {
            font_stack_count: None,
            optional_fields: &[],
            accept_language: Some("en-US,en;q=0.9"),
        };
        assert!(find(&detect_automation(&s, &ok), "language_header_mismatch")
            .unwrap()
            .passed);
        let bad = DetectOpts {
            font_stack_count: None,
            optional_fields: &[],
            accept_language: Some("fr-FR,fr;q=0.9"),
        };
        assert!(!find(&detect_automation(&s, &bad), "language_header_mismatch")
            .unwrap()
            .passed);
        assert!(find(&detect_automation(&s, &opts(None)), "language_header_mismatch").is_none());
    }

    // ---- top merge -------------------------------------------------------

    #[test]
    fn top_automation_globals_triggers_gating() {
        let mut s = chrome_human();
        s["top"] = json!({ "automationGlobals": ["__playwright__binding__"] });
        let r = detect_automation(&s, &opts(None));
        assert!(!r.pass);
        assert!(r.blocked_by.iter().any(|b| b == "automation_globals_main"));
    }

    // ---- webgpu ----------------------------------------------------------

    #[test]
    fn webgpu_webgl_cross_validation() {
        let mut s = chrome_human();
        s["webgl"] = json!({
            "ok": true,
            "vendor": "Google Inc. (Apple)",
            "renderer": "ANGLE (Apple, ANGLE Metal Renderer: Apple M1 Pro)"
        });
        s["webgpu"] = json!({ "ok": true, "vendor": "apple" });
        assert!(find(&detect_automation(&s, &opts(None)), "webgpu_webgl_mismatch")
            .unwrap()
            .passed);

        s["webgpu"] = json!({ "ok": true, "vendor": "nvidia" });
        assert!(!find(&detect_automation(&s, &opts(None)), "webgpu_webgl_mismatch")
            .unwrap()
            .passed);

        s["webgpu"] = json!({ "ok": false });
        let r = detect_automation(&s, &opts(None));
        let c = find(&r, "webgpu_absent").unwrap();
        assert!(!c.passed);
        assert!(!c.gating);
    }

    // ---- WebCrypto -------------------------------------------------------

    #[test]
    fn crypto_tamper_is_gating() {
        let mut s = chrome_human();
        s["tamper"]["cryptoSign"] = json!(false);
        let r = detect_automation(&s, &opts(None));
        assert!(!r.pass);
        assert!(r.blocked_by.iter().any(|b| b == "crypto_tampered"));

        let mut s = chrome_human();
        s["tamper"]["cryptoSign"] = json!(true);
        s["tamper"]["cryptoImportKey"] = json!(true);
        s["tamper"]["cryptoDigest"] = json!(true);
        assert!(!detect_automation(&s, &opts(None))
            .blocked_by
            .iter()
            .any(|b| b == "crypto_tampered"));
    }

    // ---- GPU regex regressions -------------------------------------------

    #[test]
    fn gpu_regex_no_false_positives() {
        let mut s = chrome_human();
        s["ua"] = json!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36");
        s["platform"] = json!("Win32");
        s["webgl"] = json!({
            "ok": true,
            "vendor": "Google Inc. (AMD)",
            "renderer": "ANGLE (AMD, AMD Radeon RX 6800 XT Direct3D11 vs_5_0 ps_5_0, D3D11)"
        });
        let r = detect_automation(&s, &opts(None));
        assert!(find(&r, "platform_gpu_mismatch").map_or(true, |c| c.passed));

        let mut s = chrome_human();
        s["platform"] = json!("MacIntel");
        s["webgl"] = json!({
            "ok": true,
            "vendor": "Google Inc. (Intel)",
            "renderer": "ANGLE (Intel, Intel(R) Iris(TM) Plus Graphics OpenGL Engine, OpenGL 4.1)"
        });
        let r = detect_automation(&s, &opts(None));
        assert!(find(&r, "platform_gpu_mismatch").map_or(true, |c| c.passed));
    }

    // ---- sanitize_vector -------------------------------------------------

    #[test]
    fn sanitize_clips_strings_and_arrays() {
        let mut v = json!({
            "ua": "a".repeat(1000),
            "workerUA": "b".repeat(1000),
            "platform": "c".repeat(200),
            "oscpu": "d".repeat(200),
            "productSub": "e".repeat(200),
            "uaData": { "brands": vec!["x"; 40] },
            "webgl": { "renderer": "r".repeat(2000), "vendor": "v".repeat(2000) },
            "languages": vec!["en"; 100],
            "fontWidths": vec![1; 200],
            "automationGlobals": vec!["g"; 100],
            "plugins": { "a": 1, "b": 2 },
            "top": { "plugins": {} }
        });
        sanitize_vector(&mut v);
        assert_eq!(v["ua"].as_str().unwrap().len(), 512);
        assert_eq!(v["workerUA"].as_str().unwrap().len(), 512);
        assert_eq!(v["platform"].as_str().unwrap().len(), 64);
        assert_eq!(v["oscpu"].as_str().unwrap().len(), 64);
        assert_eq!(v["productSub"].as_str().unwrap().len(), 64);
        assert_eq!(v["uaData"]["brands"].as_array().unwrap().len(), 16);
        assert_eq!(v["webgl"]["renderer"].as_str().unwrap().len(), 512);
        assert_eq!(v["webgl"]["vendor"].as_str().unwrap().len(), 256);
        assert_eq!(v["languages"].as_array().unwrap().len(), 32);
        assert_eq!(v["fontWidths"].as_array().unwrap().len(), 64);
        assert_eq!(v["automationGlobals"].as_array().unwrap().len(), 32);
    }

    #[test]
    fn sanitize_keeps_other_shapes_untouched() {
        let mut v = json!({ "ua": null, "plugins": [1, 2, 3], "languages": { "lang": "en" } });
        let before = v.clone();
        sanitize_vector(&mut v);
        assert_eq!(v, before);
    }

    // ---- collect_signals / probe_completeness ---------------------------

    #[test]
    fn collect_signals_drops_unbacked_failures() {
        let checks = vec![
            Check {
                id: "webgl_absent_desktop".into(),
                passed: false,
                detail: "x".into(),
                gating: false,
            },
            Check {
                id: "headless_token".into(),
                passed: false,
                detail: "HeadlessChrome present".into(),
                gating: true,
            },
        ];
        // webgl was never requested nor returned ⇒ dropped.
        let sig = collect_signals(&checks, &[], &json!({}));
        assert_eq!(ids(&sig.iter().map(|s| s.id.clone()).collect::<Vec<_>>()), vec!["headless_token"]);
        assert!(sig[0].gating);

        // webgl returned ⇒ kept.
        let sig = collect_signals(&checks, &[], &json!({ "webgl": { "ok": false } }));
        assert_eq!(sig.len(), 2);
    }

    #[test]
    fn collect_signals_suppresses_optional_only_probe_incomplete() {
        let check = Check {
            id: "probe_incomplete".into(),
            passed: false,
            detail: "missing or malformed: webgl, canvas".into(),
            gating: true,
        };
        assert!(collect_signals(&[check.clone()], &[], &json!({})).is_empty());
        let check2 = Check {
            detail: "missing or malformed: ua, webgl".into(),
            ..check
        };
        let sig = collect_signals(&[check2], &[], &json!({}));
        assert_eq!(sig.len(), 1);
        assert_eq!(sig[0].id, "probe_incomplete");
    }

    #[test]
    fn probe_completeness_reports_missing_and_wrong_length() {
        let mut s = chrome_human();
        s.as_object_mut().unwrap().remove("ua");
        s["fontWidths"] = json!([1, 2]);
        let bad = probe_completeness(&s, Some(17), &[]);
        assert!(bad.iter().any(|b| b == "ua"));
        assert!(bad.iter().any(|b| b == "fontWidths.length"));
        assert!(probe_completeness(&json!([]), None, &[]).contains(&"probe".to_string()));
    }

    #[test]
    fn shape_and_tamper_and_cdp_probe_missing_when_requested() {
        let fields: Vec<String> = ["evalShape", "tamper", "cdp"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let o = DetectOpts {
            font_stack_count: None,
            optional_fields: &fields,
            accept_language: None,
        };
        let mut s = chrome_human();
        s.as_object_mut().unwrap().remove("tamper");
        let r = detect_automation(&s, &o);
        assert!(r.blocked_by.iter().any(|b| b == "shape_probe_missing"));
        assert!(r.blocked_by.iter().any(|b| b == "tamper_probe_missing"));
        assert!(r.blocked_by.iter().any(|b| b == "crypto_probe_missing"));
        assert!(r.blocked_by.iter().any(|b| b == "cdp_probe_missing"));
        assert!(!r.pass);
    }

    #[test]
    fn worker_probe_missing_is_weak() {
        let fields = vec!["workerInfo".to_string()];
        let o = DetectOpts {
            font_stack_count: None,
            optional_fields: &fields,
            accept_language: None,
        };
        let r = detect_automation(&chrome_human(), &o);
        assert!(r.risk_flags.iter().any(|b| b == "worker_probe_missing"));
        assert!(!r.blocked_by.iter().any(|b| b == "worker_probe_missing"));
        let c = find(&r, "worker_probe_missing").unwrap();
        assert!(!c.gating);
    }

    #[test]
    fn render_pipeline_absent_when_all_requested_probes_fail() {
        let fields = vec!["webgl".to_string(), "canvas".to_string()];
        let o = DetectOpts {
            font_stack_count: None,
            optional_fields: &fields,
            accept_language: None,
        };
        let mut s = chrome_human();
        s["webgl"] = json!({ "ok": false });
        s["canvas"] = json!("");
        let r = detect_automation(&s, &o);
        assert!(!find(&r, "render_pipeline_absent").unwrap().passed);
    }

    #[test]
    fn signals_convert_back_to_borrowed_signal() {
        let mut s = chrome_human();
        s["webdriver"] = json!(true);
        let r = detect_automation(&s, &opts(None));
        assert!(r.signals.iter().any(|x| x.id == "webdriver_true" && x.gating));
        let borrowed: Vec<Signal<'_>> = r.signals.iter().map(|s| s.as_signal()).collect();
        assert_eq!(borrowed[0].id, "webdriver_true");
    }

    // ---- hostile input / no panics ---------------------------------------

    #[test]
    fn hostile_json_does_not_panic() {
        let values = vec![
            Value::Null,
            json!(true),
            json!(7),
            json!("string"),
            json!([]),
            json!([1, 2, 3]),
            json!({ "ua": [], "screen": [], "outerWH": {}, "innerWH": "x" }),
            json!({ "ua": 5, "platform": [], "engine": [], "plugins": [] }),
            json!({
                "top": { "automationGlobals": "nope", "webgl": [], "innerWH": 4, "canvas": 7 },
                "outerWH": [null, "x", 1e300],
                "innerWH": [1e308, -1e308],
                "screen": { "width": "big", "height": null },
                "fontWidths": [1, "x", null, [], {}],
                "tamper": { "a": 1, "b": null },
                "uaData": { "brands": [1, {}, []] },
                "languages": { "lang": 5, "langs": [1, "en"] },
                "active": { "devices": { "audioin": "3", "videoin": [], "audioout": {} } },
                "emoji": { "style": 5, "width": "wide" },
                "webgl": { "ok": "yes", "hash": 5, "renderer": {}, "vendor": [] },
                "webgpu": { "ok": true, "vendor": {}, "description": [] },
                "workerInfo": { "evalShape": [], "platform": 5 },
                "cdp": { "tap": "3" },
            }),
            json!({ "fontWidths": vec![1e308; 500] }),
        ];
        for v in values {
            let _ = detect_automation(&v, &opts(Some(17)));
            let fields = full_fields();
            let _ = detect_automation(
                &v,
                &DetectOpts {
                    font_stack_count: Some(17),
                    optional_fields: &fields,
                    accept_language: Some("en-US,en;q=0.9,*"),
                },
            );
            let mut c = v.clone();
            sanitize_vector(&mut c);
            let _ = probe_completeness(&c, Some(17), &fields);
            let _ = collect_signals(&[], &fields, &c);
        }
    }

    // ---- fixture parity against the JS reference -------------------------

    /// `cap-rust/` (two levels above `crates/detect`).
    fn workspace_root() -> std::path::PathBuf {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        manifest.join("..").join("..")
    }

    /// The vendored reference detector (`crates/detect/testdata/js/detect.js`),
    /// falling back to the sibling Cap checkout for local development.
    fn js_reference_path() -> Option<std::path::PathBuf> {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let vendored = manifest.join("testdata").join("js").join("detect.js");
        if vendored.is_file() {
            if let Ok(p) = vendored.canonicalize() {
                return Some(p);
            }
        }
        workspace_root()
            .join("..")
            .join("cap")
            .join("core")
            .join("src")
            .join("detect.js")
            .canonicalize()
            .ok()
    }

    fn bun_available() -> bool {
        std::process::Command::new("bun")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Run the JS reference `detectAutomation` on `probe` and compare ids,
    /// `passed`, gating, `blockedBy`, `riskFlags` and `pass` with the Rust port.
    /// Returns `false` (without failing) when bun or the JS tree is missing.
    /// `None` means the JS reference or bun is unavailable (skip), `Some(ok)`
    /// is the comparison result.
    fn compare_with_js(
        probe: &Value,
        optional: &[String],
        font_stack: usize,
        accept_language: Option<&str>,
    ) -> Option<bool> {
        use std::process::Command;

        let js = match js_reference_path() {
            Some(p) => p,
            None => {
                parity_required("JS reference not found");
                return None;
            }
        };
        if !bun_available() {
            parity_required("bun not installed");
            return None;
        }

        let optional_js = optional
            .iter()
            .map(|s| serde_json::to_string(s).unwrap())
            .collect::<Vec<_>>()
            .join(",");
        let mut js_opts = format!(
            "fontStackCount: {font_stack}, optionalFields: [{optional_js}]"
        );
        if let Some(al) = accept_language {
            js_opts.push_str(&format!(", acceptLanguage: {}", serde_json::to_string(al).unwrap()));
        }
        let script = format!(
            "import {{detectAutomation}} from {};\n\
             const p = {};\n\
             console.log(JSON.stringify(detectAutomation(p, {{{js_opts}}})));",
            serde_json::to_string(js.to_str().unwrap()).unwrap(),
            serde_json::to_string(probe).unwrap(),
        );
        let out = Command::new("bun")
            .arg("-e")
            .arg(&script)
            .output()
            .expect("run bun");
        assert!(
            out.status.success(),
            "bun failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let reference: Value =
            serde_json::from_slice(&out.stdout).expect("parse reference json");

        let o = DetectOpts {
            font_stack_count: Some(font_stack),
            optional_fields: optional,
            accept_language,
        };
        let ours = detect_automation(probe, &o);

        let js_checks = reference["checks"].as_array().expect("checks array");
        assert_eq!(js_checks.len(), ours.checks.len(), "check count mismatch");
        for (i, (jc, rc)) in js_checks.iter().zip(&ours.checks).enumerate() {
            assert_eq!(jc["id"].as_str().unwrap(), rc.id, "check #{i} id mismatch");
            assert_eq!(
                jc["passed"].as_bool().unwrap(),
                rc.passed,
                "check {} passed mismatch",
                rc.id
            );
            assert_eq!(
                jc["gating"].as_bool().unwrap(),
                rc.gating,
                "check {} gating mismatch",
                rc.id
            );
        }
        let js_blocked: Vec<&str> = reference["blockedBy"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(js_blocked, ids(&ours.blocked_by), "blockedBy mismatch");
        let js_flags: Vec<&str> = reference["riskFlags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(js_flags, ids(&ours.risk_flags), "riskFlags mismatch");
        assert_eq!(
            reference["pass"].as_bool().unwrap(),
            ours.pass,
            "pass mismatch"
        );
        eprintln!(
            "parity OK: {} checks, blockedBy={:?}, riskFlags={:?}",
            ours.checks.len(),
            ours.blocked_by,
            ours.risk_flags
        );
        Some(true)
    }

    /// Golden-fixture parity: the real captured probe must produce exactly the
    /// reference result (same check ids, `passed`, gating, blockedBy, flags).
    #[test]
    fn fixture_parity_with_js_reference() {
        let fixture_path = workspace_root().join("golden").join("instr-sample.json");
        let raw = match std::fs::read(&fixture_path) {
            Ok(b) => b,
            Err(_) => {
                parity_required("golden fixture not found");
                return;
            }
        };
        let fixture: Value = serde_json::from_slice(&raw).unwrap();
        let mut p = fixture["instr"]["p"].clone();
        if let Some(top) = fixture["instr"].get("top") {
            p["top"] = top.clone();
        }
        let Some(ok) = compare_with_js(&p, &full_fields(), PROBE_FONT_STACK_COUNT, None) else {
            parity_required("parity harness unavailable");
            return;
        };
        assert!(ok, "parity mismatch against the JS reference");
        // Sanity: this fixture is a headless Chrome and must be blocked on it.
        let r = detect_automation(
            &p,
            &DetectOpts {
                font_stack_count: Some(PROBE_FONT_STACK_COUNT),
                optional_fields: &full_fields(),
                accept_language: None,
            },
        );
        assert_eq!(ids(&r.blocked_by), vec!["headless_token"]);
    }

    /// A live-shaped Windows Chrome probe whose render probes live in `top`.
    fn synthetic_base() -> Value {
        json!({
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
            "productSub": "20030107",
            "webdriver": false,
            "oscpu": "__undefined",
            "deviceMemory": 8,
            "uaDataPresent": true,
            "uaData": { "mobile": false, "brands": ["Google Chrome/151", "Chromium/151"] },
            "plugins": { "length": 5 },
            "engine": { "hasMozInnerScreenX": false, "hasChrome": true },
            "evalShape": { "nl": false, "len": 33 },
            "nativeShape": { "nl": false, "len": 40 },
            "mimeCount": 5,
            "languages": { "lang": "en-US", "langs": ["en-US", "en"] },
            "chromeShape": { "runtime": true },
            "notifPerm": "denied",
            "platform": "Win32",
            "hardwareConcurrency": 8,
            "workerUA": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
            "workerInfo": { "platform": "Win32", "hardwareConcurrency": 8, "deviceMemory": 8, "evalShape": { "nl": false } },
            "screen": { "width": 1920, "height": 1080 },
            "innerWH": [1920, 1080],
            "outerWH": [1920, 1040],
            "isExtended": false,
            "canvasStable": true,
            "fontWidths": [1200.88, 1204.05, 1207.22, 1210.39, 1213.56, 1216.73, 1219.9, 1223.07, 1226.24, 1229.41, 1232.58, 1235.75, 1238.92, 1242.09, 1245.26, 1248.43, 1251.6],
            "tamper": { "getParameterWebGL": true, "toDataURL": true, "getImageData": true, "permissionsQuery": true, "fnToString": true, "cryptoSign": true, "cryptoImportKey": true, "cryptoDigest": true },
            "cdp": { "tap": 0, "objTap": 0, "stackTap": 0, "protoTap": 0, "dbgPause": false, "errPrep": false, "aut": 0 },
            "active": {
                "mediaApi": { "md": "object", "ed": "function" },
                "devices": { "audioin": 1, "videoin": 1, "audioout": 2 },
                "codecs": { "mp4": "probably", "webm": "probably" },
                "rtc": true,
                "media": { "pointerFine": true, "hoverHover": true },
                "permState": "denied"
            },
            "webgpu": { "ok": true, "vendor": "Google Inc. (AMD)" },
            "top": {
                "webgl": { "ok": true, "vendor": "Google Inc. (AMD)", "renderer": "ANGLE (AMD, AMD Radeon RX 6800 XT Direct3D11 vs_5_0 ps_5_0, D3D11)", "webgl2": true, "hash": "fa1b2c3d4e5f" },
                "canvas": "f77d8974",
                "emoji": { "style": "windows-like", "width": 92 },
                "audio": 0.002,
                "storageQuota": 107374182400i64,
                "automationGlobals": []
            }
        })
    }

    /// Second parity scenario: supplements really do flow through `top` (the
    /// signed probe leaves webgl/canvas/emoji absent, so `top` wins), plus the
    /// GPU / emoji / active / cdp branches.
    #[test]
    fn synthetic_parity_with_js_reference() {
        let Some(ok) = compare_with_js(
            &synthetic_base(),
            &full_fields(),
            PROBE_FONT_STACK_COUNT,
            Some("en-US,en;q=0.9"),
        ) else {
            parity_required("parity harness unavailable");
            return;
        };
        assert!(ok, "parity mismatch against the JS reference");
    }

    /// Bot-shaped mutations of the same probe: every failing (non-gating and
    /// gating) branch must agree with the reference too.
    #[test]
    fn synthetic_bot_parity_with_js_reference() {
        let mut cases: Vec<Value> = Vec::new();

        // Software rasterizer + degenerate canvas + no emoji glyphs.
        let mut v = synthetic_base();
        v["top"]["webgl"] = json!({ "ok": true, "vendor": "Google Inc.", "renderer": "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)))", "webgl2": false, "hash": "" });
        v["top"]["canvas"] = json!("0000");
        v["top"]["emoji"] = json!({ "style": "noto", "width": 0 });
        cases.push(v);

        // Live CDP attachment.
        let mut v = synthetic_base();
        v["cdp"] = json!({ "tap": 4, "objTap": 3, "stackTap": 2, "protoTap": 1, "dbgPause": true, "errPrep": true, "aut": 1 });
        cases.push(v);

        // Broken active capability probes.
        let mut v = synthetic_base();
        v["active"] = json!({
            "mediaApi": { "md": "object", "ed": "undefined" },
            "devices": { "audioin": 0, "videoin": 0, "audioout": 0 },
            "codecs": { "mp4": "", "webm": "" },
            "rtc": false,
            "media": { "pointerFine": false, "hoverHover": false },
            "permState": "prompt",
            "permError": true
        });
        v["notifPerm"] = json!("denied");
        cases.push(v);

        // macOS UA behind a D3D GPU, quantized fonts, hollow window.chrome.
        let mut v = synthetic_base();
        v["ua"] = json!("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36");
        v["platform"] = json!("MacIntel");
        v["top"]["webgl"] = json!({ "ok": true, "vendor": "Google Inc. (NVIDIA)", "renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0, D3D11)", "webgl2": true, "hash": "0123456789ab" });
        v["fontWidths"] = ints(17);
        v["chromeShape"] = json!({ "runtime": false });
        v["hardwareConcurrency"] = json!(1);
        cases.push(v);

        // Android UA with an Apple GPU, a lone core and a tiny quota.
        let mut v = synthetic_base();
        v["ua"] = json!("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36");
        v["uaData"] = json!({ "mobile": true, "brands": ["Google Chrome/151"] });
        v["platform"] = json!("Linux armv8l");
        v["top"]["webgl"] = json!({ "ok": true, "vendor": "Apple", "renderer": "ANGLE (Apple, ANGLE Metal Renderer: Apple M1)", "webgl2": true, "hash": "fa1b2c3d4e5f" });
        v["hardwareConcurrency"] = json!(1);
        v["top"]["storageQuota"] = json!(4096);
        v["webgpu"] = json!({ "ok": true, "vendor": "nvidia" });
        cases.push(v);

        for case in &cases {
            let Some(ok) = compare_with_js(case, &full_fields(), PROBE_FONT_STACK_COUNT, None)
            else {
                parity_required("parity harness unavailable");
                return;
            };
            assert!(ok, "parity mismatch against the JS reference");
        }
    }
}
