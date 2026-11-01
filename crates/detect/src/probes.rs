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

mod detect;
mod support;
#[cfg(test)]
mod tests;

pub use detect::*;
pub use support::*;
