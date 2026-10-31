//! Trust ("credit score") computation — port of `core/src/trust.js`.
//!
//! A client starts at a base score of 100. Instrumentation/consistency signals,
//! optional network-layer findings and a hard-detector verdict each subtract
//! points. The final score is clamped to `0..=100` and mapped to a level.
//! `trust_action` turns that into the coarse decision the server enforces:
//! gating signals (except `probe_incomplete`) and any score below 60 are denied.

use serde::{Deserialize, Serialize};

pub mod probes;
pub use probes::{
    collect_signals, detect_automation, geometry_stats, probe_completeness, sanitize_vector, Check,
    DetectOpts, DetectOutcome, GeometryStats, OwnedSignal, PROBE_FONT_STACK_COUNT,
};

/// Per-signal penalty table, copied verbatim from `SIGNAL_PENALTY` in
/// `core/src/trust.js`. Order is preserved. Unknown ids fall back to
/// [`DEFAULT_PENALTY`].
pub const SIGNAL_PENALTY: &[(&str, i32)] = &[
    ("probe_incomplete", 40),
    ("probe_missing", 60),
    ("webdriver_true", 55),
    ("webdriver_stripped", 45),
    ("cdp_console_trap", 45),
    ("cdp_debugger_pause", 50),
    ("cdp_stack_tamper", 20),
    ("cdp_automation_globals", 25),
    ("cdp_console_object_trap", 45),
    ("cdp_stack_getter", 45),
    ("cdp_proto_getter", 40),
    ("engine_eval_mismatch", 25),
    ("native_shape_inconsistent", 20),
    ("productsub_mismatch", 20),
    ("plugins_mime_mismatch", 12),
    ("language_not_in_languages", 6),
    ("language_header_mismatch", 6),
    ("chrome_shape_hollow", 15),
    ("worker_hw_mismatch", 30),
    ("worker_mem_mismatch", 20),
    ("worker_platform_mismatch", 20),
    ("worker_engine_mismatch", 20),
    ("notif_perm_mismatch", 12),
    ("canvas_unstable", 25),
    ("active_media_api_missing", 15),
    ("active_no_media_devices", 12),
    ("active_no_video_codecs", 12),
    ("active_no_rtc", 8),
    ("active_permissions_error", 10),
    ("active_no_fine_pointer", 8),
    ("automation_globals_main", 50),
    ("headless_token", 50),
    ("native_tamper", 18),
    ("crypto_tampered", 60),
    ("crypto_probe_missing", 45),
    ("tamper_probe_missing", 25),
    ("cdp_probe_missing", 20),
    ("shape_probe_missing", 15),
    ("worker_probe_missing", 6),
    ("widget_self_tampered", 40),
    ("geometry_quantized", 14),
    ("gecko_contradiction", 30),
    ("window_exceeds_screen", 14),
    ("viewport_override", 18),
    ("worker_ua_mismatch", 30),
    ("platform_gpu_mismatch", 28),
    ("webgl_software_renderer", 18),
    ("webgl_absent_desktop", 15),
    ("webgl_render_probe", 10),
    ("webgl2_absent_on_chromium", 8),
    ("canvas_degenerate", 16),
    ("render_pipeline_absent", 25),
    ("audio_silent", 8),
    ("emoji_no_render", 6),
    ("emoji_os_mismatch", 10),
    ("hardware_shape", 8),
    ("hw_mem_mismatch", 10),
    ("storage_quota_tiny", 10),
    ("honeypot_triggered", 100),
    ("widget_hash_mismatch", 10),
    ("webgpu_webgl_mismatch", 22),
    ("webgpu_absent", 6),
];

/// Network-layer signal penalties (JA3/JA4/HTTP2), supplied by the server.
pub const NETWORK_PENALTY: &[(&str, i32)] = &[
    ("ja4_non_browser", 35),
    ("ja3_non_browser", 30),
    ("http2_non_browser", 22),
    ("tls_missing", 8),
    ("alpn_non_browser", 12),
    ("ua_ja_mismatch", 25),
];

/// Penalty applied to any signal id not present in [`SIGNAL_PENALTY`].
pub const DEFAULT_PENALTY: i32 = 5;

/// Base score before any penalty (the JS `input.base` default).
pub const BASE_SCORE: i32 = 100;

/// Penalty applied when the hard detector failed.
pub const PROBE_FAILED_PENALTY: i32 = 30;

fn signal_penalty(id: &str) -> i32 {
    SIGNAL_PENALTY
        .iter()
        .find(|(k, _)| *k == id)
        .map(|(_, v)| *v)
        .unwrap_or(DEFAULT_PENALTY)
}

fn network_penalty(id: &str) -> i32 {
    NETWORK_PENALTY
        .iter()
        .find(|(k, _)| *k == id)
        .map(|(_, v)| *v)
        .expect("network penalty ids are static")
}

/// Protocol-layer findings consumed by `computeTrust({ network })` in
/// `core/src/trust.js` (built by `networkTrustInput` in
/// `standalone/src/networkfp.js`).
///
/// Only `Some(_)` values are meaningful: JS distinguishes `undefined` (no data,
/// ignored) from `false` (a real negative finding), so every flag is optional.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NetworkSignals {
    /// `false` ⇒ TLS was not used (`tls_missing`).
    pub tls: Option<bool>,
    /// `false` ⇒ JA4 fingerprint is not a known browser (`ja4_non_browser`).
    pub ja4_browser: Option<bool>,
    /// `false` ⇒ JA3 is not a known browser; ignored when JA4 already failed.
    pub ja3_browser: Option<bool>,
    /// `false` ⇒ HTTP/2 SETTINGS are not a known browser (`http2_non_browser`).
    pub http2_browser: Option<bool>,
    /// `true` ⇒ UA contradicts the TLS fingerprint (`ua_ja_mismatch`).
    pub ua_mismatch: Option<bool>,
}

/// One instrumentation/consistency signal.
///
/// `trust.js` accepts both `["id"]` and `[{id, gating}]`; plain strings never
/// gate. The string form is [`TrustInput::signals`]; this richer form is used by
/// [`compute_trust_signals`].
#[derive(Debug, Clone, Copy)]
pub struct Signal<'a> {
    pub id: &'a str,
    pub gating: bool,
}

impl<'a> Signal<'a> {
    /// Non-gating signal (`"id"`).
    pub fn new(id: &'a str) -> Self {
        Signal { id, gating: false }
    }

    /// Gating signal (`{id, gating: true}`).
    pub fn gating(id: &'a str) -> Self {
        Signal { id, gating: true }
    }
}

/// Input to [`compute_trust`]. Mirrors
/// `computeTrust({signals, network, probePassed})`.
///
/// The JS `base` override is intentionally not exposed: the server always uses
/// the default base of 100.
#[derive(Debug, Clone, Copy)]
pub struct TrustInput<'a> {
    pub signals: &'a [String],
    pub network: Option<&'a NetworkSignals>,
    pub probe_passed: Option<bool>,
}

/// Coarse reputation bucket (see `levelFor` in `trust.js`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// `score >= 80` (JS `trusted`).
    Clean,
    /// `30 <= score < 80` (JS `neutral` / `suspicious`).
    Restricted,
    /// `score < 30` (JS `hostile`).
    Hostile,
}

impl Level {
    fn for_score(score: i32) -> Level {
        if score >= 80 {
            Level::Clean
        } else if score >= 30 {
            Level::Restricted
        } else {
            Level::Hostile
        }
    }
}

/// One line item contributing to (or explaining) the score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reason {
    pub id: String,
    pub penalty: i32,
    pub gating: bool,
}

/// Result of [`compute_trust`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Trust {
    pub score: i32,
    pub level: Level,
    pub reasons: Vec<Reason>,
    pub gating_failure: bool,
}

/// Recommended action. `trust.js` has four tiers; only the decisive ones are
/// kept here (every non-`deny` tier collapses into `allow`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

/// Compute a trust result from plain signal ids (never gating).
pub fn compute_trust(input: &TrustInput) -> Trust {
    let signals: Vec<Signal> = input
        .signals
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| Signal::new(s.as_str()))
        .collect();
    compute_trust_signals(&signals, input.network, input.probe_passed)
}

/// Same as [`compute_trust`] but accepts gating signals, mirroring
/// `computeTrust({signals: [{id, gating}]})`.
pub fn compute_trust_signals(
    signals: &[Signal],
    network: Option<&NetworkSignals>,
    probe_passed: Option<bool>,
) -> Trust {
    let mut score = BASE_SCORE;
    let mut reasons: Vec<Reason> = Vec::new();
    let mut gating_failure = false;

    // Dedupe by id: the same signal firing twice must not double-penalize.
    // A later gating duplicate still escalates gating on the existing reason.
    let mut seen: Vec<&str> = Vec::new();
    for sig in signals.iter().filter(|s| !s.id.is_empty()) {
        if seen.contains(&sig.id) {
            if sig.gating {
                gating_failure = true;
                if let Some(existing) = reasons.iter_mut().find(|r| r.id == sig.id) {
                    existing.gating = true;
                }
            }
            continue;
        }
        seen.push(sig.id);

        let penalty = signal_penalty(sig.id);
        score -= penalty;
        reasons.push(Reason {
            id: sig.id.to_string(),
            penalty,
            gating: sig.gating,
        });
        if sig.gating {
            gating_failure = true;
        }
    }

    if let Some(net) = network {
        let push_net = |score: &mut i32, reasons: &mut Vec<Reason>, id: &str| {
            let penalty = network_penalty(id);
            *score -= penalty;
            reasons.push(Reason {
                id: id.to_string(),
                penalty,
                gating: false,
            });
        };
        if net.tls == Some(false) {
            push_net(&mut score, &mut reasons, "tls_missing");
        }
        if net.ja4_browser == Some(false) {
            push_net(&mut score, &mut reasons, "ja4_non_browser");
        }
        // JA3 is only consulted when JA4 did not already fail.
        if net.ja3_browser == Some(false) && net.ja4_browser != Some(false) {
            push_net(&mut score, &mut reasons, "ja3_non_browser");
        }
        if net.http2_browser == Some(false) {
            push_net(&mut score, &mut reasons, "http2_non_browser");
        }
        if net.ua_mismatch == Some(true) {
            push_net(&mut score, &mut reasons, "ua_ja_mismatch");
        }
    }

    // A hard-detector failure is decisive even if few weighted signals fired.
    if probe_passed == Some(false) && !gating_failure {
        score -= PROBE_FAILED_PENALTY;
        reasons.push(Reason {
            id: "probe_failed".to_string(),
            penalty: PROBE_FAILED_PENALTY,
            gating: true,
        });
        gating_failure = true;
    }

    score = score.clamp(0, 100);

    // A gating signal caps the level at "restricted" (JS: at most suspicious).
    let mut level = Level::for_score(score);
    if gating_failure && level == Level::Clean {
        level = Level::Restricted;
    }

    Trust {
        score,
        level,
        reasons,
        gating_failure,
    }
}

/// Map a trust result to a coarse decision.
///
/// Mirrors `trustAction`: any gating reason other than `probe_incomplete` is
/// decisive, as is any score below 60. Everything else is allowed (the JS
/// `interact`/`restrict` tiers are advisory and collapse into allow here).
pub fn trust_action(trust: &Trust) -> Action {
    let gating_deny = trust
        .reasons
        .iter()
        .any(|r| r.gating && r.id != "probe_incomplete");
    if gating_deny {
        return Action::Deny;
    }
    if trust.score < 60 {
        return Action::Deny;
    }
    Action::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sigs(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    fn run(ids: &[&str], probe: Option<bool>) -> Trust {
        let owned = sigs(ids);
        compute_trust(&TrustInput {
            signals: &owned,
            network: None,
            probe_passed: probe,
        })
    }

    // ---- ports of core/test/trust.test.js -------------------------------

    #[test]
    fn clean_client_scores_100_and_is_trusted() {
        let t = run(&[], Some(true));
        assert_eq!(t.score, 100);
        assert_eq!(t.level, Level::Clean);
        assert!(!t.gating_failure);
        assert_eq!(trust_action(&t), Action::Allow);
    }

    #[test]
    fn gating_signal_forces_at_most_restricted() {
        let t = compute_trust_signals(&[Signal::gating("webdriver_true")], None, Some(false));
        assert!(t.gating_failure);
        assert!(t.score < 80);
        assert_ne!(t.level, Level::Clean);
        assert!(t.reasons.iter().any(|r| r.id == "webdriver_true"));
        // Exact: base 100 - webdriver_true 55; probe_failed skipped (already gating).
        assert_eq!(t.score, 45);
        assert_eq!(t.level, Level::Restricted);
        assert_eq!(trust_action(&t), Action::Deny);
    }

    #[test]
    fn string_signals_are_accepted() {
        let t = run(&["native_tamper"], None);
        assert!(t.reasons.iter().any(|r| r.id == "native_tamper"));
        assert!(t.score < 100);
        assert_eq!(t.score, 82);
        assert_eq!(t.level, Level::Clean);
    }

    #[test]
    fn platform_gpu_mismatch_penalizes_heavily() {
        let a = run(&[], None);
        let b = run(&["platform_gpu_mismatch"], None);
        assert!(a.score - b.score >= 20);
        assert_eq!(a.score - b.score, 28);
        assert_eq!(b.score, 72);
    }

    #[test]
    fn network_signals_feed_into_the_score() {
        let clean = compute_trust(&TrustInput {
            signals: &[],
            network: Some(&NetworkSignals::default()),
            probe_passed: None,
        });
        let bad = compute_trust(&TrustInput {
            signals: &[],
            network: Some(&NetworkSignals {
                ja4_browser: Some(false),
                http2_browser: Some(false),
                ..Default::default()
            }),
            probe_passed: None,
        });
        assert!(bad.score < clean.score);
        assert_eq!(clean.score, 100);
        assert_eq!(bad.score, 100 - 35 - 22);
        let ids: Vec<&str> = bad.reasons.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"ja4_non_browser"));
        assert!(ids.contains(&"http2_non_browser"));
    }

    #[test]
    fn probe_passed_false_alone_drags_the_score_down() {
        let t = run(&[], Some(false));
        assert!(t.gating_failure);
        assert!(t.score < 80);
        assert!(t.reasons.iter().any(|r| r.id == "probe_failed"));
        assert_eq!(t.score, 70);
        assert_eq!(t.level, Level::Restricted);
        // probe_failed is gating ⇒ denied.
        assert_eq!(trust_action(&t), Action::Deny);
    }

    #[test]
    fn score_is_clamped_to_0_100() {
        let t = run(
            &[
                "webdriver_true",
                "headless_token",
                "probe_missing",
                "native_tamper",
                "worker_ua_mismatch",
                "platform_gpu_mismatch",
                "canvas_degenerate",
            ],
            Some(false),
        );
        assert!((0..=100).contains(&t.score));
        assert_eq!(t.score, 0);
        assert_eq!(t.level, Level::Hostile);
        assert_eq!(trust_action(&t), Action::Deny);
    }

    #[test]
    fn many_weak_signals_accumulate() {
        let t = run(
            &[
                "hardware_shape",
                "hw_mem_mismatch",
                "storage_quota_tiny",
                "audio_silent",
                "emoji_os_mismatch",
            ],
            None,
        );
        assert!(t.score < 80);
        assert_eq!(t.score, 100 - 8 - 10 - 10 - 8 - 10);
        assert_eq!(t.score, 54);
        assert_eq!(t.level, Level::Restricted);
    }

    #[test]
    fn trust_action_maps_levels_to_tiers() {
        // Clean ⇒ allow.
        assert_eq!(
            trust_action(&Trust {
                score: 100,
                level: Level::Clean,
                reasons: vec![],
                gating_failure: false,
            }),
            Action::Allow
        );
        // Neutral (60..79) is allowed by score; the JS "interact" tier collapses.
        assert_eq!(
            trust_action(&Trust {
                score: 70,
                level: Level::Restricted,
                reasons: vec![],
                gating_failure: false,
            }),
            Action::Allow
        );
        // Restricted below 60 ⇒ deny.
        assert_eq!(
            trust_action(&Trust {
                score: 45,
                level: Level::Restricted,
                reasons: vec![],
                gating_failure: false,
            }),
            Action::Deny
        );
        // Hostile ⇒ deny.
        assert_eq!(
            trust_action(&Trust {
                score: 10,
                level: Level::Hostile,
                reasons: vec![],
                gating_failure: false,
            }),
            Action::Deny
        );
    }

    // ---- extra edge cases ----------------------------------------------

    #[test]
    fn empty_signals_and_no_probe_is_100() {
        let t = run(&[], None);
        assert_eq!(t.score, 100);
        assert_eq!(t.level, Level::Clean);
        assert!(t.reasons.is_empty());
        assert!(!t.gating_failure);
        assert_eq!(trust_action(&t), Action::Allow);
    }

    #[test]
    fn all_unknown_ids_score_5_each() {
        let t = run(&["nope_one", "nope_two", "nope_three"], None);
        assert_eq!(t.score, 85);
        for r in &t.reasons {
            assert_eq!(r.penalty, DEFAULT_PENALTY);
        }
        assert_eq!(t.reasons.len(), 3);
        assert_eq!(t.level, Level::Clean);
    }

    #[test]
    fn empty_strings_are_ignored() {
        let t = run(&["", ""], None);
        assert_eq!(t.score, 100);
        assert!(t.reasons.is_empty());
    }

    #[test]
    fn duplicate_ids_are_deduplicated() {
        let t = run(
            &["canvas_unstable", "canvas_unstable", "canvas_unstable"],
            None,
        );
        assert_eq!(t.reasons.len(), 1);
        assert_eq!(t.score, 100 - 25);
    }

    #[test]
    fn duplicate_gating_merge_escalates_existing_reason() {
        let t = compute_trust_signals(
            &[
                Signal::new("headless_token"),
                Signal::gating("headless_token"),
            ],
            None,
            None,
        );
        assert_eq!(t.reasons.len(), 1);
        assert!(t.reasons[0].gating);
        assert!(t.gating_failure);
        assert_eq!(t.score, 50);
        assert_eq!(trust_action(&t), Action::Deny);
    }

    #[test]
    fn gating_with_high_score_caps_level_and_denies() {
        // Unknown id (5) marked gating leaves the score at 95 but gating wins.
        let t = compute_trust_signals(&[Signal::gating("mystery_signal")], None, Some(true));
        assert_eq!(t.score, 95);
        assert_eq!(t.level, Level::Restricted);
        assert!(t.gating_failure);
        assert_eq!(trust_action(&t), Action::Deny);
    }

    #[test]
    fn probe_incomplete_gating_is_not_decisive() {
        // 100 - 40 = 60 ⇒ allowed by score even though the signal gates.
        let t = compute_trust_signals(&[Signal::gating("probe_incomplete")], None, Some(false));
        assert!(t.gating_failure);
        assert_eq!(t.score, 60);
        assert_eq!(t.level, Level::Restricted);
        assert_eq!(trust_action(&t), Action::Allow);
    }

    #[test]
    fn score_floor_is_zero() {
        let t = run(&["honeypot_triggered", "crypto_tampered"], None);
        assert_eq!(t.score, 0);
        assert_eq!(t.level, Level::Hostile);
    }

    #[test]
    fn score_ceiling_is_100() {
        let t = run(&[], Some(true));
        assert_eq!(t.score, 100);
    }

    #[test]
    fn network_ja3_skipped_when_ja4_fails() {
        let t = compute_trust(&TrustInput {
            signals: &[],
            network: Some(&NetworkSignals {
                ja3_browser: Some(false),
                ja4_browser: Some(false),
                ..Default::default()
            }),
            probe_passed: None,
        });
        let ids: Vec<&str> = t.reasons.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"ja4_non_browser"));
        assert!(!ids.contains(&"ja3_non_browser"));
        assert_eq!(t.score, 100 - 35);
    }

    #[test]
    fn network_tls_and_ua_mismatch() {
        let t = compute_trust(&TrustInput {
            signals: &[],
            network: Some(&NetworkSignals {
                tls: Some(false),
                ua_mismatch: Some(true),
                ..Default::default()
            }),
            probe_passed: None,
        });
        assert_eq!(t.score, 100 - 8 - 25);
        assert_eq!(t.reasons.len(), 2);
        assert!(!t.gating_failure);
    }

    #[test]
    fn network_default_and_none_are_equal() {
        let a = compute_trust(&TrustInput {
            signals: &[],
            network: Some(&NetworkSignals::default()),
            probe_passed: Some(true),
        });
        let b = run(&[], Some(true));
        assert_eq!(a.score, b.score);
        assert_eq!(a.reasons, b.reasons);
    }

    #[test]
    fn network_signals_deserialize_from_camel_case() {
        let net: NetworkSignals = serde_json::from_str(
            r#"{"tls": false, "ja4Browser": false, "ja3Browser": true,
                "http2Browser": false, "uaMismatch": true, "extra": 1}"#,
        )
        .unwrap();
        assert_eq!(net.tls, Some(false));
        assert_eq!(net.ja4_browser, Some(false));
        assert_eq!(net.ja3_browser, Some(true));
        assert_eq!(net.http2_browser, Some(false));
        assert_eq!(net.ua_mismatch, Some(true));

        let empty: NetworkSignals = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, NetworkSignals::default());
    }

    #[test]
    fn trust_serializes_camel_case() {
        let t = run(&["native_tamper"], Some(false));
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["score"], serde_json::json!(52));
        assert_eq!(v["level"], serde_json::json!("restricted"));
        assert_eq!(v["gatingFailure"], serde_json::json!(true));
        assert_eq!(v["reasons"][0]["id"], serde_json::json!("native_tamper"));
        assert_eq!(v["reasons"][0]["penalty"], serde_json::json!(18));
        assert_eq!(v["reasons"][0]["gating"], serde_json::json!(false));
    }

    #[test]
    fn no_panic_on_large_signal_lists() {
        let owned: Vec<String> = (0..1000).map(|i| format!("sig_{i}")).collect();
        let t = compute_trust(&TrustInput {
            signals: &owned,
            network: None,
            probe_passed: Some(false),
        });
        assert_eq!(t.score, 0);
        assert_eq!(t.level, Level::Hostile);
    }

    #[test]
    fn level_thresholds_match_js() {
        assert_eq!(Level::for_score(80), Level::Clean);
        assert_eq!(Level::for_score(79), Level::Restricted);
        assert_eq!(Level::for_score(55), Level::Restricted);
        assert_eq!(Level::for_score(30), Level::Restricted);
        assert_eq!(Level::for_score(29), Level::Hostile);
        assert_eq!(Level::for_score(0), Level::Hostile);
    }
}
