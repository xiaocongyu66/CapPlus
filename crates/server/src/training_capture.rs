//! Bounded, typed observations only. No raw client value escapes extraction.
//! MAC validity means protocol conformance, never humanity. Call extraction only
//! after the site's enabled gate; enqueue only after atomic nonce consumption.
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Browser {
    Chromium,
    Firefox,
    Safari,
    Other,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Os {
    Windows,
    Macos,
    Linux,
    Android,
    Ios,
    Other,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Timing {
    Under10Ms,
    Under100Ms,
    Under1Sec,
    Under10Sec,
    Over10Sec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct Client {
    pub browser: Browser,
    pub os: Os,
    pub hardware_concurrency: Option<u16>,
    pub software_renderer: Option<bool>,
    /// Server-observed verification duration, not an unMACed client timestamp.
    pub timing: Option<Timing>,
}

// Reject overlong strings before matching or allocating, at byte boundaries.
// Dropping is safer than truncating an adversarial classification string.
fn bounded_string(value: Option<&Value>, limit: usize) -> Option<&str> {
    value?
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= limit)
}

pub(crate) fn extract(p: &Value, elapsed_ms: Option<u64>) -> Client {
    let ua = bounded_string(p.get("ua"), 512);
    let browser = match ua {
        None => Browser::Unknown,
        Some(s) if s.contains("Firefox/") => Browser::Firefox,
        Some(s) if s.contains("Chrome/") || s.contains("Chromium/") || s.contains("CriOS/") => {
            Browser::Chromium
        }
        Some(s) if s.contains("Safari/") && s.contains("Version/") => Browser::Safari,
        Some(_) => Browser::Other,
    };
    let os = match ua {
        None => Os::Unknown,
        Some(s) if s.contains("Android") => Os::Android,
        Some(s) if s.contains("iPhone") || s.contains("iPad") || s.contains("iPod") => Os::Ios,
        Some(s) if s.contains("Windows") => Os::Windows,
        Some(s) if s.contains("Macintosh") => Os::Macos,
        Some(s) if s.contains("Linux") => Os::Linux,
        Some(_) => Os::Other,
    };
    let hardware_concurrency = p
        .get("hardwareConcurrency")
        .and_then(Value::as_u64)
        .filter(|n| (1..=256).contains(n))
        .map(|n| n as u16);
    let software_renderer = p
        .get("webgl")
        .filter(|gl| gl.get("ok").and_then(Value::as_bool) == Some(true))
        .and_then(|gl| bounded_string(gl.get("renderer"), 256))
        .map(|renderer| {
            let renderer = renderer.to_ascii_lowercase();
            [
                "swiftshader",
                "llvmpipe",
                "softpipe",
                "software",
                "basic render",
            ]
            .iter()
            .any(|s| renderer.contains(s))
        });
    Client {
        browser,
        os,
        hardware_concurrency,
        software_renderer,
        timing: elapsed_ms.map(timing),
    }
}

pub(crate) fn timing(ms: u64) -> Timing {
    match ms {
        0..=9 => Timing::Under10Ms,
        10..=99 => Timing::Under100Ms,
        100..=999 => Timing::Under1Sec,
        1000..=9999 => Timing::Under10Sec,
        _ => Timing::Over10Sec,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct Proxy {
    pub tls: Option<bool>,
    pub ja4_browser: Option<bool>,
    pub ja3_browser: Option<bool>,
    pub http2_browser: Option<bool>,
    pub ua_mismatch: Option<bool>,
}
impl From<&cap_detect::NetworkSignals> for Proxy {
    fn from(n: &cap_detect::NetworkSignals) -> Self {
        Self {
            tls: n.tls,
            ja4_browser: n.ja4_browser,
            ja3_browser: n.ja3_browser,
            http2_browser: n.http2_browser,
            ua_mismatch: n.ua_mismatch,
        }
    }
}

/// A deliberately small static reason whitelist. Unknown/new reason IDs are
/// omitted, not copied; no details or arbitrary strings can enter the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reason {
    HoneypotTriggered,
    Webdriver,
    WebglSoftwareRenderer,
    WorkerUaMismatch,
    TlsMissing,
    Ja4NonBrowser,
    Ja3NonBrowser,
    Http2NonBrowser,
    UaJaMismatch,
}
pub(crate) fn reasons(trust: &cap_detect::Trust) -> Vec<Reason> {
    let mut out = Vec::with_capacity(9);
    for r in trust.reasons.iter().take(64) {
        if r.id.len() > 64 {
            continue;
        }
        let r = match r.id.as_str() {
            "honeypot_triggered" => Reason::HoneypotTriggered,
            "webdriver" => Reason::Webdriver,
            "webgl_software_renderer" => Reason::WebglSoftwareRenderer,
            "worker_ua_mismatch" => Reason::WorkerUaMismatch,
            "tls_missing" => Reason::TlsMissing,
            "ja4_non_browser" => Reason::Ja4NonBrowser,
            "ja3_non_browser" => Reason::Ja3NonBrowser,
            "http2_non_browser" => Reason::Http2NonBrowser,
            "ua_ja_mismatch" => Reason::UaJaMismatch,
            _ => continue,
        };
        if !out.contains(&r) {
            out.push(r);
        }
    }
    out
}

/// Records redeem policy execution ONLY. It must not be interpreted as token
/// issuance or downstream siteverify success.
pub(crate) fn policy_decision(
    recommended: cap_detect::Action,
    block_on_deny: bool,
) -> cap_detect::Action {
    if block_on_deny {
        recommended
    } else {
        cap_detect::Action::Allow
    }
}

pub(crate) fn eligible(enabled: bool, mac_verified: bool, nonce_consumed: bool) -> bool {
    enabled && mac_verified && nonce_consumed
}

/// Convert only already-sanitized observations to the store's fixed schema.
/// `decision` describes this redeem's execution, never a siteverify result.
/// The current storage schema has only a coarse reason: Policy means the
/// recommendation was deny (even if the configured execution allowed it).
pub(crate) fn sample(
    client: Client,
    net: Option<&cap_detect::NetworkSignals>,
    trust: &cap_detect::Trust,
    recommended: cap_detect::Action,
    block_on_deny: bool,
    elapsed_ms: u64,
    protocol: crate::training::Protocol,
) -> crate::training::Sample {
    use crate::training as t;
    // elapsed_ms is server wall time from before network/proof verification
    // through successful nonce consumption, including scheduler/store waits.
    // It is neither client timing nor pure CPU/GPU time. In particular do not
    // populate ClientReported.timing from this clock.
    let decision = match policy_decision(recommended, block_on_deny) {
        cap_detect::Action::Allow => t::Decision::Allow,
        cap_detect::Action::Deny => t::Decision::Deny,
    };
    let reason = match recommended {
        cap_detect::Action::Allow => t::ReasonId::ProofValid,
        cap_detect::Action::Deny => t::ReasonId::Policy,
    };
    let mut sample = t::Sample::new(
        decision,
        reason,
        elapsed_ms.min(3_600_000) as u32,
        trust.score.clamp(0, 100) as u16,
        true,
    );
    // The store currently supports only the coarse Redeem stage and protocol
    // version. Do not invent numeric level encodings or reinterpret Unknown.
    sample.phase = t::Phase::Redeem;
    sample.protocol = protocol;
    sample.recommended_action = match recommended {
        cap_detect::Action::Allow => t::RecommendedAction::Allow,
        cap_detect::Action::Deny => t::RecommendedAction::Deny,
    };
    // ReasonId has no detector IDs yet. These are true coarse observations,
    // not a lossy claim that any particular detector reason was persisted.
    sample.reasons.push(t::ReasonId::ProofValid);
    if recommended == cap_detect::Action::Deny {
        sample.reasons.push(t::ReasonId::Policy);
    }
    sample.client = Some(t::ClientFeatures {
        source: t::ClientSource::ClientReported,
        browser: match client.browser {
            Browser::Chromium => t::BrowserFamily::Chromium,
            Browser::Firefox => t::BrowserFamily::Firefox,
            Browser::Safari => t::BrowserFamily::Safari,
            Browser::Other => t::BrowserFamily::Other,
            Browser::Unknown => t::BrowserFamily::Unknown,
        },
        os: match client.os {
            Os::Windows => t::OsFamily::Windows,
            Os::Macos => t::OsFamily::Macos,
            Os::Linux => t::OsFamily::Linux,
            Os::Android => t::OsFamily::Android,
            Os::Ios => t::OsFamily::Ios,
            Os::Other => t::OsFamily::Other,
            Os::Unknown => t::OsFamily::Unknown,
        },
        hardware_concurrency: client.hardware_concurrency,
        software_renderer: client.software_renderer,
        timing: client.timing.map(|t| match t {
            Timing::Under10Ms => t::TimingBucket::Under10Ms,
            Timing::Under100Ms => t::TimingBucket::Under100Ms,
            Timing::Under1Sec => t::TimingBucket::Under1Sec,
            Timing::Under10Sec => t::TimingBucket::Under10Sec,
            Timing::Over10Sec => t::TimingBucket::Over10Sec,
        }),
    });
    sample.proxy = net.map(|n| {
        let n = Proxy::from(n);
        t::ProxyFeatures {
            source: t::ProxySource::TrustedProxy,
            tls: n.tls,
            ja4_browser: n.ja4_browser,
            ja3_browser: n.ja3_browser,
            http2_browser: n.http2_browser,
            ua_mismatch: n.ua_mismatch,
        }
    });
    sample
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn malicious_strings_never_escape_and_matching_is_bounded() {
        let secret = "private-cookie-IP-token-keyboard-session-nonce";
        let p = json!({"ua": format!("Chrome/ Windows {secret}"), "hardwareConcurrency":secret,
            "webgl":{"ok":true,"renderer":secret},"top":{"ua":secret},"keyboard":secret});
        let serialized = serde_json::to_string(&extract(&p, Some(u64::MAX))).unwrap();
        assert!(!serialized.contains(secret));
        let huge = "Chrome/ Windows SwiftShader ".repeat(1000);
        let c = extract(
            &json!({"ua":huge,"webgl":{"ok":true,"renderer":huge}}),
            None,
        );
        assert_eq!(c.browser, Browser::Unknown);
        assert_eq!(c.os, Os::Unknown);
        assert_eq!(c.software_renderer, None);
    }
    #[test]
    fn optional_missing_is_not_false_and_bad_types_drop() {
        for p in [
            json!({}),
            json!(null),
            json!({"hardwareConcurrency":-1,"webgl":false}),
            json!({"hardwareConcurrency":257,"webgl":{"ok":true,"renderer":42}}),
        ] {
            let c = extract(&p, None);
            assert_eq!(c.hardware_concurrency, None);
            assert_eq!(c.software_renderer, None);
            assert_eq!(c.timing, None);
        }
        let c = extract(
            &json!({"hardwareConcurrency":8,"webgl":{"ok":true,"renderer":"ANGLE GPU"}}),
            Some(10),
        );
        assert_eq!(c.hardware_concurrency, Some(8));
        assert_eq!(c.software_renderer, Some(false));
        let proxy = Proxy::from(&cap_detect::NetworkSignals {
            tls: Some(false),
            ..Default::default()
        });
        assert_eq!(proxy.tls, Some(false));
        assert_eq!(proxy.ja4_browser, None);
    }
    #[test]
    fn gating_and_actual_policy_are_distinct_from_recommendation() {
        for enabled in [false, true] {
            for mac in [false, true] {
                for nonce in [false, true] {
                    assert_eq!(eligible(enabled, mac, nonce), enabled && mac && nonce);
                }
            }
        }
        assert_eq!(
            policy_decision(cap_detect::Action::Deny, false),
            cap_detect::Action::Allow
        );
        assert_eq!(
            policy_decision(cap_detect::Action::Deny, true),
            cap_detect::Action::Deny
        );
    }
    #[test]
    fn samples_never_infer_truth_or_confuse_recommended_and_executed() {
        let trust = cap_detect::compute_trust_signals(
            &[cap_detect::Signal::gating("honeypot_triggered")],
            None,
            Some(true),
        );
        let client = extract(
            &json!({"ua":"Firefox/ Windows private-secret", "hardwareConcurrency":8}),
            None,
        );
        for block in [false, true] {
            let s = sample(
                client,
                None,
                &trust,
                cap_detect::Action::Deny,
                block,
                42,
                crate::training::Protocol::V2,
            );
            assert_eq!(s.phase, crate::training::Phase::Redeem);
            assert_eq!(s.protocol, crate::training::Protocol::V2);
            assert_eq!(
                s.recommended_action,
                crate::training::RecommendedAction::Deny
            );
            assert_eq!(s.level, None); // no documented numeric encoding
            assert_eq!(s.elapsed_ms, 42);
            assert!(s.client.as_ref().unwrap().timing.is_none());
            assert_eq!(
                s.reasons,
                vec![
                    crate::training::ReasonId::ProofValid,
                    crate::training::ReasonId::Policy
                ]
            );
            assert_eq!(s.truth, crate::training::Truth::Unknown);
            assert_eq!(
                s.decision,
                if block {
                    crate::training::Decision::Deny
                } else {
                    crate::training::Decision::Allow
                }
            );
            assert_eq!(s.reason, crate::training::ReasonId::Policy);
            assert!(s.proxy.is_none());
            assert!(
                !serde_json::to_string(&s)
                    .unwrap()
                    .contains("private-secret")
            );
        }
    }

    #[test]
    fn unknown_protocol_is_never_promoted_to_a_known_version() {
        use crate::training::{Phase, Protocol, ReasonId, RecommendedAction};
        let trust = cap_detect::compute_trust_signals(&[], None, Some(true));
        for protocol in [Protocol::Unknown, Protocol::V1, Protocol::V2] {
            let s = sample(
                extract(&json!({}), None),
                None,
                &trust,
                cap_detect::Action::Allow,
                false,
                10_000,
                protocol,
            );
            assert_eq!(s.protocol, protocol);
            assert_eq!(s.phase, Phase::Redeem);
            assert_eq!(s.recommended_action, RecommendedAction::Allow);
            assert_eq!(s.reasons, vec![ReasonId::ProofValid]);
            assert!(s.reasons.len() <= 16);
            assert_eq!(s.elapsed_ms, 10_000);
            assert!(s.client.unwrap().timing.is_none());
        }
    }

    #[tokio::test]
    async fn disabled_training_writes_no_observations_in_private_temp_directory() {
        use crate::training::{RecordOutcome, TrainingService};
        let path =
            std::env::temp_dir().join(format!("cap-capture-test-{}", cap_core::random_hex(16)));
        let service = TrainingService::open(&path).unwrap();
        let site = "capture-test";
        let status = service.status(site).await.unwrap();
        assert!(!status.config.enabled);
        let trust = cap_detect::compute_trust_signals(&[], None, Some(true));
        let observation = sample(
            extract(&json!({}), None),
            None,
            &trust,
            cap_detect::Action::Allow,
            true,
            1,
            crate::training::Protocol::V1,
        );
        assert_eq!(
            service.try_record(site, observation),
            RecordOutcome::Disabled
        );
        let status = service.status(site).await.unwrap();
        assert_eq!(status.written, 0);
        assert_eq!(status.bytes, 0);
        assert!(
            service
                .export_page(site, None, 10)
                .await
                .unwrap()
                .samples
                .is_empty()
        );
        drop(service);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn reasons_have_fixed_size_and_do_not_copy_freeform_ids() {
        let mut trust = cap_detect::compute_trust_signals(&[], None, None);
        trust.reasons = (0..1000)
            .map(|_| cap_detect::Reason {
                id: "secret".repeat(100),
                penalty: 0,
                gating: false,
            })
            .collect();
        assert!(reasons(&trust).is_empty());
        trust.reasons[0].id = "honeypot_triggered".into();
        assert_eq!(reasons(&trust), vec![Reason::HoneypotTriggered]);
    }
}
