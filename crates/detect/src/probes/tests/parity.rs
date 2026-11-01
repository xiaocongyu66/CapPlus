use serde_json::json;

use super::*;

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
