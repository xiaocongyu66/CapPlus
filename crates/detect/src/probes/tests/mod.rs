//! Tests for the probe checks, split into the rule tests and the JS parity
//! harness (the latter needs bun and the reference tree).

use serde_json::json;

use super::*;

mod parity;
mod rules;

    /// `cap-rust/` (two levels above `crates/detect`).
    fn workspace_root() -> std::path::PathBuf {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        manifest.join("..").join("..")
    }

/// Missing optional JS parity dependencies skip unless strict mode is enabled.
pub(crate) fn parity_required(reason: &str) {
    if std::env::var("CAP_SKIP_JS_PARITY").as_deref() == Ok("1") {
        eprintln!("SKIP (CAP_SKIP_JS_PARITY=1): {reason}");
        return;
    }
    if std::env::var("CAP_REQUIRE_JS_PARITY").as_deref() == Ok("1") {
        panic!("{reason}; install bun and set CAP_JS_CORE_DIR if no vendored reference is available");
    }
    eprintln!("SKIP JS parity: {reason}; set CAP_REQUIRE_JS_PARITY=1 to require it");
}

    fn ids(v: &[String]) -> Vec<&str> {
        v.iter().map(|s| s.as_str()).collect()
    }

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

    fn cdp_base() -> Value {
        let mut s = chrome_human();
        s["cdp"] = json!({
            "tap": 0, "objTap": 0, "stackTap": 0, "protoTap": 0,
            "dbgPause": false, "errPrep": false, "aut": 0, "webdriver": false
        });
        s
    }

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
