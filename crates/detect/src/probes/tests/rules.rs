use super::*;

pub(crate) fn parity_required(reason: &str) {
    if std::env::var("CAP_SKIP_JS_PARITY").as_deref() == Ok("1") {
        eprintln!("SKIP (CAP_SKIP_JS_PARITY=1): {reason}");
        return;
    }
    panic!("{reason}; install bun and the reference tree, or set CAP_SKIP_JS_PARITY=1");
}

    use super::*;
    use serde_json::{json, Value};










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






