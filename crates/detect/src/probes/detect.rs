//! The detection rules: base checks, tamper checks and instrumentation checks.
//!
//! Each rule is a pure function over an already-sanitised probe vector; the
//! public entry point is `detect_automation`.

use super::*;

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
    let quantized = geo.is_some_and(|g| g.count >= 5 && g.distinct >= 3);
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

    if want_shape && field(s, "evalShape").is_some_and(|v| !v.is_null())
        && !(eval_obj.is_some() && eval_nl.is_some()) {
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
        let lang_truthy = lang_v.is_some_and(truthy);
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
    if chromium_ua
        && let Some(cs) = as_obj(field(s, "chromeShape"))
    {
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

    // --- cross-realm (worker) consistency --------------------------------
    if opts.wants("workerInfo") && as_obj(field(s, "workerInfo")).is_none() {
        add(&mut checks, "worker_probe_missing", false, "worker probe missing", false);
    }
    if let Some(wi) = as_obj(field(s, "workerInfo")) {
        if let (Some(a), Some(b)) = (
            as_num(wi.get("hardwareConcurrency")),
            as_num(field(s, "hardwareConcurrency")),
        ) && a != b {
            add(
                &mut checks,
                "worker_hw_mismatch",
                false,
                format!("main={} worker={}", dnum(b), dnum(a)),
                false,
            );
        }
        if let (Some(a), Some(b)) = (as_num(wi.get("deviceMemory")), as_num(field(s, "deviceMemory")))
            && a != b
        {
            add(
                &mut checks,
                "worker_mem_mismatch",
                false,
                format!("main={} worker={}", dnum(b), dnum(a)),
                false,
            );
        }
        if let (Some(a), Some(b)) = (
            as_str(wi.get("platform")).filter(|p| !p.is_empty()),
            as_str(field(s, "platform")).filter(|p| !p.is_empty()),
        ) && a != b {
            add(
                &mut checks,
                "worker_platform_mismatch",
                false,
                "main≠worker platform",
                false,
            );
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
    if let (Some(x), Some(y)) = (iw0, iw1)
        && (ow0.is_some_and(|o| x > o + OUTER_HEIGHT_SLACK)
            || ow1.is_some_and(|o| y > o + OUTER_HEIGHT_SLACK)
            || scw.is_some_and(|w| x > w + OUTER_HEIGHT_SLACK)
            || sch.is_some_and(|h| y > h + OUTER_HEIGHT_SLACK))
    {
        iw0 = None;
        iw1 = None;
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
    if want_cdp && field(s, "cdp").is_some_and(|v| !v.is_null()) && cdp.is_none() {
        add(&mut checks, "cdp_probe_missing", false, "cdp probe missing or malformed", true);
    }
    if let Some(cdp) = cdp {
        let tapped = as_num(cdp.get("tap")).is_some_and(|x| x > 0.0);
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
        let obj_tap = as_num(cdp.get("objTap")).is_some_and(|x| x > 0.0);
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
        let stack_tap = as_num(cdp.get("stackTap")).is_some_and(|x| x > 0.0);
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
        let proto_tap = as_num(cdp.get("protoTap")).is_some_and(|x| x > 0.0);
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
                    .any(|k| codecs.get(*k).is_some_and(truthy));
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
            if let Some(media) = as_obj(act.get("media"))
                && is_false(media.get("pointerFine"))
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
        if firefox_ua
            && let Some(api) = as_obj(act.get("mediaApi"))
            && as_str(api.get("md")) == Some("object")
        {
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

    if let (Some(wua), Some(ua)) = (as_str(field(s, "workerUA")), as_str(field(s, "ua")))
        && !ua.is_empty()
    {
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

        let hash_ok = as_str(gl.get("hash")).is_some_and(|h| h.chars().count() >= 8 && h != "0");
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
            Some("macos") | Some("linux")
                if gpu_windows && !gpu_apple && os == Some("macos") =>
            {
                platform_gpu_mismatch = true;
                pg_detail = "macos declared, D3D backend";
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
