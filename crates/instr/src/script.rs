//! Final script assembly: environment checks, automation block checks, the
//! state computation, the probe, and the result post.

use crate::probes::{build_probe, tmpl};
use crate::rng::{Namer, Rng};

pub struct ScriptInput<'a> {
    pub id: &'a str,
    pub vars: &'a [String; 4],
    pub init_vals: &'a [i64; 4],
    pub client_eqs: &'a str,
    pub block_automated_browsers: bool,
    pub extended: Option<&'a [String]>,
    pub mac_key: Option<&'a str>,
}

/// JS `hashWith(seed)` — FNV-ish rolling XOR/multiply hash over UTF-16 code
/// units, truncated to u32 (`>>> 0`).
pub fn hash_with(seed: u32, s: &str) -> u32 {
    let mut h = seed;
    for unit in s.encode_utf16() {
        h ^= unit as u32;
        h = h
            .wrapping_add(h << 1)
            .wrapping_add(h << 4)
            .wrapping_add(h << 7)
            .wrapping_add(h << 8)
            .wrapping_add(h << 24);
    }
    h
}

fn json_nums(nums: &[u32]) -> String {
    let parts: Vec<String> = nums.iter().map(|n| n.to_string()).collect();
    format!("[{}]", parts.join(","))
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).expect("string serialisation cannot fail")
}

// ---------------------------------------------------------------- block checks

const WINDOW_PROP_MARKERS: &[&str] = &[
    "_Selenium_IDE_Recorder",
    "_selenium",
    "calledSelenium",
    "__webdriverFunc",
    "__lastWatirAlert",
    "__lastWatirConfirm",
    "__lastWatirPrompt",
    "_WEBDRIVER_ELEM_CACHE",
    "ChromeDriverw",
    "awesomium",
    "CefSharp",
    "RunPerfTest",
    "fmget_targets",
    "geb",
    "spawn",
    "domAutomation",
    "domAutomationController",
    "wdioElectron",
    "callPhantom",
    "_phantom",
    "__nightmare",
    "nightmare",
    "__playwright__binding__",
    "__pwInitScripts",
];
const DOC_PROP_MARKERS: &[&str] = &[
    "__selenium_evaluate",
    "selenium-evaluate",
    "__selenium_unwrapped",
    "__webdriver_script_fn",
    "__driver_evaluate",
    "__webdriver_evaluate",
    "__fxdriver_evaluate",
    "__driver_unwrapped",
    "__webdriver_unwrapped",
    "__fxdriver_unwrapped",
    "__webdriver_script_func",
    "__webdriver_script_function",
];
const NAV_OWN_PROP_MARKERS: &[&str] = &[
    "webdriver",
    "userAgent",
    "appVersion",
    "userAgentData",
    "platform",
    "vendor",
    "product",
    "productSub",
    "languages",
    "language",
    "plugins",
    "mimeTypes",
    "hardwareConcurrency",
    "deviceMemory",
    "maxTouchPoints",
    "permissions",
    "connection",
];
const ATTR_SUBSTRING_MARKERS: &[&str] = &["selenium", "webdriver", "driver"];
const STACK_SUBSTRING_MARKERS: &[&str] = &["pptr:", "UtilityScript.", "PhantomJS"];
const WINDOW_PREFIX_MARKERS: &[&str] = &["puppeteer_", "cdc_", "$cdc_"];
const UA_TOKEN_MARKERS: &[&str] = &["HeadlessChrome", "PhantomJS", "SlimerJS", "headless"];
const WEBGL_VENDOR_MARKER: &str = "Brian Paul";
const WEBGL_RENDERER_MARKER: &str = "Mesa OffScreen";
const PRODUCTSUB_GECKO: &str = "20030107";
const SEQUENTUM_MARKER: &str = "Sequentum";

fn hashes(seed: u32, list: &[&str]) -> Vec<u32> {
    list.iter().map(|m| hash_with(seed, m)).collect()
}

/// Build the automation block checks. Only a random sample of 8 is emitted (as
/// in the reference), and the resulting `if (B) { postMessage(blocked); return }`
/// is prepended to the state computation.
fn build_block_checks(
    rng: &mut Rng,
    namer: &mut Namer,
    b: &str,
    id: &str,
    hf: &str,
    hset: &str,
    seed: u32,
) -> String {
    let h = |s: &str| hash_with(seed, s).to_string();
    let subs = |a: &str| -> Vec<(String, String)> {
        vec![
            ("%B%".into(), b.into()),
            ("%HF%".into(), hf.into()),
            ("%HSET%".into(), hset.into()),
            ("%A%".into(), a.into()),
        ]
    };
    let apply = |t: &str, extra: &[(String, String)], a: &str| -> String {
        let mut pairs: Vec<(String, String)> = subs(a);
        pairs.extend_from_slice(extra);
        let refs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        tmpl(t, &refs)
    };

    let mut checks: Vec<String> = Vec::new();

    checks.push(apply(
        r#"if (!%B%) { try { var d = Object.getOwnPropertyDescriptors(navigator); var __wh = %H_WD%; for (const k in d) { if (%HF%(k) === __wh) { %B% = true; break; } } if (!%B%) { var p = Object.getPrototypeOf(navigator); while (p && !%B%) { for (const k of Object.getOwnPropertyNames(p)) { if (%HF%(k) === __wh) { try { if (navigator[k]) %B% = true; } catch {} break; } } p = Object.getPrototypeOf(p); } } } catch { %B% = true; } }"#,
        &[("%H_WD%".into(), h("webdriver"))],
        "",
    ));

    {
        let a = namer.var(rng, None);
        checks.push(apply(
            r#"if (!%B%) { try { var %A% = %NAVOWN%; for (const k of Object.getOwnPropertyNames(navigator)) { if (%HSET%(%A%, %HF%(k))) { %B% = true; break; } } } catch { %B% = true; } }"#,
            &[("%NAVOWN%".into(), json_nums(&hashes(seed, NAV_OWN_PROP_MARKERS)))],
            &a,
        ));
    }

    {
        let a = namer.var(rng, None);
        checks.push(apply(
            r#"if (!%B%) { var %A% = %WINPREFIX%; for (const k of Object.getOwnPropertyNames(window)) { for (var pl = 4; pl <= 5; pl++) { if (%HSET%(%A%, %HF%(k.slice(0, pl)))) { %B% = true; break; } } if (%B%) break; } }"#,
            &[("%WINPREFIX%".into(), json_nums(&hashes(seed, WINDOW_PREFIX_MARKERS)))],
            &a,
        ));
    }

    {
        let a = namer.var(rng, None);
        checks.push(apply(
            r#"if (!%B%) { var %A% = %WINHASH%; for (const k of Object.getOwnPropertyNames(window)) { if (%HSET%(%A%, %HF%(k))) { %B% = true; break; } } }"#,
            &[("%WINHASH%".into(), json_nums(&hashes(seed, WINDOW_PROP_MARKERS)))],
            &a,
        ));
    }

    {
        let a = namer.var(rng, None);
        checks.push(apply(
            r#"if (!%B%) { var %A% = %DOCHASH%; for (const k of Object.getOwnPropertyNames(document)) { if (%HSET%(%A%, %HF%(k))) { %B% = true; break; } } }"#,
            &[("%DOCHASH%".into(), json_nums(&hashes(seed, DOC_PROP_MARKERS)))],
            &a,
        ));
    }

    {
        let a = namer.var(rng, None);
        checks.push(apply(
            r#"if (!%B%) { try { var %A% = %ATTRSUB%; var an = document.documentElement.getAttributeNames(); for (const n of an) { for (const t of n.split(/[^a-z]+/i)) { if (t && %HSET%(%A%, %HF%(t.toLowerCase()))) { %B% = true; break; } } if (%B%) break; } } catch { %B% = true; } }"#,
            &[("%ATTRSUB%".into(), json_nums(&hashes(seed, ATTR_SUBSTRING_MARKERS)))],
            &a,
        ));
    }

    {
        let a = namer.var(rng, None);
        let st = namer.var(rng, None);
        checks.push(apply(
            r#"if (!%B%) { try { var %A% = %STACKSUB%; var %ST% = (new Error()).stack || ''; for (var i = 0; i + 5 <= %ST%.length; i++) { for (var sl = 5; sl <= 14; sl++) { if (i + sl > %ST%.length) break; if (%HSET%(%A%, %HF%(%ST%.substr(i, sl)))) { %B% = true; break; } } if (%B%) break; } } catch {} }"#,
            &[
                ("%STACKSUB%".into(), json_nums(&hashes(seed, STACK_SUBSTRING_MARKERS))),
                ("%ST%".into(), st),
            ],
            &a,
        ));
    }

    checks.push(apply(
        r#"if (!%B%) { try { if (typeof window.exposedFn !== 'undefined') { var s = window.exposedFn.toString(); for (var i = 0; i + 19 <= s.length; i++) { if (%HF%(s.substr(i, 19)) === %H_EXPOSE%) { %B% = true; break; } } } } catch {} }"#,
        &[("%H_EXPOSE%".into(), h("exposeBindingHandle"))],
        "",
    ));

    checks.push(apply(
        r#"if (!%B% && typeof window.process !== 'undefined') { try { if (%HF%(window.process.type || '') === %H_RENDERER% || (window.process.versions && window.process.versions.electron)) %B% = true; } catch { %B% = true; } }"#,
        &[("%H_RENDERER%".into(), h("renderer"))],
        "",
    ));

    {
        let a = namer.var(rng, None);
        checks.push(apply(
            r#"if (!%B%) { try { var %A% = %UATOK%; var ua = navigator.userAgent || ''; for (const t of ua.split(/[\s/(),;]/)) { if (t && %HSET%(%A%, %HF%(t))) { %B% = true; break; } } if (!%B%) { var av = navigator.appVersion || ''; for (const t of av.split(/[\s/(),;]/)) { if (t && %HSET%(%A%, %HF%(t))) { %B% = true; break; } } } } catch {} }"#,
            &[("%UATOK%".into(), json_nums(&hashes(seed, UA_TOKEN_MARKERS)))],
            &a,
        ));
    }

    checks.push(apply(
        r#"if (!%B%) { try { var c = document.createElement('canvas').getContext('webgl'); if (c) { var v = c.getParameter(c.VENDOR); var r = c.getParameter(c.RENDERER); if (%HF%(v || '') === %H_WGL_V% && %HF%(r || '') === %H_WGL_R%) %B% = true; } } catch {} }"#,
        &[
            ("%H_WGL_V%".into(), h(WEBGL_VENDOR_MARKER)),
            ("%H_WGL_R%".into(), h(WEBGL_RENDERER_MARKER)),
        ],
        "",
    ));

    checks.push(apply(
        r#"if (!%B%) { try { if (document.hasFocus && document.hasFocus() && window.outerWidth === 0 && window.outerHeight === 0) %B% = true; } catch { %B% = true; } }"#,
        &[],
        "",
    ));

    checks.push(apply(
        r#"if (!%B%) { try { var es = Function.prototype.toString.call(eval); var found = false; for (var i = 0; i + 13 <= es.length; i++) { if (%HF%(es.substr(i, 13)) === %H_NATIVE%) { found = true; break; } } if (!found) %B% = true; } catch {} }"#,
        &[("%H_NATIVE%".into(), h("[native code]"))],
        "",
    ));

    checks.push(apply(
        r#"if (!%B%) { try { if (typeof Function.prototype.bind === 'undefined') %B% = true; } catch {} }"#,
        &[],
        "",
    ));

    checks.push(apply(
        r#"if (!%B%) { try { if (window.external && typeof window.external.toString === 'function') { var s = window.external.toString(); for (var i = 0; i + 9 <= s.length; i++) { if (%HF%(s.substr(i, 9)) === %H_SEQ%) { %B% = true; break; } } } } catch { %B% = true; } }"#,
        &[("%H_SEQ%".into(), h(SEQUENTUM_MARKER))],
        "",
    ));

    {
        let ok = namer.var(rng, None);
        let i = namer.var(rng, None);
        checks.push(apply(
            r#"if (!%B%) { try { if (navigator.mimeTypes) { var %OK% = Object.getPrototypeOf(navigator.mimeTypes) === MimeTypeArray.prototype; for (var %I% = 0; %I% < navigator.mimeTypes.length && %OK%; %I%++) { %OK% = Object.getPrototypeOf(navigator.mimeTypes[%I%]) === MimeType.prototype; } if (!%OK%) %B% = true; } } catch {} }"#,
            &[("%OK%".into(), ok), ("%I%".into(), i)],
            "",
        ));
    }

    {
        let ps = namer.var(rng, None);
        let ua = namer.var(rng, None);
        checks.push(apply(
            r#"if (!%B%) { try { var %PS% = navigator.productSub; var %UA% = navigator.userAgent || ''; if (%PS% && %HF%(%PS%) !== %H_PS%) { var likeBlink = false; for (const t of %UA%.toLowerCase().split(/[\s/(),;]/)) { var hh = %HF%(t); if (hh === %H_CHROME% || hh === %H_SAFARI% || hh === %H_OPERA%) { likeBlink = true; break; } } if (likeBlink) %B% = true; } } catch {} }"#,
            &[
                ("%PS%".into(), ps),
                ("%UA%".into(), ua),
                ("%H_PS%".into(), h(PRODUCTSUB_GECKO)),
                ("%H_CHROME%".into(), h("chrome")),
                ("%H_SAFARI%".into(), h("safari")),
                ("%H_OPERA%".into(), h("opera")),
            ],
            "",
        ));
    }

    {
        let k = namer.var(rng, None);
        checks.push(apply(
            r#"if (!%B%) { try { var %K% = Object.getOwnPropertyNames(window); for (const n of %K%) { var u = n.lastIndexOf('_'); if (u > 3 && u < n.length - 1) { var suf = n.slice(u + 1); var hh = %HF%(suf); if (hh === %H_ARRAY% || hh === %H_PROMISE% || hh === %H_SYMBOL%) { %B% = true; break; } } } } catch {} }"#,
            &[
                ("%K%".into(), k),
                ("%H_ARRAY%".into(), h("Array")),
                ("%H_PROMISE%".into(), h("Promise")),
                ("%H_SYMBOL%".into(), h("Symbol")),
            ],
            "",
        ));
    }

    rng.shuffle(&mut checks);
    let sampled = &checks[..checks.len().min(8)];

    format!(
        "let {b} = false;try {{{body}}} catch {{{b} = true}} if ({b}) {{parent.postMessage({{ type: 'cap:instr', nonce: {id}, result: '', blocked: true }}, '*');return;}}",
        b = b,
        body = sampled.concat(),
        id = json_str(id)
    )
}

// ------------------------------------------------------------ environment checks

fn build_env_checks(rng: &mut Rng, namer: &mut Namer, hf: &str, hset: &str, seed: u32) -> String {
    let nk = namer.var(rng, None);
    let h = |s: &str| hash_with(seed, s).to_string();
    let leak1 = json_nums(&hashes(seed, &["Bun", "process", "module", "require", "global", "__dirname", "Deno"]));
    let leak2 = json_nums(&hashes(seed, &["Bun", "process", "require", "global", "__dirname", "Deno"]));

    let owned: Vec<(String, String)> = vec![
        ("%NK%".into(), nk.clone()),
        ("%HF%".into(), hf.into()),
        ("%HSET%".into(), hset.into()),
        ("%LEAK1%".into(), leak1),
        ("%LEAK2%".into(), leak2),
        ("%H_NAV%".into(), h("[object Navigator]")),
        ("%H_WIN%".into(), h("[object Window]")),
        ("%H_DOC%".into(), h("[object HTMLDocument]")),
    ];
    let pairs: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let checks: Vec<String> = vec![
        tmpl(
            r#"try { const %NK%st = (new Error()).stack || ''; if (%NK%st.indexOf('node:internal') !== -1 || %NK%st.indexOf('moduleEvaluation') !== -1 || %NK%st.indexOf('loadAndEvaluateModule') !== -1 || %NK%st.indexOf('file:///') !== -1 || %NK%st.indexOf('[eval]') !== -1 || /\(native:/.test(%NK%st)) return null; } catch { return null }"#,
            &pairs,
        ),
        r#"if (typeof HTMLElement !== 'function' || typeof Window !== 'function' || typeof Document !== 'function' || typeof Navigator !== 'function' || typeof Node !== 'function') return null; if (!(navigator instanceof Navigator) || !(document instanceof Document) || !(window instanceof Window) || !(document.body instanceof HTMLElement)) return null; if (globalThis !== window || window.self !== window || document.defaultView !== window) return null;"#.to_string(),
        tmpl(
            r#"try { const %NK%ots = Object.prototype.toString; if (%HF%(%NK%ots.call(navigator)) !== %H_NAV% || %HF%(%NK%ots.call(window)) !== %H_WIN% || %HF%(%NK%ots.call(document)) !== %H_DOC%) return null; } catch { return null }"#,
            &pairs,
        ),
        tmpl(
            r#"try { if (typeof EventTarget !== 'function' || !(document.body instanceof EventTarget) || !(window instanceof EventTarget)) return null; const %NK%probe = document.createElement('div'); let %NK%fired = 0; const %NK%ev = '_c' + (Date.now() & 0xffff).toString(36); const %NK%h = (e) => { if (e && e.detail === 0xc0de) %NK%fired++; }; %NK%probe.addEventListener(%NK%ev, %NK%h); %NK%probe.dispatchEvent(new CustomEvent(%NK%ev, { detail: 0xc0de })); %NK%probe.dispatchEvent(new CustomEvent(%NK%ev, { detail: 0xc0de })); %NK%probe.removeEventListener(%NK%ev, %NK%h); %NK%probe.dispatchEvent(new CustomEvent(%NK%ev, { detail: 0xc0de })); if (%NK%fired !== 2) return null; } catch { return null }"#,
            &pairs,
        ),
        tmpl(
            r#"try { const %NK%gf = new Function('return this'); const %NK%tg = %NK%gf(); if (%NK%tg !== globalThis) return null; const %NK%leakHashes = %LEAK1%; for (const %NK%k of Object.getOwnPropertyNames(%NK%tg)) { if (%HSET%(%NK%leakHashes, %HF%(%NK%k))) return null; } const %NK%fnArgs = new Function('a','b','c','return a+b+c'); if (%NK%fnArgs.length !== 3) return null; if (%NK%fnArgs(10,20,30) !== 60) return null; const %NK%src = Function.prototype.toString.call(%NK%fnArgs); if (%NK%src.indexOf('return a+b+c') === -1) return null; if (%NK%src.indexOf('apply') !== -1 || %NK%src.indexOf('callArgs') !== -1 || %NK%src.indexOf('Reflect.') !== -1) return null; let %NK%thrown = null; try { new Function('throw new Error("x")')(); } catch (%NK%e) { %NK%thrown = %NK%e; } if (!%NK%thrown || !%NK%thrown.stack) return null; const %NK%st2 = %NK%thrown.stack; if (%NK%st2.indexOf('node:internal') !== -1 || %NK%st2.indexOf('moduleEvaluation') !== -1 || %NK%st2.indexOf('file:///') !== -1 || %NK%st2.indexOf('[eval]') !== -1 || /\(native:/.test(%NK%st2)) return null; } catch { return null }"#,
            &pairs,
        ),
        tmpl(
            r#"try { const %NK%ie = (0, eval); const %NK%eg = %NK%ie('this'); if (%NK%eg !== globalThis) return null; const %NK%leak2 = %LEAK2%; for (const %NK%k of Object.getOwnPropertyNames(%NK%eg)) { if (%HSET%(%NK%leak2, %HF%(%NK%k))) return null; } } catch { return null }"#,
            &pairs,
        ),
        build_eval_check(rng, namer),
    ];

    let mut checks = checks;
    rng.shuffle(&mut checks);
    checks.concat()
}

/// The eval-scoping self-test: a secret is split across two identifiers and the
/// script must be able to recover it via direct + indirect eval.
fn build_eval_check(rng: &mut Rng, namer: &mut Namer) -> String {
    let ev = namer.var(rng, None);
    let a = namer.var(rng, None);
    let b = namer.var(rng, None);
    let c = namer.var(rng, None);
    let secret = rng.inclusive(1_000_000, 0x7fff_fffe);
    let head: String = ev.chars().take(2).collect();
    let tail: String = ev.chars().skip(2).collect();

    let owned: Vec<(String, String)> = vec![
        ("%EV%".into(), ev.clone()),
        ("%A%".into(), a),
        ("%B%".into(), b),
        ("%C%".into(), c),
        ("%SECRET%".into(), secret.to_string()),
        ("%SECRET1%".into(), (secret + 1).to_string()),
        ("%SECRET2%".into(), (secret * 2).to_string()),
        ("%HEAD%".into(), head),
        ("%TAIL%".into(), tail),
    ];
    let pairs: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

    let inner = tmpl(
        r#"try { var %EV% = %SECRET%; var %A% = '%HEAD%'; var %B% = '%TAIL%'; var %C% = %A% + %B%; var %EV%r1 = (0, eval)('typeof ' + %C%); if (%EV%r1 !== 'undefined') return false; var %EV%r2 = eval(%C%); if (%EV%r2 !== %SECRET%) return false; var %EV%r3 = eval(%A% + %B% + '+1'); if (%EV%r3 !== %SECRET1%) return false; var %EV%arr = ['(', '(', ')', '=', '>', 't', 'h', 'i', 's', ')', '(', ')']; var %EV%arrow = (0, eval)(%EV%arr.join('')); if (%EV%arrow !== globalThis) return false; var %EV%r4 = eval('(function(){return ' + %C% + '*2;})()'); if (%EV%r4 !== %SECRET2%) return false; return true; } catch { return false }"#,
        &pairs,
    );

    format!("if (!new Function({})()) return null;", json_str(&inner))
}

// ------------------------------------------------------------------- assembly

pub fn build_script(rng: &mut Rng, namer: &mut Namer, inp: &ScriptInput<'_>) -> String {
    let seed = rng.inclusive(1, 0x7fff_fffe) as u32;
    let hf = namer.var(rng, None);
    let hset = namer.var(rng, None);
    let dv = namer.var(rng, None);
    let out_key = namer.var(rng, None);
    let p_key = namer.var(rng, None);

    let helpers = format!(
        "function {hf}(s){{let h={seed}>>>0;for(let i=0;i<s.length;i++){{h^=s.charCodeAt(i);h=(h+(h<<1)+(h<<4)+(h<<7)+(h<<8)+(h<<24))>>>0;}}return h>>>0;}}function {hset}(a,v){{for(var i=0;i<a.length;i++)if(a[i]===v)return true;return false;}}",
        hf = hf,
        hset = hset,
        seed = seed
    );

    let block = if inp.block_automated_browsers {
        let b = namer.var(rng, None);
        build_block_checks(rng, namer, &b, inp.id, &hf, &hset, seed)
    } else {
        String::new()
    };

    let env = build_env_checks(rng, namer, &hf, &hset, seed);

    let probe = build_probe(rng, namer, &p_key, inp.extended);

    let await_pending = format!(
        "try {{ if ({p} && Array.isArray({p}.__pending)) {{ await Promise.race([Promise.all({p}.__pending.map(function(pr){{return Promise.resolve(pr).catch(function(){{}})}})), new Promise(function(r){{setTimeout(r,2000)}})]); }} delete {p}.__pending; }} catch(e) {{}}",
        p = p_key
    );

    let idj = json_str(inp.id);
    let post = match inp.mac_key {
        Some(key) => {
            let kj = json_str(key);
            format!(
                "var __cR={{i:{idj},state:{dv},p:{p},ts:Date.now()}};try{{var __cE=new TextEncoder();var __cK=await crypto.subtle.importKey('raw',__cE.encode({kj}),{{name:'HMAC',hash:'SHA-256'}},false,['sign']);var __cS=await crypto.subtle.sign('HMAC',__cK,__cE.encode('cap-instr|'+{idj}+'|'+__cR.ts+'|'+JSON.stringify(__cR.state)+'|'+JSON.stringify(__cR.p)));var __cB=new Uint8Array(__cS);var __cH='';for(var __cI=0;__cI<__cB.length;__cI++)__cH+=(__cB[__cI]&255).toString(16).padStart(2,'0');__cR.mac=__cH;}}catch(e){{}}parent.postMessage({{type:'cap:instr',nonce:{idj},result:__cR}},'*');",
                idj = idj,
                dv = dv,
                p = p_key,
                kj = kj
            )
        }
        None => format!(
            "parent.postMessage({{type: 'cap:instr',nonce:{idj},result:{{i:{idj},state:{dv},p:{p},ts:Date.now()}}}},'*');",
            idj = idj,
            dv = dv,
            p = p_key
        ),
    };

    let go_key = format!("{}n", out_key);
    let owned: Vec<(String, String)> = vec![
        ("%HELPERS%".into(), helpers),
        ("%ENV%".into(), env),
        ("%BLOCK%".into(), block),
        ("%CLIENTEQ%".into(), inp.client_eqs.to_string()),
        ("%DV%".into(), dv),
        ("%OUT%".into(), out_key),
        ("%PROBE%".into(), probe),
        ("%AWAIT%".into(), await_pending),
        ("%POST%".into(), post),
        // Named entry point for the load listener (avoids `window.onload`,
        // which would clobber the widget's own handler).
        ("%GO%".into(), go_key),
    ];
    let mut pairs: Vec<(String, String)> = owned;
    for (i, v) in inp.vars.iter().enumerate() {
        pairs.push((format!("%V{}%", i), v.clone()));
        pairs.push((format!("%I{}%", i), inp.init_vals[i].to_string()));
    }
    let refs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

    tmpl(
        "(function(){async function %GO%(){try {%HELPERS%const %DV%=await (async function(){%ENV%%BLOCK%var %V0%=%I0%;var %V1%=%I1%;var %V2%=%I2%;var %V3%=%I3%;%CLIENTEQ%var %OUT%={};%OUT%[\"%V0%\"]=%V0%;%OUT%[\"%V1%\"]=%V1%;%OUT%[\"%V2%\"]=%V2%;%OUT%[\"%V3%\"]=%V3%;return %OUT%;})();if (!%DV% || typeof %DV% !== 'object') return;%PROBE%%AWAIT%%POST%} catch {}}if(document.readyState==='complete'){%GO%()}else{window.addEventListener('load',%GO%)};})();",
        &refs,
    )
}

/// Apply the requested obfuscation level.
///
/// The level is clamped to `1..=10`. Levels 1..=3 in the reference only strip
/// indentation (which we always do); levels 4..=10 additionally rely on esbuild
/// and `javascript-obfuscator`, which are not ported in phase 1. The level is
/// therefore currently a no-op beyond whitespace normalisation — documented in
/// the crate docs.
pub fn apply_obfuscation(script: String, level: u8) -> String {
    // No-op for every level in phase 1 (see the module docs); the clamp only
    // documents the accepted range.
    let _ = level.clamp(1, 10);
    normalize_whitespace(&script)
}

/// Applied for every obfuscation level here (phase 1 is a no-op beyond this).
pub fn normalize_whitespace(script: &str) -> String {
    let mut out = String::with_capacity(script.len() + 16);
    let mut first = true;
    for line in script.split('\n') {
        if !first {
            out.push('\n');
        }
        first = false;
        out.push_str(line.trim_start());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_matches_js_reference_values() {
        // Values computed with the JS `hashWith` helper (bun).
        assert_eq!(hash_with(12345, "webdriver"), 3151209047);
        assert_eq!(hash_with(12345, "[object Navigator]"), 1113801103);
        assert_eq!(hash_with(12345, "[native code]"), 1553330389);
        assert_eq!(hash_with(12345, "Brian Paul"), 2485347699);
        assert_eq!(hash_with(12345, "Sequentum"), 3886487666);
        assert_eq!(hash_with(12345, "chrome"), 2675064399);
        assert_eq!(hash_with(12345, "20030107"), 339447644);
        assert_eq!(hash_with(2147483646, "webdriver"), 78468838);
        assert_eq!(hash_with(2147483646, "renderer"), 4238379141);
    }

    #[test]
    fn whitespace_normalisation_is_idempotent() {
        let s = "a\n    b\n\tc";
        assert_eq!(normalize_whitespace(s), "a\nb\nc");
        assert_eq!(
            normalize_whitespace(&normalize_whitespace(s)),
            "a\nb\nc"
        );
    }

    #[test]
    fn eval_check_splits_the_name() {
        let mut r = Rng::from_seed(1);
        let mut n = Namer::new();
        let s = build_eval_check(&mut r, &mut n);
        assert!(s.starts_with("if (!new Function(\""));
        assert!(s.ends_with("\")()) return null;"));
    }
}
