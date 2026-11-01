//! Probe construction: the sync field harness, the extended probes, and the
//! async probe spawns. Field names match the JS generator exactly.

use crate::rng::{Namer, Rng};
use crate::ExtProbes;

pub const PROBE_FONT_STACKS: [&str; 17] = [
    "sans-serif",
    "serif",
    "monospace",
    "Arial",
    "'Times New Roman'",
    "'Courier New'",
    "'Segoe UI'",
    "'SF Pro Text'",
    "'Helvetica Neue'",
    "'Ubuntu'",
    "'DejaVu Sans'",
    "'Roboto'",
    "Tahoma",
    "Calibri",
    "'Cantarell'",
    "'Liberation Sans'",
    "'Noto Sans'",
];

pub const PROBE_FONT_STACK_COUNT: usize = PROBE_FONT_STACKS.len();

/// Optional probes, in the same order as the JS `EXTENDED_PROBE_KEYS`.
pub const EXTENDED_PROBE_KEYS: [&str; 11] = [
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
];

/// Resolve the requested extended field list.
///
/// `Off → None`, `All → every known key`, `List → requested ∩ known` (in known
/// key order). A non-zero `polymorphism` (sharing the JS semantics) drops a
/// random subset but always keeps `platform` and `workerUA`.
pub fn resolve_extended_fields(
    rng: &mut Rng,
    probes: &ExtProbes<'_>,
    polymorphism: f64,
) -> Option<Vec<String>> {
    let mut keys: Vec<String> = match probes {
        ExtProbes::Off => return None,
        ExtProbes::All => EXTENDED_PROBE_KEYS.iter().map(|s| s.to_string()).collect(),
        ExtProbes::List(list) => EXTENDED_PROBE_KEYS
            .iter()
            .filter(|k| list.iter().any(|w| w == *k))
            .map(|s| s.to_string())
            .collect(),
    };

    if polymorphism > 0.0 && keys.len() > 2 {
        // JS clamps the drop probability to 0.6.
        let p = polymorphism.min(0.6);
        keys.retain(|k| {
            if k == "platform" || k == "workerUA" {
                return true;
            }
            rng.unit() >= p
        });
        for must in ["platform", "workerUA"] {
            if !keys.iter().any(|k| k == must) {
                keys.push(must.to_string());
            }
        }
    }
    Some(keys)
}

/// Tiny textual template helper. Tokens look like `%SF%`; JS never contains such
/// sequences so a plain sequential replace is safe.
pub(crate) fn tmpl(t: &str, subs: &[(&str, &str)]) -> String {
    let mut s = t.to_string();
    for (k, v) in subs {
        s = s.replace(k, v);
    }
    // Placeholders are `%NAME%`; a leftover means a substitution was missed
    // (or an inserted value contained one). Fail loudly in debug builds.
    debug_assert!(
        !s.contains('%') || std::env::var("CAP_ALLOW_PLACEHOLDER_LEFTOVER").is_ok(),
        "unreplaced template placeholder"
    );
    s
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).expect("string serialisation cannot fail")
}

fn json_nums(nums: &[u32]) -> String {
    let parts: Vec<String> = nums.iter().map(|n| n.to_string()).collect();
    format!("[{}]", parts.join(","))
}

/// Base sync probe fields. Every entry is `sf("name", function(){...});`.
const BASE_FIELDS: &[&str] = &[
    r#"%SF%("ua",function(){return navigator.userAgent});"#,
    r#"%SF%("productSub",function(){return navigator.productSub});"#,
    r#"%SF%("webdriver",function(){return navigator.webdriver});"#,
    r#"%SF%("oscpu",function(){return navigator.oscpu===undefined?"__undefined":navigator.oscpu});"#,
    r#"%SF%("deviceMemory",function(){return navigator.deviceMemory});"#,
    r#"%SF%("uaDataPresent",function(){return !!navigator.userAgentData});"#,
    r#"%SF%("uaData",function(){var u=navigator.userAgentData;return u?{mobile:u.mobile,brands:(u.brands||[]).map(function(b){return b.brand+"/"+b.version})}:null});"#,
    r#"%SF%("plugins",function(){return {length:navigator.plugins.length}});"#,
    r#"%SF%("pdfViewerEnabled",function(){return navigator.pdfViewerEnabled});"#,
    r#"%SF%("engine",function(){return {hasMozInnerScreenX:typeof window.mozInnerScreenX!=="undefined",hasChrome:typeof window.chrome!=="undefined"}});"#,
    // Engine identity by native-function code shape.
    r#"%SF%("evalShape",function(){try{var s=String(eval.toString());return {len:s.length,nl:s.indexOf("\n")!==-1}}catch(e){return null}});"#,
    r#"%SF%("nativeShape",function(){try{var s=String(Function.prototype.toString.call(Array.prototype.push));return {len:s.length,nl:s.indexOf("\n")!==-1}}catch(e){return null}});"#,
    r#"%SF%("mimeCount",function(){try{return navigator.mimeTypes?navigator.mimeTypes.length:null}catch(e){return null}});"#,
    r#"%SF%("languages",function(){var l=navigator.languages;return {lang:navigator.language||null,langs:l?Array.prototype.slice.call(l,0,8):[]}});"#,
    r#"%SF%("chromeShape",function(){var c=window.chrome;return c?{runtime:typeof c.runtime!=="undefined",loadTimes:typeof c.loadTimes!=="undefined",csi:typeof c.csi!=="undefined",app:typeof c.app!=="undefined"}:null});"#,
    r#"%SF%("notifPerm",function(){try{return typeof Notification!=="undefined"&&Notification.permission?Notification.permission:null}catch(e){return null}});"#,
    r#"%SF%("screen",function(){return {width:screen.width,height:screen.height}});"#,
    r#"%SF%("outerWH",function(){return [outerWidth,outerHeight]});"#,
    r#"%SF%("isExtended",function(){return screen.isExtended===undefined?null:screen.isExtended});"#,
    r#"%SF%("fontWidths",function(){var sp=document.createElement("span");sp.style.cssText="position:absolute;left:-9999px;top:-9999px;font-size:72px;white-space:nowrap";sp.textContent="mmmmmmmmmmlli WwWwGg @#Xj";document.body.appendChild(sp);var st=%FONTS%;var out=[];for(var i=0;i<st.length;i++){sp.style.fontFamily=st[i];out.push(Math.round(sp.getBoundingClientRect().width*100)/100)}document.body.removeChild(sp);return out});"#,
    r#"%SF%("tamper",function(){var n=%NAT%;var s=null,i=null,d=null;try{var c=crypto&&crypto.subtle;if(c){s=c.sign?n(c.sign):null;i=c.importKey?n(c.importKey):null;d=c.digest?n(c.digest):null}}catch(e){}return {getParameterWebGL:n(WebGLRenderingContext.prototype.getParameter),toDataURL:n(HTMLCanvasElement.prototype.toDataURL),getImageData:n(CanvasRenderingContext2D.prototype.getImageData),permissionsQuery:navigator.permissions?n(navigator.permissions.query):true,fnToString:n(Function.prototype.toString),cryptoSign:s,cryptoImportKey:i,cryptoDigest:d}});"#,
    // CDP / DevTools attachment probe (console traps, stack getter, debugger
    // pause, automation globals, overridden prepareStackTrace).
    r#"%SF%("cdp",function(){var hit=0,errPrep=false,dbgPause=false;var objTap=0,stackTap=0,protoTap=0;var c=window.console;var rLog=c&&c.log?c.log:null,rDbg=c&&c.debug?c.debug:null,rErr=c&&c.error?c.error:null;try{if(c){try{Object.defineProperty(c,"__capTap",{configurable:true,get:function(){hit++;return undefined}});}catch(e){}try{Object.defineProperty(c,"debug",{configurable:true,get:function(){hit++;return function(){}}});}catch(e){}try{Object.defineProperty(c,"log",{configurable:true,get:function(){hit++;return function(){}}});}catch(e){}}}catch(e){}var callReal=function(fn,a){try{if(fn)fn.call(c,a)}catch(e){}};try{var o={};Object.defineProperty(o,"capProbe",{configurable:true,enumerable:true,get:function(){objTap++;return 1;}});callReal(rLog,o);callReal(rDbg,o);}catch(e){}try{var er=new Error("cap");Object.defineProperty(er,"stack",{configurable:true,get:function(){stackTap++;return "cap";}});callReal(rLog,er);callReal(rErr,er);}catch(e){}try{function CapP(){}Object.defineProperty(CapP,"name",{configurable:true,get:function(){protoTap++;return "CapP";}});var cp=new CapP();callReal(rLog,cp);}catch(e){}try{var t0=Date.now();(function(){debugger;})();var dt=Date.now()-t0;if(dt>50)dbgPause=true;}catch(e){}try{errPrep=typeof Error.prepareStackTrace==="function"&&%NAT%(Error.prepareStackTrace)===false;}catch(e){}var aut=0;try{var names=["__nightmare","_phantom","callPhantom","__selenium_unwrapped","__webdriver_evaluate","__driver_evaluate","__playwright__binding__","__pwInitScripts","_WEBDRIVER_ELEM_CACHE","domAutomation","domAutomationController"];for(var i=0;i<names.length;i++){if(typeof window[names[i]]!=="undefined"){aut=1;break;}}}catch(e){}var webdriver=!!navigator.webdriver;return {tap:hit,objTap:objTap,stackTap:stackTap,protoTap:protoTap,dbgPause:dbgPause,errPrep:errPrep,aut:aut,webdriver:webdriver}});"#,
];

/// Extended probes wired into the sync harness (always emitted as functions; see
/// the note in `build_probe`). `storageQuota` and `workerUA` are async and live
/// in `ASYNC_PARTS` instead.
fn extended_sync_snippet(key: &str) -> Option<&'static str> {
    Some(match key {
        "platform" => r#"("platform",function(){return navigator.platform||"__undefined"});"#,
        "hardwareConcurrency" => {
            r#"("hardwareConcurrency",function(){return navigator.hardwareConcurrency});"#
        }
        "webgl" => r#"("webgl",function(){try{var cv=document.createElement("canvas");cv.width=cv.height=64;var g=cv.getContext("webgl")||cv.getContext("experimental-webgl");if(!g)return {ok:false};var ext=g.getExtension("WEBGL_debug_renderer_info");var v=ext?g.getParameter(ext.UNMASKED_VENDOR_WEBGL):g.getParameter(g.VENDOR);var r=ext?g.getParameter(ext.UNMASKED_RENDERER_WEBGL):g.getParameter(g.RENDERER);var cv2=document.createElement("canvas");cv2.width=cv2.height=4;var g2=!!cv2.getContext("webgl2");var px=new Uint8Array(4);g.clearColor(0.2,0.4,0.6,1);g.clear(g.COLOR_BUFFER_BIT);g.readPixels(0,0,1,1,g.RGBA,g.UNSIGNED_BYTE,px);var seed=(v+"|"+r).length;for(var i=0;i<px.length;i++){seed=(seed*31+px[i])>>>0;}return {ok:true,vendor:String(v),renderer:String(r),webgl2:g2,hash:seed.toString(16)}}catch(e){return {ok:false}}});"#,
        "canvas" => r#"("canvas",function(){try{var c=document.createElement("canvas");c.width=120;c.height=40;var x=c.getContext("2d");x.textBaseline="top";x.font="16px Arial";x.fillStyle='#f60';x.fillRect(0,0,60,20);x.fillStyle='#069';x.fillText("cap\u00e9 \ud83e\udd80",2,2);var d=c.toDataURL();var h=0;for(var i=0;i<d.length;i++){h=(h*31+d.charCodeAt(i))>>>0;}return h.toString(16)}catch(e){return ""}});"#,
        "audio" => r#"("audio",function(){try{var AC=window.OfflineAudioContext||window.webkitOfflineAudioContext;if(!AC)return null;var ctx=new AC(1,5000,44100);var o=ctx.createOscillator();o.type="triangle";o.frequency.value=10000;var cp=ctx.createDynamicsCompressor();o.connect(cp);cp.connect(ctx.destination);o.start(0);var buf=null;ctx.startRendering&&ctx.startRendering();ctx.oncomplete=function(e){buf=e.renderedBuffer};var out=0;var data=buf?buf.getChannelData(0):null;if(data){for(var i=4500;i<5000;i++){out+=Math.abs(data[i])}}return out}catch(e){return null}});"#,
        "emoji" => r#"("emoji",function(){try{var sp=document.createElement("span");sp.style.cssText="position:absolute;left:-9999px;top:-9999px;font-size:64px";sp.textContent="\ud83d\ude00\u2764";document.body.appendChild(sp);var w=sp.getBoundingClientRect().width;document.body.removeChild(sp);var style=w>=110?"apple-like":"narrow";return {style:style,width:Math.round(w)}}catch(e){return null}});"#,
        "canvasStable" => r#"("canvasStable",function(){try{function draw(c){var x=c.getContext("2d");x.textBaseline="top";x.font="16px Arial";x.fillStyle='#f60';x.fillRect(0,0,60,20);x.fillStyle='#069';x.fillText("cap\u00e9 \ud83e\udd80",2,2);return c.toDataURL()}var c=document.createElement("canvas");c.width=120;c.height=40;var h1=draw(c),h2=draw(c);return h1===h2}catch(e){return null}});"#,
        _ => return None,
    })
}

const WORKER_SRC: &str = r#"var o={ua:null,platform:null,hardwareConcurrency:null,deviceMemory:null,evalShape:null};try{o.ua=navigator.userAgent}catch(e){};try{o.platform=navigator.platform}catch(e){};try{o.hardwareConcurrency=navigator.hardwareConcurrency}catch(e){};try{o.deviceMemory=navigator.deviceMemory}catch(e){};try{var s=String(eval.toString());o.evalShape={nl:s.indexOf("\n")!==-1,len:s.length}}catch(e){};postMessage(JSON.stringify(o));"#;

const ASYNC_WORKER: &str = r#"try { %P%.workerUA=null; %P%.workerInfo=null; var %SF%url=URL.createObjectURL(new Blob([%WSRC%],{type:"application/javascript"})); var %SF%w=new Worker(%SF%url); %SF%pending.push(new Promise(function(res){var done=false;var to=setTimeout(function(){if(!done){done=true;res()}try{%SF%w.terminate()}catch(e){}},1500);%SF%w.onmessage=function(ev){if(done)return;done=true;clearTimeout(to);try{var o=typeof ev.data==="string"?JSON.parse(ev.data):ev.data;if(o&&typeof o==="object"){%P%.workerInfo=o;%P%.workerUA=typeof o.ua==="string"?o.ua:null}else{%P%.workerUA=typeof ev.data==="string"?ev.data:null}}catch(e){%P%.workerUA=typeof ev.data==="string"?ev.data:null}res();try{%SF%w.terminate()}catch(e){}};%SF%w.onerror=function(){if(done)return;done=true;clearTimeout(to);res()}})); } catch(e) { %P%.workerUA=null; %P%.workerInfo=null; }"#;

const ASYNC_STORAGE: &str = r#"try { if (navigator.storage && navigator.storage.estimate) { %SF%pending.push(navigator.storage.estimate().then(function(e){ %P%.storageQuota=e&&typeof e.quota==="number"?e.quota:null; }).catch(function(){ %P%.storageQuota=null; })); } else { %P%.storageQuota=null; } } catch(e) {}"#;

const ASYNC_ACTIVE: &str = r#"try{%P%.active=%P%.active||{};try{%P%.active.mediaApi={md:typeof navigator.mediaDevices,ed:(navigator.mediaDevices&&typeof navigator.mediaDevices.enumerateDevices)||"undefined"};}catch(e){}try{if(navigator.mediaDevices&&navigator.mediaDevices.enumerateDevices){%SF%pending.push(navigator.mediaDevices.enumerateDevices().then(function(ds){var a={audioin:0,videoin:0,audioout:0};for(var i=0;i<ds.length;i++){var k=ds[i].kind;if(k==="audioinput")a.audioin++;else if(k==="videoinput")a.videoin++;else if(k==="audiooutput")a.audioout++;}%P%.active.devices=a;%P%.active.deviceCount=ds.length;}).catch(function(){%P%.active.devicesError=true;}));}else{%P%.active.devicesSupported=false;}}catch(e){%P%.active.devicesError=true;}try{if(navigator.permissions&&navigator.permissions.query){%SF%pending.push(navigator.permissions.query({name:"notifications"}).then(function(st){%P%.active.permState=st&&st.state?st.state:null;%P%.active.permIsPromise=true;}).catch(function(){%P%.active.permError=true;}));}}catch(e){%P%.active.permError=true;}try{var mq=function(q){try{return !!window.matchMedia(q).matches}catch(e){return null}};%P%.active.media={pointerFine:mq("(pointer:fine)"),hoverHover:mq("(hover:hover)"),anyPointerFine:mq("(any-pointer:fine)")};}catch(e){}try{var vv=document.createElement("video");%P%.active.codecs={mp4:vv.canPlayType('video/mp4; codecs="avc1.42E01E"'),webm:vv.canPlayType('video/webm; codecs="vp9"')};}catch(e){}try{var cn=navigator.connection||navigator.mozConnection;%P%.active.connection=cn?{effectiveType:cn.effectiveType||null,downlink:typeof cn.downlink==="number"?cn.downlink:null}:null;}catch(e){}try{if(typeof window.RTCPeerConnection==="function"){var pc=new window.RTCPeerConnection();%P%.active.rtc=true;try{pc.close()}catch(e){}}else{%P%.active.rtc=false;}}catch(e){%P%.active.rtc=false;}try{ if(navigator.getBattery){%SF%pending.push(navigator.getBattery().then(function(b){%P%.active.battery={charging:!!b.charging,level:typeof b.level==="number"?b.level:null};}).catch(function(){}));} }catch(e){}}catch(e){}"#;

const ASYNC_AUDIO: &str = r#"try{var AC=window.OfflineAudioContext||window.webkitOfflineAudioContext;if(!AC){%P%.audio=null;}else{var ctx=new AC(1,5000,44100);var o=ctx.createOscillator();o.type="triangle";o.frequency.value=10000;var cp=ctx.createDynamicsCompressor();o.connect(cp);cp.connect(ctx.destination);o.start(0);var pr=ctx.startRendering();if(pr&&pr.then){%SF%pending.push(pr.then(function(buf){var out=0;var d=buf?buf.getChannelData(0):null;if(d){for(var i=4500;i<5000;i++)out+=Math.abs(d[i])}%P%.audio=out;}).catch(function(){%P%.audio=null}));}else{ctx.oncomplete=function(e){var buf=e.renderedBuffer;var out=0;var d=buf.getChannelData(0);for(var i=4500;i<5000;i++)out+=Math.abs(d[i]);%P%.audio=out;};}}}catch(e){%P%.audio=null;}"#;

const ASYNC_WEBGPU: &str = r#"try{ if(navigator.gpu&&navigator.gpu.requestAdapter){ %SF%pending.push(navigator.gpu.requestAdapter().then(function(a){ if(!a){%P%.webgpu={ok:false};return;} var i=a.info||{}; %P%.webgpu={ok:true,vendor:i.vendor||null,architecture:i.architecture||null,device:i.device||null,description:i.description||null}; }).catch(function(){%P%.webgpu={ok:false};})); }else{%P%.webgpu=null;} }catch(e){}"#;

/// Build the probe body: `var P={};function sf(k,f){...}function nat(fn){...}`
/// followed by the (shuffled) sync fields, opted-in extended fields, and the
/// async spawns (`P.__pending`).
///
/// Deviation: the reference wires IIFE-style extended snippets (`("webgl",
/// (function(){...})(),false)`) into the harness as *values*, so calling them
/// throws and the field is always `null`. We emit the same snippets as
/// functions so they actually produce data. Names/shape are unchanged.
pub fn build_probe(
    rng: &mut Rng,
    namer: &mut Namer,
    p: &str,
    extended: Option<&[String]>,
) -> String {
    let sf = namer.var(rng, None);
    let nat = namer.var(rng, None);
    let fonts = serde_json::to_string(&PROBE_FONT_STACKS.to_vec()).unwrap();
    let subs: &[(&str, &str)] = &[("%SF%", sf.as_str()), ("%NAT%", nat.as_str()), ("%FONTS%", fonts.as_str())];

    let mut fields: Vec<String> = BASE_FIELDS.iter().map(|f| tmpl(f, subs)).collect();
    rng.shuffle(&mut fields);

    let mut sync_ext: Vec<String> = Vec::new();
    let mut async_parts: Vec<String> = Vec::new();

    if let Some(keys) = extended {
        for key in keys {
            if let Some(snippet) = extended_sync_snippet(key) {
                // Snippet starts with "(" → prefix the harness call.
                sync_ext.push(format!("{}{}", sf, tmpl(snippet, subs)));
            }
        }
        rng.shuffle(&mut sync_ext);

        for key in keys {
            match key.as_str() {
                "workerUA" => async_parts.push(tmpl(
                    ASYNC_WORKER,
                    &[
                        ("%P%", p),
                        ("%SF%", sf.as_str()),
                        ("%WSRC%", json_str(WORKER_SRC).as_str()),
                    ],
                )),
                "storageQuota" => async_parts.push(tmpl(ASYNC_STORAGE, &[("%P%", p), ("%SF%", sf.as_str())])),
                "active" => async_parts.push(tmpl(ASYNC_ACTIVE, &[("%P%", p), ("%SF%", sf.as_str())])),
                "audio" => async_parts.push(tmpl(ASYNC_AUDIO, &[("%P%", p), ("%SF%", sf.as_str())])),
                "webgpu" => async_parts.push(tmpl(ASYNC_WEBGPU, &[("%P%", p), ("%SF%", sf.as_str())])),
                _ => {}
            }
        }
    }

    let async_spawns = if async_parts.is_empty() {
        String::new()
    } else {
        let mut s = format!("var {}pending=[];", sf);
        for part in &async_parts {
            s.push_str(part);
        }
        s.push_str(&format!(";{}.__pending={}pending;", p, sf));
        s
    };

    let preamble = tmpl(
        r#"var %P%={};function %SF%(k,f){try{%P%[k]=f()}catch(e){%P%[k]=null}}function %NAT%(fn){try{return /\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(fn))}catch(e){return true}}"#,
        &[("%P%", p), ("%SF%", sf.as_str()), ("%NAT%", nat.as_str())],
    );

    let mut out = String::with_capacity(16384);
    out.push_str(&preamble);
    for f in &fields {
        out.push_str(f);
    }
    for f in &sync_ext {
        out.push_str(f);
    }
    out.push_str(&async_spawns);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn namer_rng(seed: u64) -> (Rng, Namer) {
        (Rng::from_seed(seed), Namer::new())
    }

    #[test]
    fn ext_off_is_none() {
        let (mut r, mut n) = namer_rng(1);
        let _ = n.var(&mut r, None);
        assert!(resolve_extended_fields(&mut r, &ExtProbes::Off, 0.0).is_none());
    }

    #[test]
    fn ext_all_is_every_key() {
        let (mut r, _n) = namer_rng(2);
        let keys = resolve_extended_fields(&mut r, &ExtProbes::All, 0.0).unwrap();
        assert_eq!(keys.len(), EXTENDED_PROBE_KEYS.len());
        for k in EXTENDED_PROBE_KEYS {
            assert!(keys.iter().any(|x| x == k), "missing {}", k);
        }
    }

    #[test]
    fn ext_list_intersects_known_keys() {
        let (mut r, _n) = namer_rng(3);
        let list = ["webgl", "nope", "canvas", "webgl", "platform"];
        let keys = resolve_extended_fields(&mut r, &ExtProbes::List(&list), 0.0).unwrap();
        assert_eq!(keys, vec!["platform", "webgl", "canvas"]);
    }

    #[test]
    fn polymorphism_always_keeps_cross_checks() {
        for seed in 0..50u64 {
            let (mut r, _n) = namer_rng(seed);
            let keys = resolve_extended_fields(&mut r, &ExtProbes::All, 1.0).unwrap();
            assert!(keys.iter().any(|k| k == "platform"));
            assert!(keys.iter().any(|k| k == "workerUA"));
            assert!(keys.len() <= EXTENDED_PROBE_KEYS.len());
        }
    }

    #[test]
    fn probe_contains_every_field_name() {
        let (mut r, mut n) = namer_rng(5);
        let p = n.var(&mut r, None);
        let script = build_probe(&mut r, &mut n, &p, None);
        for field in [
            "ua",
            "productSub",
            "webdriver",
            "oscpu",
            "deviceMemory",
            "uaDataPresent",
            "uaData",
            "plugins",
            "pdfViewerEnabled",
            "engine",
            "evalShape",
            "nativeShape",
            "mimeCount",
            "languages",
            "chromeShape",
            "notifPerm",
            "screen",
            "outerWH",
            "isExtended",
            "fontWidths",
            "tamper",
            "cdp",
        ] {
            assert!(
                script.contains(&format!("\"{}\",function()", field))
                    || script.contains(&format!("\"{}\",(function()", field)),
                "missing field {}",
                field
            );
        }
    }

    #[test]
    fn extended_probe_emits_async_and_sync_parts() {
        let (mut r, mut n) = namer_rng(6);
        let p = n.var(&mut r, None);
        let keys: Vec<String> = EXTENDED_PROBE_KEYS.iter().map(|s| s.to_string()).collect();
        let script = build_probe(&mut r, &mut n, &p, Some(&keys));
        for needle in [
            "\"platform\",function()",
            "\"hardwareConcurrency\",function()",
            "\"webgl\",function()",
            "\"canvas\",function()",
            "\"emoji\",function()",
            "\"canvasStable\",function()",
        ] {
            assert!(script.contains(needle), "missing {}", needle);
        }
        assert!(script.contains("workerUA"));
        assert!(script.contains("storageQuota"));
        assert!(script.contains("__pending"));
        assert!(script.contains("navigator.gpu"));
    }
}
