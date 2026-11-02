//! Format-2 (v2) challenge/redeem support: `challenges[]` + AES-256-GCM sealed
//! expectations, with the `rsw` protocol. Wire-compatible with core's
//! `generateChallengeV2` / `validateChallengeV2`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

use cap_proto::{deserialize_keypair, verify_solution, RswMinter};

pub const INFO_FMT2: &str = "cap:fmt2-v1";

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn derive_key(secret: &str, info: &str) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(info.as_bytes());
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// AES-256-GCM, layout `base64url(iv[12] || tag[16] || ciphertext)` — the exact
/// format `core/src/crypto.js#encryptGcm` produces.
pub fn encrypt_gcm(data: &Value, secret: &str, info: &str) -> Option<String> {
    let key = derive_key(secret, info);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let mut iv = [0u8; 12];
    {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut iv);
    }
    let plaintext = serde_json::to_vec(data).ok()?;
    let sealed = cipher.encrypt(Nonce::from_slice(&iv), plaintext.as_ref()).ok()?;
    if sealed.len() < 16 {
        return None;
    }
    let split = sealed.len() - 16;
    let (ciphertext, tag) = sealed.split_at(split);
    let mut out = Vec::with_capacity(12 + 16 + ciphertext.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(tag);
    out.extend_from_slice(ciphertext);
    Some(URL_SAFE_NO_PAD.encode(out))
}

pub fn decrypt_gcm(blob: &str, secret: &str, info: &str) -> Option<Value> {
    let raw = URL_SAFE_NO_PAD.decode(blob).ok()?;
    if raw.len() < 28 {
        return None;
    }
    let iv = &raw[..12];
    let tag = &raw[12..28];
    let ciphertext = &raw[28..];
    let mut sealed = Vec::with_capacity(ciphertext.len() + 16);
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(tag);
    let key = derive_key(secret, info);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let plaintext = cipher.decrypt(Nonce::from_slice(iv), sealed.as_ref()).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

/// Build the CRT minter for a stored keypair and time parameter `t`. This is
/// the expensive step (two full-size modpows); callers cache the result.
pub fn rsw_minter(
    keypair_fields: &std::collections::HashMap<String, String>,
    t: u64,
) -> Option<RswMinter> {
    let kp_json = serde_json::json!({
        "N": keypair_fields.get("N")?,
        "p": keypair_fields.get("p")?,
        "q": keypair_fields.get("q")?,
        "bits": keypair_fields.get("bits").and_then(|b| b.parse::<usize>().ok()),
    });
    let kp = deserialize_keypair(&kp_json)?;
    RswMinter::build(&kp, t, None)
}

/// Build the rsw challenge entry: `{protocol, payload:{N,x,t}}` plus the sealed
/// expectation `{protocol:"rsw", y}`. Returns `(challenge, expected)`.
pub fn rsw_challenge(minter: &RswMinter) -> (Value, Value) {
    let minted = minter.mint();
    let challenge = json!({
        "protocol": "rsw",
        "payload": { "N": minter.n_hex, "x": minted.x_hex, "t": minter.t },
    });
    let expected = json!({ "protocol": "rsw", "y": minted.y_hex });
    (challenge, expected)
}

/// Build hashwx challenge entries + their sealed expectations.
pub fn hashwx_challenges(
    difficulty: u64,
    nonces_per_hash: u32,
    count: u32,
) -> Option<(Vec<Value>, Vec<Value>)> {
    let specs = cap_proto::hashwx::mint_challenges(difficulty, nonces_per_hash, count).ok()?;
    let mut challs = Vec::with_capacity(specs.len());
    let mut expected = Vec::with_capacity(specs.len());
    for spec in &specs {
        challs.push(json!({
            "protocol": "hashwx",
            "payload": { "c": spec.c_hex, "d": spec.d, "n": spec.n },
        }));
        expected.push(json!({
            "protocol": "hashwx", "c": spec.c_hex, "d": spec.d, "n": spec.n,
        }));
    }
    Some((challs, expected))
}

/// Parse a JSON nonce (u64 number or decimal string).
fn parse_nonce(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    let s = v.as_str()?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok()
}

/// Build the instrumentation challenge entry + its sealed meta.
/// `blob` is the raw-deflate+base64 script produced by `cap_instr::script_blob`.
pub fn instrumentation_challenge(
    challenge: &cap_instr::InstrChallenge,
    expires: i64,
) -> (Value, Value) {
    let payload = json!({
        "protocol": "instrumentation",
        "payload": { "blob": cap_instr::script_blob(&challenge.script) },
    });
    let meta = json!({
        "protocol": "instrumentation",
        "instrMeta": {
            "id": challenge.id,
            "expectedVals": challenge.expected_vals,
            "vars": challenge.vars,
            "blockAutomatedBrowsers": challenge.block_automated_browsers,
            "extendedFields": challenge.extended_fields,
            "scriptHash": challenge.script_hash,
            "macKey": challenge.mac_key,
            "iat": now_ms(),
            "expires": expires,
        },
    });
    (payload, meta)
}

/// JS seals `{ expected: [...] }`; older Rust builds sealed a bare array.
/// All expectation consumers must use the same envelope interpretation.
pub fn expected_entries(expected: &Value) -> Result<&[Value], String> {
    expected
        .get("expected")
        .unwrap_or(expected)
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| "invalid_expected".to_string())
}

/// Verify a v2 solution list; unknown protocols fail closed.
pub fn verify_solutions(expected: &Value, solutions: &[Value]) -> Result<(), String> {
    verify_solutions_observation(expected, solutions).map(|_| ())
}

pub(crate) fn verify_solutions_observation(expected: &Value, solutions: &[Value]) -> Result<VerifiedObservation, String> {
    let mut observation = None;
    let expected = expected_entries(expected)?;
    if expected.len() != solutions.len() {
        return Err("invalid_solutions".into());
    }
    for (idx, exp) in expected.iter().enumerate() {
        let sol = &solutions[idx];
        let proto = exp.get("protocol").and_then(Value::as_str).unwrap_or("");
        match proto {
            "rsw" => {
                let expected_y = exp.get("y").and_then(Value::as_str).unwrap_or("");
                let claimed = sol.get("y").and_then(Value::as_str).unwrap_or("");
                if !verify_solution(expected_y, claimed) {
                    return Err(format!("invalid_solution:{idx}"));
                }
            }
            "hashwx" => {
                let Some(c_hex) = exp.get("c").and_then(Value::as_str) else {
                    return Err("invalid_expected".into());
                };
                let d = exp.get("d").and_then(Value::as_u64).unwrap_or(0);
                let n = exp.get("n").and_then(Value::as_u64).unwrap_or(0);
                if n == 0 || n > cap_proto::hashwx::MAX_HASHWX_NONCES_PER_HASH as u64 {
                    return Err("invalid_expected".into());
                }
                let Some(nonce) = sol.get("nonce").and_then(parse_nonce) else {
                    return Err(format!("invalid_solution:{idx}"));
                };
                let spec = cap_proto::hashwx::HashwxSpec {
                    c_hex: c_hex.to_string(),
                    d,
                    n: n as u32,
                };
                if !cap_proto::hashwx::verify_solution(&spec, nonce) {
                    return Err(format!("invalid_solution:{idx}"));
                }
            }
            "instrumentation" => {
                let verified = verify_instr_observation(
                    exp.get("instrMeta")
                        .ok_or_else(|| "invalid_expected".to_string())?,
                    sol.get("instr").ok_or_else(|| "instr_missing".to_string())?,
                )?;
                // take_probe selects the first instrumentation entry too.
                if observation.is_none() { observation = Some(verified); }
            }
            other => return Err(format!("protocol_not_supported:{other}")),
        }
    }
    Ok(observation.unwrap_or_default())
}

/// Verify one instrumentation solution against its sealed meta. Shared by the
/// v2 challenge list and the v1 `ei` path.
pub fn verify_instr(meta: &Value, instr: &Value) -> Result<(), String> {
    verify_instr_observation(meta, instr).map(|_| ())
}

/// Evidence about protocol verification only; a valid client MAC does not prove
/// humanity. Constructed only after all existing instrumentation checks pass.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct VerifiedObservation {
    pub(crate) mac_verified: bool,
}

pub(crate) fn verify_instr_observation(meta: &Value, instr: &Value) -> Result<VerifiedObservation, String> {
    let mut mac_verified = false;
    let id_ok = instr.get("i").and_then(Value::as_str) == meta.get("id").and_then(Value::as_str);
    if !id_ok {
        return Err("instr_id_mismatch".into());
    }
    let state = instr
        .get("state")
        .ok_or_else(|| "instr_no_state".to_string())?;
    let vars = meta
        .get("vars")
        .and_then(Value::as_array)
        .ok_or_else(|| "invalid_expected".to_string())?;
    let vals = meta
        .get("expectedVals")
        .and_then(Value::as_array)
        .ok_or_else(|| "invalid_expected".to_string())?;
    if vars.len() != vals.len() {
        return Err("invalid_expected".into());
    }
    for (name, expected) in vars.iter().zip(vals.iter()) {
        let Some(key) = name.as_str() else {
            return Err("invalid_expected".into());
        };
        if state.get(key) != Some(expected) {
            return Err("instr_failed_challenge".into());
        }
    }
    // Tamper-evidence: the client HMACs id|ts|JSON(state)|JSON(p) with the
    // per-session key. Canonical JSON must reproduce the client's
    // `JSON.stringify` (see cap_instr::js_stringify).
    if let Some(mac_key) = meta.get("macKey").and_then(Value::as_str) {
        if !mac_key.is_empty() {
            let mac = instr.get("mac").and_then(Value::as_str).unwrap_or("");
            let ts_mac = instr.get("ts").and_then(Value::as_i64).unwrap_or(0);
            let id_str = meta.get("id").and_then(Value::as_str).unwrap_or("");
            let p_val = instr.get("p").cloned().unwrap_or(Value::Null);
            if !cap_instr::mac::verify_result_mac(mac_key, id_str, ts_mac, state, &p_val, mac) {
                return Err("instr_mac_mismatch".into());
            }
            mac_verified = true;
        }
    }
    // Replay window.
    let ts = instr.get("ts").and_then(Value::as_i64).unwrap_or(0);
    let iat = meta.get("iat").and_then(Value::as_i64).unwrap_or(0);
    let now = now_ms();
    if ts < iat.saturating_sub(5_000) || ts > now.saturating_add(120_000) {
        return Err("instr_ts_invalid".into());
    }
    // Structure is a protocol requirement, not a trust-score penalty. Check
    // the raw probe before sanitizing/merging top-frame data. Optional APIs
    // may be unavailable, even when extendedFields requested them.
    let p = instr.get("p").ok_or_else(|| "instr_probe_missing".to_string())?;
    if !cap_detect::probe_completeness(p, Some(cap_detect::PROBE_FONT_STACK_COUNT), &[]).is_empty() {
        return Err("instr_probe_invalid".into());
    }
    Ok(VerifiedObservation { mac_verified })
}

/// Extract the probe payload from an instrumentation solution (for detection).
pub struct ProbeCapture {
    pub p: Value,
    pub optional_fields: Vec<String>,
}

/// Call only after verify_instr: the MAC covers raw p, not sibling top.
/// Detection applies its shared top allowlist and gives signed base fields priority.
pub fn capture_instr(meta: &Value, instr: &Value) -> Option<ProbeCapture> {
    let mut p = instr.get("p")?.as_object()?.clone();
    if let Some(top) = instr.get("top").filter(|t| t.is_object()) {
        p.insert("top".into(), cap_detect::probes::capture_top(top));
    }
    let optional_fields = meta.get("extendedFields").and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    Some(ProbeCapture { p: Value::Object(p), optional_fields })
}

pub fn take_probe(expected: &Value, solutions: &[Value]) -> Option<ProbeCapture> {
    let expected = expected_entries(expected).ok()?;
    for (idx, exp) in expected.iter().enumerate() {
        if exp.get("protocol").and_then(Value::as_str) != Some("instrumentation") {
            continue;
        }
        let sol = solutions.get(idx)?;
        let instr = sol.get("instr")?;
        return capture_instr(exp.get("instrMeta")?, instr);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_probe() -> Value {
        json!({
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "productSub": "20030107", "oscpu": "__undefined",
            "uaDataPresent": false, "uaData": null,
            "plugins": {"length": 5}, "engine": {"hasChrome": false, "hasMozInnerScreenX": false},
            "screen": {"width": 1440, "height": 900}, "outerWH": [1440, 900],
            "isExtended": null, "tamper": null,
            "fontWidths": (0..cap_detect::PROBE_FONT_STACK_COUNT).map(|i| 1200.25 + i as f64).collect::<Vec<_>>()
        })
    }

    #[test]
    fn sealed_instrumentation_requires_valid_probe_in_both_protocols() {
        let meta = json!({"id":"test", "vars":["a"], "expectedVals":[7], "iat":now_ms(),
            "extendedFields":["webgl", "canvas", "webgpu"]});
        let expected = json!({"expected":[{"protocol":"instrumentation", "instrMeta":meta}]});
        let blob = encrypt_gcm(&expected, "secret", INFO_FMT2).unwrap();
        let wrapped = decrypt_gcm(&blob, "secret", INFO_FMT2).unwrap();
        let bare = wrapped["expected"].clone();
        let instr = json!({"i":"test", "state":{"a":7}, "ts":now_ms(), "p":valid_probe()});
        assert!(verify_instr(&meta, &instr).is_ok()); // v1 ei path
        for expected in [&wrapped, &bare] {
            let sols = [json!({"instr":instr})];
            assert!(verify_solutions(expected, &sols).is_ok());
            assert_eq!(take_probe(expected, &sols).unwrap().p, instr["p"]);
            for bad in [None, Some(json!({})), Some(Value::Null), Some(json!([])), Some(json!("bad"))] {
                let mut malformed = instr.clone();
                match bad {
                    None => { malformed.as_object_mut().unwrap().remove("p"); }
                    Some(p) => malformed["p"] = p,
                }
                assert!(verify_instr(&meta, &malformed).is_err());
                assert!(verify_solutions(expected, &[json!({"instr":malformed})]).is_err());
            }
            for name in valid_probe().as_object().unwrap().keys() {
                let mut missing = instr.clone();
                missing["p"].as_object_mut().unwrap().remove(name);
                assert!(verify_instr(&meta, &missing).is_err(), "missing {name}");
                assert!(verify_solutions(expected, &[json!({"instr":missing})]).is_err());
                let mut wrong = instr.clone();
                wrong["p"][name] = json!(42);
                assert!(verify_instr(&meta, &wrong).is_err(), "wrong type {name}");
                assert!(verify_solutions(expected, &[json!({"instr":wrong})]).is_err());
            }
        }
    }

    #[test]
    fn wrapped_verified_probe_reaches_detection_and_honeypot_denies() {
        let meta = json!({"id":"test", "vars":[], "expectedVals":[], "iat":now_ms()});
        let expected = json!({"expected":[{"protocol":"instrumentation", "instrMeta":meta}]});
        let sols = [json!({"instr":{"i":"test", "state":{}, "ts":now_ms(), "p":valid_probe()}})];
        verify_solutions(&expected, &sols).unwrap();
        let captured = take_probe(&expected, &sols).unwrap();
        let outcome = cap_detect::detect_automation(&captured.p, &cap_detect::DetectOpts {
            font_stack_count: Some(cap_detect::PROBE_FONT_STACK_COUNT),
            optional_fields: &captured.optional_fields, accept_language: None,
        });
        assert!(outcome.pass, "{:?}", outcome.blocked_by);
        let mut signals: Vec<_> = outcome.signals.iter().map(|s| s.as_signal()).collect();
        let clean = cap_detect::compute_trust_signals(&signals, None, Some(outcome.pass));
        assert_eq!(cap_detect::trust_action(&clean), cap_detect::Action::Allow);
        signals.push(cap_detect::Signal::gating("honeypot_triggered"));
        let trapped = cap_detect::compute_trust_signals(&signals, None, Some(outcome.pass));
        assert_eq!(cap_detect::trust_action(&trapped), cap_detect::Action::Deny);
    }

    fn signed_instr(meta: &Value, p: Value) -> Value {
        let mut instr = json!({"i":"test", "state":{"a":7}, "ts":now_ms(), "p":p});
        // Same canonical message and ASCII hex-key encoding as the JS producer.
        let message = format!("cap-instr|test|{}|{}|{}", instr["ts"],
            cap_instr::js_stringify(&instr["state"]), cap_instr::js_stringify(&instr["p"]));
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(meta["macKey"].as_str().unwrap().as_bytes()).unwrap();
        mac.update(message.as_bytes());
        instr["mac"] = json!(mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>());
        instr
    }

    fn verified_outcome(meta: &Value, instr: &Value, v2: bool) -> cap_detect::DetectOutcome {
        let captured = if v2 {
            let expected = json!({"expected":[{"protocol":"instrumentation", "instrMeta":meta}]});
            let sealed = encrypt_gcm(&expected, "secret", INFO_FMT2).unwrap();
            let expected = decrypt_gcm(&sealed, "secret", INFO_FMT2).unwrap();
            let sols = [json!({"instr":instr})];
            verify_solutions(&expected, &sols).unwrap();
            take_probe(&expected, &sols).unwrap()
        } else {
            verify_instr(meta, instr).unwrap();
            capture_instr(meta, instr).unwrap()
        };
        cap_detect::detect_automation(&captured.p, &cap_detect::DetectOpts {
            font_stack_count: Some(cap_detect::PROBE_FONT_STACK_COUNT),
            optional_fields: &captured.optional_fields, accept_language: None,
        })
    }

    fn action(outcome: &cap_detect::DetectOutcome) -> cap_detect::Action {
        let signals: Vec<_> = outcome.signals.iter().map(|s| s.as_signal()).collect();
        cap_detect::trust_action(&cap_detect::compute_trust_signals(&signals, None, Some(outcome.pass)))
    }

    #[test]
    fn signed_optional_absence_and_observations_follow_complete_pipeline() {
        let meta = json!({"id":"test", "vars":["a"], "expectedVals":[7], "iat":now_ms(),
            "macKey":"0123456789abcdef0123456789abcdef",
            "extendedFields":["workerUA", "storageQuota", "webgl", "cdp", "evalShape", "webgpu"]});
        for v2 in [false, true] {
            let instr = signed_instr(&meta, valid_probe());
            let clean = verified_outcome(&meta, &instr, v2);
            assert!(clean.pass, "{:?}", clean.blocked_by);
            assert_eq!(action(&clean), cap_detect::Action::Allow);
            for (field, value, signal) in [
                ("workerUA", json!("different UA"), "worker_ua_mismatch"),
                ("storageQuota", json!(1024), "storage_quota_tiny"),
                ("webgl", json!({"ok":true,"renderer":"SwiftShader"}), "webgl_software_renderer"),
            ] {
                let mut probe = valid_probe();
                probe[field] = value;
                let observed = verified_outcome(&meta, &signed_instr(&meta, probe), v2);
                assert!(observed.signals.iter().any(|s| s.id == signal), "{field}: {:?}", observed.signals);
                if field == "workerUA" {
                    assert_eq!(action(&observed), cap_detect::Action::Deny);
                } else {
                    // Quota/render observations remain scored signals, not
                    // automatic protocol errors merely because an API exists.
                    let signals: Vec<_> = observed.signals.iter().map(|s| s.as_signal()).collect();
                    let trust = cap_detect::compute_trust_signals(&signals, None, Some(observed.pass));
                    assert!(trust.score < 100);
                    assert_eq!(action(&observed), cap_detect::trust_action(&trust));
                }
            }
            let mut wrong = valid_probe();
            wrong["ua"] = json!(42);
            assert_eq!(verify_instr(&meta, &signed_instr(&meta, wrong)), Err("instr_probe_invalid".into()));
            let mut tampered = instr.clone();
            tampered["p"]["ua"] = json!("changed after signing");
            assert_eq!(verify_instr(&meta, &tampered), Err("instr_mac_mismatch".into()));
            let mut top = instr.clone();
            top["top"] = json!({"automationGlobals":["__playwright__binding__"], "ua":"ignored", "webdriver":true});
            let capture = capture_instr(&meta, &top).unwrap();
            assert!(capture.p["top"].get("ua").is_none());
            assert!(capture.p["top"].get("webdriver").is_none());
            let trapped = verified_outcome(&meta, &top, v2);
            assert!(trapped.blocked_by.iter().any(|s| s == "automation_globals_main"));
            assert_eq!(action(&trapped), cap_detect::Action::Deny);
            assert_eq!(top["p"], instr["p"]); // capture never mutates MAC input
        }
    }

    #[test]
    fn observation_requires_real_mac_for_both_signed_protocol_fixtures() {
        let meta = json!({"id":"test", "vars":["a"], "expectedVals":[7], "iat":now_ms(),
            "macKey":"0123456789abcdef0123456789abcdef"});
        for is_v2 in [false, true] {
            let instr = signed_instr(&meta, valid_probe());
            let verify = |meta: &Value, instr: &Value| {
                // Exercise the actual sealed v1 metadata and v2 expectation paths.
                if is_v2 {
                    let sealed = encrypt_gcm(&json!({"expected":[{"protocol":"instrumentation","instrMeta":meta}]}), "secret", INFO_FMT2).unwrap();
                    let expected = decrypt_gcm(&sealed, "secret", INFO_FMT2).unwrap();
                    verify_solutions_observation(&expected, &[json!({"instr":instr})])
                } else {
                    let sealed = encrypt_gcm(meta, "secret", INFO_FMT2).unwrap();
                    verify_instr_observation(&decrypt_gcm(&sealed, "secret", INFO_FMT2).unwrap(), instr)
                }
            };
            let verified = verify(&meta, &instr).unwrap();
            assert!(verified.mac_verified);
            assert!(crate::training_capture::eligible(true, verified.mac_verified, true));
            assert!(!crate::training_capture::eligible(true, verified.mac_verified, false));
            assert!(!crate::training_capture::eligible(false, verified.mac_verified, true));
            let mut tampered = instr.clone();
            tampered["p"]["ua"] = json!("tampered");
            assert!(verify(&meta, &tampered).is_err());
            let mut legacy = meta.clone();
            legacy.as_object_mut().unwrap().remove("macKey");
            let legacy_verified = verify(&legacy, &instr).unwrap();
            assert!(!legacy_verified.mac_verified);
            assert!(!crate::training_capture::eligible(true, legacy_verified.mac_verified, true));
            legacy["macKey"] = json!("");
            assert!(!verify(&legacy, &instr).unwrap().mac_verified);
            legacy["iat"] = json!(i64::MIN);
            assert!(!verify(&legacy, &instr).unwrap().mac_verified);
        }
    }

    #[test]
    fn gcm_roundtrip_matches_js_layout() {
        let data = json!({"protocol":"rsw","y":"abcd"});
        let blob = encrypt_gcm(&data, "secret-1", INFO_FMT2).unwrap();
        let raw = URL_SAFE_NO_PAD.decode(&blob).unwrap();
        assert_eq!(raw.len(), 12 + 16 + serde_json::to_vec(&data).unwrap().len());
        let back = decrypt_gcm(&blob, "secret-1", INFO_FMT2).unwrap();
        assert_eq!(back, data);
        assert!(decrypt_gcm(&blob, "other", INFO_FMT2).is_none());
    }

    #[test]
    fn take_probe_extracts_p_and_top() {
        let expected = json!([
            {"protocol":"rsw","y":"aa"},
            {"protocol":"instrumentation","instrMeta":{"extendedFields":["webgl","canvas"]}}
        ]);
        let solutions = json!([
            {"y":"aa"},
            {"instr":{"i":"x","state":{"a":1},"p":{"ua":"UA","webgl":null},"top":{"canvas":"abc"}}}
        ]);
        let cap = super::take_probe(&expected, solutions.as_array().unwrap()).unwrap();
        assert_eq!(cap.p["ua"], "UA");
        assert_eq!(cap.p["top"]["canvas"], "abc");
        assert_eq!(cap.optional_fields, vec!["webgl", "canvas"]);
    }

    #[test]
    fn solutions_verify_and_reject() {
        let expected = json!([{"protocol":"rsw","y":"00ab"}]);
        assert!(verify_solutions(&expected, &[json!({"y":"0x00AB"})]).is_ok());
        assert!(verify_solutions(&expected, &[json!({"y":"00ac"})]).is_err());
        assert!(verify_solutions(&expected, &[]).is_err());
        assert!(verify_solutions(&json!([{"protocol":"hashwx"}]), &[json!({})]).is_err());
    }
}
