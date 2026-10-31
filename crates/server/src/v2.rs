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

/// Build the rsw challenge entry: `{protocol, payload:{N,x,t}}` plus the sealed
/// expectation `{protocol:"rsw", y}`. Returns `(challenge, expected)`.
pub fn rsw_challenge(
    keypair_fields: &std::collections::HashMap<String, String>,
    t: u64,
) -> Option<(Value, Value)> {
    let kp_json = serde_json::json!({
        "N": keypair_fields.get("N")?,
        "p": keypair_fields.get("p")?,
        "q": keypair_fields.get("q")?,
        "bits": keypair_fields.get("bits").and_then(|b| b.parse::<usize>().ok()),
    });
    let kp = deserialize_keypair(&kp_json)?;
    let minter = RswMinter::build(&kp, t, None)?;
    let minted = minter.mint();
    let challenge = json!({
        "protocol": "rsw",
        "payload": { "N": minter.n_hex, "x": minted.x_hex, "t": minter.t },
    });
    let expected = json!({ "protocol": "rsw", "y": minted.y_hex });
    Some((challenge, expected))
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

/// Verify a v2 solution list against the sealed expectations. Supports the
/// `rsw` protocol; unknown protocols fail closed.
pub fn verify_solutions(expected: &Value, solutions: &[Value]) -> Result<(), String> {
    let expected = expected
        .as_array()
        .ok_or_else(|| "invalid_expected".to_string())?;
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
                // Solution shape: {instr:{i,state,p,ts,mac,scriptHash}} |
                // {blocked:true} | {timeout:true}.
                if sol.get("blocked").and_then(Value::as_bool) == Some(true) {
                    return Err("instr_blocked".into());
                }
                if sol.get("timeout").and_then(Value::as_bool) == Some(true) {
                    return Err("instr_timeout".into());
                }
                let Some(instr) = sol.get("instr") else {
                    return Err("instr_missing".into());
                };
                let meta = exp
                    .get("instrMeta")
                    .ok_or_else(|| "invalid_expected".to_string())?;
                let id_ok = instr.get("i").and_then(Value::as_str)
                    == meta.get("id").and_then(Value::as_str);
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
                        return Err(format!("instr_failed_challenge:{idx}"));
                    }
                }
                // Tamper-evidence: the client HMACs id|ts|JSON(state)|JSON(p)
                // with the per-session key. Canonical JSON must reproduce the
                // client's `JSON.stringify` (see cap_instr::js_stringify).
                if let Some(mac_key) = meta.get("macKey").and_then(Value::as_str) {
                    if !mac_key.is_empty() {
                        let mac = instr.get("mac").and_then(Value::as_str).unwrap_or("");
                        let ts_mac = instr.get("ts").and_then(Value::as_i64).unwrap_or(0);
                        let id_str = meta.get("id").and_then(Value::as_str).unwrap_or("");
                        let p_val = instr.get("p").cloned().unwrap_or(Value::Null);
                        if !cap_instr::mac::verify_result_mac(
                            mac_key, id_str, ts_mac, state, &p_val, mac,
                        ) {
                            return Err(format!("instr_mac_mismatch:{idx}"));
                        }
                    }
                }
                // Replay window.
                let ts = instr.get("ts").and_then(Value::as_i64).unwrap_or(0);
                let iat = meta.get("iat").and_then(Value::as_i64).unwrap_or(0);
                let now = now_ms();
                if ts < iat - 5_000 || ts > now + 120_000 {
                    return Err("instr_ts_invalid".into());
                }
            }
            other => return Err(format!("protocol_not_supported:{other}")),
        }
    }
    Ok(())
}

/// Extract the probe payload from an instrumentation solution (for detection).
pub struct ProbeCapture {
    pub p: Value,
    pub optional_fields: Vec<String>,
}

pub fn take_probe(expected: &Value, solutions: &[Value]) -> Option<ProbeCapture> {
    let expected = expected.as_array()?;
    for (idx, exp) in expected.iter().enumerate() {
        if exp.get("protocol").and_then(Value::as_str) != Some("instrumentation") {
            continue;
        }
        let sol = solutions.get(idx)?;
        let instr = sol.get("instr")?;
        let p = instr.get("p")?.clone();
        // `top` supplements (canvas/WebGL/automationGlobals measured in the top
        // document) live next to `p` on the solution; detect merges them.
        let mut vector = p;
        if let Some(top) = instr.get("top") {
            if vector.is_object() {
                vector["top"] = top.clone();
            }
        }
        let optional_fields = exp
            .get("instrMeta")
            .and_then(|m| m.get("extendedFields"))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        return Some(ProbeCapture {
            p: vector,
            optional_fields,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
