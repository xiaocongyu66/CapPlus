//! Cap core primitives, ported 1:1 from the JavaScript implementation so that
//! tokens/challenges produced by either stack stay mutually verifiable.
//!
//! Ported so far: FNV-1a + xorshift PRNG, SHA-256 helpers, HS256 JWT
//! (sign/verify), the sha256-pow solution check, UA hashing and the session
//! bind record.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn sha256_hex(input: impl AsRef<[u8]>) -> String {
    hex(&Sha256::digest(input.as_ref()))
}

pub fn random_hex(len: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; len.div_ceil(2)];
    rand::thread_rng().fill_bytes(&mut buf);
    hex(&buf)[..len].to_string()
}

/// FNV-1a over the seed, matching `core/src/prng.js` (including the JS quirk
/// where the multiply-add is evaluated in doubles and truncated with ToInt32
/// at the start of the next iteration).
pub fn fnv1a(seed: &str) -> u32 {
    let mut h: i32 = 0x811C9DC5u32 as i32;
    for b in seed.bytes() {
        h ^= b as i32;
        let h64 = h as i64;
        let s1 = h.wrapping_shl(1) as i64;
        let s4 = h.wrapping_shl(4) as i64;
        let s7 = h.wrapping_shl(7) as i64;
        let s8 = h.wrapping_shl(8) as i64;
        let s24 = h.wrapping_shl(24) as i64;
        let sum = h64 + s1 + s4 + s7 + s8 + s24;
        h = (sum as u32) as i32;
    }
    h as u32
}

pub fn prng_from_hash(initial: u32, len: usize) -> String {
    let mut state = initial;
    let mut out = String::with_capacity(len + 8);
    while out.len() < len {
        state ^= state.wrapping_shl(13);
        state ^= state >> 17;
        state ^= state.wrapping_shl(5);
        out.push_str(&format!("{state:08x}"));
    }
    out.truncate(len);
    out
}

pub fn prng(seed: &str, len: usize) -> String {
    prng_from_hash(fnv1a(seed), len)
}

// ---------------------------------------------------------------------------
// JWT (HS256), wire-compatible with core/src/crypto.js
// ---------------------------------------------------------------------------

const JWT_HEADER_B64: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

fn hmac_sha256(secret: &str, msg: &str) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(msg.as_bytes());
    mac.finalize().into_bytes().into()
}

pub fn jwt_sign(payload: &serde_json::Value, secret: &str) -> String {
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("json"));
    let signing_input = format!("{JWT_HEADER_B64}.{body}");
    let sig = URL_SAFE_NO_PAD.encode(hmac_sha256(secret, &signing_input));
    format!("{signing_input}.{sig}")
}

/// Returns the decoded payload when the signature matches, `None` otherwise.
pub fn jwt_verify(token: &str, secret: &str) -> Option<serde_json::Value> {
    // Pin the header instead of only relying on the HMAC: the signing input
    // must be the exact HS256/JWT header we issue.
    let rest = token.strip_prefix(JWT_HEADER_B64)?.strip_prefix('.')?;
    let last = rest.rfind('.')?;
    if rest.is_empty() {
        return None;
    }
    let sig_b64 = &rest[last + 1..];
    let actual = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    let expected = hmac_sha256(secret, &token[..token.len() - sig_b64.len() - 1]);
    if actual.ct_eq(&expected).unwrap_u8() != 1 {
        return None;
    }
    let payload_b64 = &rest[..last];
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Raw signature bytes of a JWT (used as the nonce-consumption key).
pub fn jwt_sig_hex(token: &str) -> Option<String> {
    let last = token.rfind('.')?;
    let sig = URL_SAFE_NO_PAD.decode(&token[last + 1..]).ok()?;
    Some(hex(&sig))
}

// ---------------------------------------------------------------------------
// Proof of work (sha256-pow, v1 payload: {n,c,s,d,exp,iat,sk})
// ---------------------------------------------------------------------------

pub const MAX_CHALLENGE_COUNT: u32 = 1000;
// Match the JS reference (core/src/index.js): 256 / 16. Lower limits made the
// Rust server reject challenges the JS backend had already issued.
pub const MAX_CHALLENGE_SIZE: u32 = 256;
pub const MAX_CHALLENGE_DIFFICULTY: u32 = 16;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PowParams {
    pub c: u32,
    pub s: u32,
    pub d: u32,
}

impl PowParams {
    pub fn valid(&self) -> bool {
        (1..=MAX_CHALLENGE_COUNT).contains(&self.c)
            && (1..=MAX_CHALLENGE_SIZE).contains(&self.s)
            && (1..=MAX_CHALLENGE_DIFFICULTY).contains(&self.d)
    }
}

/// Verify a submitted solution set against the parameters sealed in the token.
/// Mirrors `validateChallenge`: exact count, and every solution hashes to a
/// value prefixed with the difficulty target derived from the token itself.
pub fn verify_pow(token: &str, params: PowParams, solutions: &[u64]) -> bool {
    if solutions.len() as u32 != params.c {
        return false;
    }
    let target_len = params.d as usize;
    for (i, n) in solutions.iter().enumerate() {
        let idx = i + 1;
        let salt = prng(&format!("{token}{idx}"), params.s as usize);
        let target = prng(&format!("{token}{idx}d"), target_len);
        let h = sha256_hex(format!("{salt}{n}"));
        if !h.starts_with(&target) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Session binding
// ---------------------------------------------------------------------------

pub fn ua_hash(ua: &str) -> String {
    sha256_hex(ua)[..32].to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBind {
    pub ip: Option<String>,
    pub ua: Option<String>,
    pub host: Option<String>,
    pub ts: i64,
}

impl SessionBind {
    pub fn new(ip: Option<String>, ua: &str, ts: i64) -> Self {
        Self {
            ip: ip.filter(|s| !s.is_empty()),
            ua: Some(ua_hash(ua)),
            // Verified embedding: the request origin is the Cap origin, which
            // says nothing about the app — host stays unbound.
            host: None,
            ts,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("bind json")
    }

    pub fn matches(&self, strict: bool, ctx_ip: &str, ctx_ua: &str, ctx_host: &str) -> bool {
        let ua_ok = match &self.ua {
            None => true,
            Some(b) if b.is_empty() => true,
            Some(b) => !ctx_ua.is_empty() && ua_hash(ctx_ua) == *b,
        };
        let ip_ok = match &self.ip {
            None => true,
            Some(b) => {
                if strict {
                    !ctx_ip.is_empty() && b == ctx_ip
                } else {
                    ctx_ip.is_empty() || b == ctx_ip
                }
            }
        };
        let host_ok = match &self.host {
            None => true,
            Some(b) => {
                if strict {
                    !ctx_host.is_empty() && b == ctx_host
                } else {
                    ctx_host.is_empty() || b == ctx_host
                }
            }
        };
        ua_ok && ip_ok && host_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_matches_js() {
        assert_eq!(fnv1a("test"), 2949673445);
        assert_eq!(fnv1a("hello world"), 3582672807);
    }

    #[test]
    fn prng_matches_js() {
        assert_eq!(prng("test", 16), "9c7ca3730a4a283a");
        assert_eq!(prng("e1ff69493d1", 32), "0bb5dde1b13d194550a3b9afd55f06e4");
        assert_eq!(prng("e1ff69493d1d", 4), "ef18");
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex("abc1234"),
            "36f583dd16f4e1e201eb1e6f6d8e35a2ccb3bbe2658de46b4ffae7b0e9ed872e"
        );
    }

    #[test]
    fn jwt_roundtrip_and_tamper() {
        let payload = serde_json::json!({"n":"abc","c":2,"s":8,"d":1,"exp":1_900_000_000_000i64});
        let token = jwt_sign(&payload, "secret-key");
        assert_eq!(jwt_verify(&token, "secret-key"), Some(payload));
        assert!(jwt_verify(&token, "other-key").is_none());
        let mut tampered = token.clone();
        tampered.push('x');
        assert!(jwt_verify(&tampered, "secret-key").is_none());
    }

    #[test]
    fn pow_solutions_verify() {
        // Solve a tiny challenge the same way the client does.
        let token = "abc123:tok";
        let params = PowParams { c: 2, s: 8, d: 1 };
        let mut sols = vec![];
        for i in 1..=2u32 {
            let salt = prng(&format!("{token}{i}"), params.s as usize);
            let target = prng(&format!("{token}{i}d"), params.d as usize);
            let mut n = 0u64;
            loop {
                if sha256_hex(format!("{salt}{n}")).starts_with(&target) {
                    sols.push(n);
                    break;
                }
                n += 1;
            }
        }
        assert!(verify_pow(token, params, &sols));
        let mut bad = sols.clone();
        bad[0] += 1;
        assert!(!verify_pow(token, params, &bad));
        // count mismatch
        assert!(!verify_pow(token, params, &sols[..1]));
    }

    #[test]
    fn bind_matching_rules() {
        let b = SessionBind::new(Some("1.2.3.4".into()), "UA", 1);
        assert!(b.matches(true, "1.2.3.4", "UA", ""));
        assert!(!b.matches(true, "", "UA", ""));
        assert!(b.matches(false, "", "UA", ""));
        assert!(!b.matches(false, "1.2.3.4", "other", ""));
    }
}
