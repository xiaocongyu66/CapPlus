//! HashWX proof-of-work — port of `core/src/hashwx.js`.
//!
//! The hash itself is an opaque pseudo-random permutation implemented in a
//! WASM interpreter module (`core/src/hashwx.wasm`, the "interpreted" backend
//! — the same one `hashwx.js` uses in Node). We embed that exact module and run
//! it with `wasmi`, so the Rust verifier is bit-compatible with the JS one
//! without reimplementing the hash.
//!
//! Protocol:
//!   * `seed  = sha256(challenge[32] || block as u64 LE)`
//!   * write `seed` into the module's buffer at `hashwx_seed(ctx)`, call
//!     `hashwx_make(ctx, seed_ptr)`, then `hashwx_exec(ctx, nonce)` → u64.
//!   * a solution is valid when `hash(seed, nonce) <= U64_MAX / difficulty`.
//!
//! The instance is initialised lazily behind a `OnceLock<Mutex<..>>`. If the
//! module cannot be instantiated (e.g. an unsupported wasm feature) every
//! `hash_nonce` returns `None` instead of panicking; the reason is logged once
//! to stderr.

use std::num::NonZeroU64;
use std::sync::{Mutex, OnceLock};

use rand::RngCore;
use sha2::{Digest, Sha256};
use wasmi::{Engine, Linker, Memory, Module, Store, TypedFunc};

pub const HASHWX_CHALLENGE_SIZE: usize = 32;
pub const HASHWX_SEED_SIZE: usize = 32;

pub const DEFAULT_HASHWX_NONCES_PER_HASH: u32 = 65_536;
pub const DEFAULT_HASHWX_DIFFICULTY: u64 = 1_000_000;
pub const DEFAULT_HASHWX_CHALLENGE_COUNT: u32 = 4;

pub const MAX_HASHWX_DIFFICULTY: u64 = 1_000_000_000;
pub const MAX_HASHWX_NONCES_PER_HASH: u32 = 1_048_576;
pub const MAX_HASHWX_CHALLENGE_COUNT: u32 = 64;

/// `0` selects the interpreted backend, as in `hashwx.js`.
const HASHWX_INTERPRETED: i32 = 0;

/// The exact module shipped with the JS core.
static HASHWX_WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../cap/core/src/hashwx.wasm"
));

/// A single minted challenge: hex-encoded 32-byte challenge `c`, the
/// per-challenge difficulty `d`, and `n`, how many nonces share one seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashwxSpec {
    pub c_hex: String,
    pub d: u64,
    pub n: u32,
}

struct HashwxState {
    store: Store<()>,
    memory: Memory,
    make: TypedFunc<(i32, i32), ()>,
    exec: TypedFunc<(i32, i64), i64>,
    ctx: i32,
    seed_ptr: i32,
}

fn init_state() -> Result<HashwxState, String> {
    let engine = Engine::default();
    let module = Module::new(&engine, HASHWX_WASM).map_err(|e| format!("module: {e}"))?;
    let mut store = Store::new(&engine, ());
    let linker: Linker<()> = Linker::new(&engine);
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| format!("instantiate: {e}"))?
        .start(&mut store)
        .map_err(|e| format!("start: {e}"))?;

    // Reactor-style module: initialise constructors before touching memory.
    if let Ok(init_fn) = instance.get_typed_func::<(), ()>(&store, "_initialize") {
        init_fn
            .call(&mut store, ())
            .map_err(|e| format!("_initialize: {e}"))?;
    }

    let alloc = instance
        .get_typed_func::<i32, i32>(&store, "hashwx_alloc")
        .map_err(|e| format!("hashwx_alloc: {e}"))?;
    let ctx = alloc
        .call(&mut store, HASHWX_INTERPRETED)
        .map_err(|e| format!("hashwx_alloc call: {e}"))?;
    if ctx <= 0 {
        return Err(format!("hashwx_alloc returned {ctx}"));
    }

    let seed_fn = instance
        .get_typed_func::<i32, i32>(&store, "hashwx_seed")
        .map_err(|e| format!("hashwx_seed: {e}"))?;
    let seed_ptr = seed_fn
        .call(&mut store, ctx)
        .map_err(|e| format!("hashwx_seed call: {e}"))?;

    let make = instance
        .get_typed_func::<(i32, i32), ()>(&store, "hashwx_make")
        .map_err(|e| format!("hashwx_make: {e}"))?;
    let exec = instance
        .get_typed_func::<(i32, i64), i64>(&store, "hashwx_exec")
        .map_err(|e| format!("hashwx_exec: {e}"))?;
    let memory = instance
        .get_memory(&store, "memory")
        .ok_or_else(|| "missing `memory` export".to_string())?;

    Ok(HashwxState {
        store,
        memory,
        make,
        exec,
        ctx,
        seed_ptr,
    })
}

/// Lazily initialised, process-wide interpreter instance. `None` if init failed
/// (logged once at initialisation time).
fn state() -> Option<&'static Mutex<HashwxState>> {
    static STATE: OnceLock<Option<Mutex<HashwxState>>> = OnceLock::new();
    STATE
        .get_or_init(|| match init_state() {
            Ok(state) => Some(Mutex::new(state)),
            Err(err) => {
                eprintln!("[cap-proto] hashwx: wasm instantiation failed: {err}");
                None
            }
        })
        .as_ref()
}

impl HashwxState {
    fn run(&mut self, seed: &[u8; HASHWX_SEED_SIZE], nonce: u64) -> Option<u64> {
        let offset = usize::try_from(self.seed_ptr).ok()?;
        self.memory.write(&mut self.store, offset, seed).ok()?;
        self.make
            .call(&mut self.store, (self.ctx, self.seed_ptr))
            .ok()?;
        let out = self
            .exec
            .call(&mut self.store, (self.ctx, nonce as i64))
            .ok()?;
        Some(out as u64)
    }
}

/// `U64_MAX / difficulty`; `None` when `difficulty == 0` (divides by zero in
/// the reference implementation).
pub fn hashwx_target(difficulty: u64) -> Option<u64> {
    let divisor = NonZeroU64::new(difficulty)?;
    Some(u64::MAX / divisor.get())
}

/// `sha256(challenge || block as u64 LE)`.
pub fn hashwx_seed(challenge: &[u8; HASHWX_CHALLENGE_SIZE], block: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(block.to_le_bytes());
    hasher.finalize().into()
}

/// Hash `seed` with `nonce` via the embedded WASM module. `None` if the module
/// could not be instantiated or a call trapped.
pub fn hash_nonce(seed: &[u8; HASHWX_SEED_SIZE], nonce: u64) -> Option<u64> {
    let mutex = state()?;
    let mut guard = mutex.lock().unwrap_or_else(|poison| poison.into_inner());
    guard.run(seed, nonce)
}

/// `max(1, round(difficulty / count))`, computed with integer half-up rounding
/// to match `Math.round` without floating point.
fn each_difficulty(difficulty: u64, count: u32) -> u64 {
    let count = u64::from(count);
    let each = (difficulty.saturating_mul(2).saturating_add(count)) / (2 * count);
    each.max(1)
}

fn validate(difficulty: u64, nonces_per_hash: u32, count: u32) -> Result<(), String> {
    if !(1..=MAX_HASHWX_DIFFICULTY).contains(&difficulty) {
        return Err(format!(
            "hashwxDifficulty must be an integer in [1, {MAX_HASHWX_DIFFICULTY}]"
        ));
    }
    if !(1..=MAX_HASHWX_NONCES_PER_HASH).contains(&nonces_per_hash) {
        return Err(format!(
            "hashwxNoncesPerHash must be an integer in [1, {MAX_HASHWX_NONCES_PER_HASH}]"
        ));
    }
    if !(1..=MAX_HASHWX_CHALLENGE_COUNT).contains(&count) {
        return Err(format!(
            "hashwxChallengeCount must be an integer in [1, {MAX_HASHWX_CHALLENGE_COUNT}]"
        ));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    out
}

fn hex_decode_32(hex: &str) -> Option<[u8; HASHWX_CHALLENGE_SIZE]> {
    let bytes = hex.as_bytes();
    if bytes.len() != HASHWX_CHALLENGE_SIZE * 2 {
        return None;
    }
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; HASHWX_CHALLENGE_SIZE];
    for (i, pair) in out.iter_mut().enumerate() {
        *pair = (nibble(bytes[i * 2])? << 4) | nibble(bytes[i * 2 + 1])?;
    }
    Some(out)
}

/// Mint `count` challenges whose per-challenge difficulty sums to roughly
/// `difficulty`.
pub fn mint_challenges(
    difficulty: u64,
    nonces_per_hash: u32,
    count: u32,
) -> Result<Vec<HashwxSpec>, String> {
    validate(difficulty, nonces_per_hash, count)?;

    let each = each_difficulty(difficulty, count);
    let mut rng = rand::rngs::OsRng;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut challenge = [0u8; HASHWX_CHALLENGE_SIZE];
        rng.fill_bytes(&mut challenge);
        out.push(HashwxSpec {
            c_hex: hex_encode(&challenge),
            d: each,
            n: nonces_per_hash,
        });
    }
    Ok(out)
}

/// Parse a `nonce` JSON value: an unsigned integer number or a decimal string
/// that fits in a `u64`.
pub fn parse_nonce(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => {
            if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            s.parse::<u64>().ok()
        }
        _ => None,
    }
}

/// Verify `nonce` against a minted [`HashwxSpec`]. Never panics.
pub fn verify_solution(spec: &HashwxSpec, nonce: u64) -> bool {
    let Some(challenge) = hex_decode_32(&spec.c_hex) else {
        return false;
    };
    if !(1..=MAX_HASHWX_NONCES_PER_HASH).contains(&spec.n) {
        return false;
    }
    let Some(target) = hashwx_target(spec.d) else {
        return false;
    };
    let block = nonce / u64::from(spec.n);
    let seed = hashwx_seed(&challenge, block);
    match hash_nonce(&seed, nonce) {
        Some(hash) => hash <= target,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::process::Command;

    fn kat_expected() -> Option<([u8; 32], u64)> {
        let script = r#"
import {hashwxSeed,hashwxHash,hashwxReady} from "/root/cpa/cap/core/src/hashwx.js";
const st=await hashwxReady();
const ch=new Uint8Array(32).fill(7);
const seed=hashwxSeed(ch,3n);
console.log(JSON.stringify({seed:[...seed], hash:String(hashwxHash(st,seed,12345n))}));
"#;
        let output = Command::new("bun")
            .arg("-e")
            .arg(script)
            .current_dir("/root/cpa/cap/core")
            .output()
            .ok()?;
        if !output.status.success() {
            eprintln!(
                "hashwx KAT: bun failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return None;
        }
        let text = String::from_utf8(output.stdout).ok()?;
        let line = text.lines().find(|l| l.starts_with('{'))?;
        let value: serde_json::Value = serde_json::from_str(line).ok()?;
        let seed_json = value.get("seed")?.as_array()?;
        if seed_json.len() != 32 {
            return None;
        }
        let mut seed = [0u8; 32];
        for (i, v) in seed_json.iter().enumerate() {
            seed[i] = u8::try_from(v.as_u64()?).ok()?;
        }
        let hash: u64 = value.get("hash")?.as_str()?.parse().ok()?;
        Some((seed, hash))
    }

    #[test]
    fn kat_matches_js_reference() {
        let Some((expected_seed, expected_hash)) = kat_expected() else {
            eprintln!("SKIP: bun or the JS core tree is unavailable; KAT not checked");
            return;
        };
        let challenge = [7u8; 32];
        let seed = hashwx_seed(&challenge, 3);
        assert_eq!(seed.to_vec(), expected_seed.to_vec(), "seed mismatch");
        let hash = hash_nonce(&seed, 12_345).expect("wasm module must run for the KAT");
        assert_eq!(hash, expected_hash, "hash mismatch");
    }

    #[test]
    fn wasm_instantiates() {
        let seed = hashwx_seed(&[1u8; 32], 0);
        assert!(hash_nonce(&seed, 0).is_some(), "hashwx wasm did not run");
    }

    #[test]
    fn target_and_seed_basics() {
        assert_eq!(hashwx_target(1), Some(u64::MAX));
        assert_eq!(hashwx_target(2), Some(u64::MAX / 2));
        assert_eq!(hashwx_target(0), None);
        assert_eq!(hashwx_seed(&[0u8; 32], 1), hashwx_seed(&[0u8; 32], 1));
        assert_ne!(hashwx_seed(&[0u8; 32], 1), hashwx_seed(&[0u8; 32], 2));
    }

    #[test]
    fn deterministic_hash() {
        let seed = hashwx_seed(&[9u8; 32], 7);
        let a = hash_nonce(&seed, 42).expect("wasm ran");
        let b = hash_nonce(&seed, 42).expect("wasm ran");
        assert_eq!(a, b);
    }

    #[test]
    fn mint_then_verify_bruteforce() {
        let specs = mint_challenges(1000, 65_536, 1).expect("mint");
        assert_eq!(specs.len(), 1);
        let spec = &specs[0];
        assert_eq!(spec.d, 1000);
        assert_eq!(spec.n, 65_536);
        assert_eq!(spec.c_hex.len(), 64);

        let found = (0..200_000u64).find(|&nonce| verify_solution(spec, nonce));
        assert!(found.is_some(), "no valid nonce within 200k attempts");

        // A nonce that is not the solution must fail (pick one offset away).
        let bad = found.unwrap().wrapping_add(1);
        assert!(!verify_solution(spec, bad), "wrong nonce verified");
    }

    #[test]
    fn mint_limits_are_enforced() {
        assert!(mint_challenges(0, 65_536, 1).is_err());
        assert!(mint_challenges(MAX_HASHWX_DIFFICULTY + 1, 65_536, 1).is_err());
        assert!(mint_challenges(1000, 0, 1).is_err());
        assert!(mint_challenges(1000, MAX_HASHWX_NONCES_PER_HASH + 1, 1).is_err());
        assert!(mint_challenges(1000, 65_536, 0).is_err());
        assert!(mint_challenges(1000, 65_536, MAX_HASHWX_CHALLENGE_COUNT + 1).is_err());
        // Boundaries are accepted.
        assert!(mint_challenges(1, 1, 1).is_ok());
        assert!(
            mint_challenges(
                MAX_HASHWX_DIFFICULTY,
                MAX_HASHWX_NONCES_PER_HASH,
                MAX_HASHWX_CHALLENGE_COUNT
            )
            .is_ok()
        );
    }

    #[test]
    fn mint_split_matches_js_rounding() {
        // round(1000 / 3) = 333, round(1 / 4) = 0 → clamped to 1.
        let specs = mint_challenges(1000, 65_536, 3).expect("mint");
        assert_eq!(specs.len(), 3);
        assert!(specs.iter().all(|s| s.d == 333));
        let specs = mint_challenges(1, 65_536, 4).expect("mint");
        assert!(specs.iter().all(|s| s.d == 1));
        // round(5 / 2) = 3 (half rounds up), like Math.round.
        let specs = mint_challenges(5, 65_536, 2).expect("mint");
        assert!(specs.iter().all(|s| s.d == 3));
    }

    #[test]
    fn nonce_parsing() {
        assert_eq!(parse_nonce(&json!(0)), Some(0));
        assert_eq!(parse_nonce(&json!(12_345)), Some(12_345));
        assert_eq!(parse_nonce(&json!(u64::MAX)), Some(u64::MAX));
        assert_eq!(parse_nonce(&json!("12345")), Some(12_345));
        assert_eq!(parse_nonce(&json!("18446744073709551615")), Some(u64::MAX));
        // Too large / malformed.
        assert_eq!(parse_nonce(&json!("18446744073709551616")), None);
        assert_eq!(parse_nonce(&json!("99999999999999999999999")), None);
        assert_eq!(parse_nonce(&json!("-1")), None);
        assert_eq!(parse_nonce(&json!("1.5")), None);
        assert_eq!(parse_nonce(&json!("")), None);
        assert_eq!(parse_nonce(&json!("0x10")), None);
        assert_eq!(parse_nonce(&json!(1.5)), None);
        assert_eq!(parse_nonce(&json!(-1)), None);
        assert_eq!(parse_nonce(&json!(true)), None);
        assert_eq!(parse_nonce(&serde_json::Value::Null), None);
    }

    #[test]
    fn verify_rejects_malformed_spec() {
        let good = mint_challenges(1000, 65_536, 1).expect("mint").remove(0);
        let mut bad = good.clone();
        bad.c_hex = "zz".repeat(32);
        assert!(!verify_solution(&bad, 0));
        let mut bad = good.clone();
        bad.c_hex = "00".to_string();
        assert!(!verify_solution(&bad, 0));
        let mut bad = good.clone();
        bad.d = 0;
        assert!(!verify_solution(&bad, 0));
        let mut bad = good.clone();
        bad.n = 0;
        assert!(!verify_solution(&bad, 0));
    }
}
