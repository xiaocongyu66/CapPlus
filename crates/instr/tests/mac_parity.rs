//! Parity and robustness tests for the result-MAC canonicaliser.
//!
//! The fixtures in `tests/fixtures/mac_vectors.json` were produced by the real
//! JS implementation (bun/node):
//!
//! ```text
//! const canon = ['cap-instr', id, String(ts), JSON.stringify(state), JSON.stringify(p)].join('|');
//! const mac = crypto.createHmac('sha256', Buffer.from(key)).update(canon).digest('hex');
//! ```
//!
//! Each entry stores the exact `JSON.stringify` output of `state` and `p`, the
//! canonical string and the HMAC, so the Rust side is checked byte for byte.

use cap_instr::mac::{js_f64, js_stringify, verify_result_mac};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::{Number, Value};

fn vectors() -> Vec<Value> {
    serde_json::from_str(include_str!("fixtures/mac_vectors.json")).expect("fixture json")
}

fn field<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k).unwrap_or_else(|| panic!("missing field {k}"))
}

#[test]
fn fixture_is_non_trivial() {
    let vs = vectors();
    assert!(vs.len() >= 8, "expected a decent number of vectors");
    // Every vector must actually be signed by JS with a 64-char lowercase hex mac.
    for v in &vs {
        let mac = field(v, "mac").as_str().unwrap();
        assert_eq!(mac.len(), 64);
        assert!(mac.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}

/// Core parity: canonicaliser reproduces `JSON.stringify` and the MAC verifies.
#[test]
fn js_parity_of_stringify_and_mac() {
    for v in vectors() {
        let key = field(&v, "key").as_str().unwrap();
        let id = field(&v, "id").as_str().unwrap();
        let ts = field(&v, "ts").as_i64().unwrap();
        let state_json = field(&v, "stateJson").as_str().unwrap();
        let p_json = field(&v, "pJson").as_str().unwrap();
        let canon = field(&v, "canon").as_str().unwrap();
        let mac = field(&v, "mac").as_str().unwrap();

        let state: Value = serde_json::from_str(state_json).unwrap();
        let p: Value = serde_json::from_str(p_json).unwrap();

        // 1. byte-for-byte JSON.stringify parity
        assert_eq!(js_stringify(&state), state_json, "state mismatch (ts={ts})");
        assert_eq!(js_stringify(&p), p_json, "p mismatch (ts={ts})");

        // 2. we rebuild the same canonical string JS signed
        let rebuilt = format!(
            "cap-instr|{}|{}|{}|{}",
            id,
            ts,
            js_stringify(&state),
            js_stringify(&p)
        );
        assert_eq!(&rebuilt, canon, "canon mismatch (id={id})");

        // 3. the real JS HMAC verifies
        assert!(
            verify_result_mac(key, id, ts, &state, &p, mac),
            "mac should verify (id={id})"
        );

        // 4. any tampering fails
        let mut bad_mac = mac.to_string();
        let last = bad_mac.pop().unwrap();
        bad_mac.push(if last == '0' { '1' } else { '0' });
        assert!(!verify_result_mac(key, id, ts, &state, &p, &bad_mac));
        assert!(!verify_result_mac(key, id, ts + 1, &state, &p, mac));
        assert!(!verify_result_mac(key, &format!("{id}x"), ts, &state, &p, mac));
        assert!(!verify_result_mac(
            key,
            id,
            ts,
            &serde_json::json!({ "tampered": true }),
            &p,
            mac
        ));
        // Case-flip inside an object value.
        let mut alt_state = state.clone();
        if let Some(obj) = alt_state.as_object_mut() {
            obj.insert("__injected".into(), Value::Bool(true));
            assert!(!verify_result_mac(key, id, ts, &alt_state, &p, mac));
        }
    }
}

/// Malformed digests / keys are rejected instead of panicking.
#[test]
fn rejects_malformed_mac_and_missing_key() {
    let v = &vectors()[0];
    let key = field(v, "key").as_str().unwrap();
    let id = field(v, "id").as_str().unwrap();
    let ts = field(v, "ts").as_i64().unwrap();
    let state: Value = serde_json::from_str(field(v, "stateJson").as_str().unwrap()).unwrap();
    let p: Value = serde_json::from_str(field(v, "pJson").as_str().unwrap()).unwrap();
    let mac = field(v, "mac").as_str().unwrap();

    // Sanity: the good one verifies, and case-insensitive hex is accepted.
    assert!(verify_result_mac(key, id, ts, &state, &p, mac));
    assert!(verify_result_mac(key, id, ts, &state, &p, &mac.to_uppercase()));

    // Empty key can never verify.
    assert!(!verify_result_mac("", id, ts, &state, &p, mac));

    // Short, long, odd-length, non-hex, whitespace and non-ASCII digests.
    let short = &mac[..63];
    let long = format!("{mac}00");
    let odd = format!("{mac}0");
    let nonhex = "zz4b88c1e6b7e0afac680219148873dfb9f5b077a3f2f0d147dfc77b160a50be";
    let spaced = " dc4b88c1e6b7e0afac680219148873dfb9f5b077a3f2f0d147dfc77b160a50b";
    let unicode = "dc4b88c1e6b7e0afac680219148873dfb9f5b077a3f2f0d147dfc77b160a50bé";
    for bad in [
        "",
        "dc4b",
        short,
        long.as_str(),
        odd.as_str(),
        nonhex,
        spaced,
        unicode,
    ] {
        assert!(
            !verify_result_mac(key, id, ts, &state, &p, bad),
            "should reject mac {bad:?}"
        );
    }
}

/// `Number::toString` edge cases, values taken verbatim from V8.
#[test]
fn number_formatting_matches_v8() {
    let cases: &[(f64, &str)] = &[
        (0.0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (-1.0, "-1"),
        (0.5, "0.5"),
        (-0.5, "-0.5"),
        (1.5, "1.5"),
        (100.0, "100"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1e22, "1e+22"),
        (123456789012345678901.0, "123456789012345680000"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (1e-8, "1e-8"),
        (1e-5, "0.00001"),
        (0.1, "0.1"),
        (0.30000000000000004, "0.30000000000000004"),
        (172.67165096606914, "172.67165096606914"),
        (1.0 / 3.0, "0.3333333333333333"),
        (5e-324, "5e-324"),
        (f64::MAX, "1.7976931348623157e+308"),
        (9007199254740992.0, "9007199254740992"),
        (1234567890123456.0, "1234567890123456"),
        (12345678901234567.0, "12345678901234568"),
        (-1e-7, "-1e-7"),
        (-1e21, "-1e+21"),
        (1.25, "1.25"),
        (4.5, "4.5"),
        (std::f64::consts::PI, "3.141592653589793"),
        (2.5e-300, "2.5e-300"),
        // The two bit patterns where Rust's own Display rounds the other way.
        (1789178001445300.2, "1789178001445300.2"),
        (103628009358931.12, "103628009358931.12"),
    ];
    for &(f, want) in cases {
        assert_eq!(js_f64(f), want, "js_f64({f:?})");
    }
    assert_eq!(js_f64(f64::NAN), "null");
    assert_eq!(js_f64(f64::INFINITY), "null");
    assert_eq!(js_f64(f64::NEG_INFINITY), "null");
}

/// String escaping parity with `JSON.stringify`.
#[test]
fn string_escaping() {
    let v: Value = serde_json::from_str(
        r#"{"q":"quote\" back\\slash/slash","tab":"\t","nl":"\n","cr":"\r","bs":"\b","ff":"\f","ctl":"\u0000\u0001\u001f","del":"\u007f","u":"é世😀\u2028\u2029"}"#,
    )
    .unwrap();
    let s = js_stringify(&v);
    // Slash is NOT escaped; control chars use short escapes or \u00XX; DEL,
    // U+2028/U+2029 and non-ASCII stay raw.
    assert_eq!(
        s,
        "{\"q\":\"quote\\\" back\\\\slash/slash\",\"tab\":\"\\t\",\"nl\":\"\\n\",\"cr\":\"\\r\",\"bs\":\"\\b\",\"ff\":\"\\f\",\"ctl\":\"\\u0000\\u0001\\u001f\",\"del\":\"\u{7f}\",\"u\":\"é世😀\u{2028}\u{2029}\"}"
    );
    // Round-trips.
    let back: Value = serde_json::from_str(&s).unwrap();
    assert_eq!(back, v);
}

/// Key order of the incoming JSON text is preserved verbatim.
#[test]
fn key_order_is_preserved() {
    let v: Value = serde_json::from_str(r#"{"z":1,"y":2,"x":3,"__":4,"Aa":5,"aA":6}"#).unwrap();
    assert_eq!(js_stringify(&v), r#"{"z":1,"y":2,"x":3,"__":4,"Aa":5,"aA":6}"#);
}

/// Property: stringify output re-parses to an equal value and is idempotent.
#[test]
fn property_roundtrip_and_idempotent() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE_1234_5678);
    for _ in 0..2000 {
        let v = gen_value(&mut rng, 4);
        let s = js_stringify(&v);
        let back: Value =
            serde_json::from_str(&s).unwrap_or_else(|e| panic!("reparse failed: {e}\n{s}"));
        assert_eq!(back, v, "value changed after round-trip\n{s}");
        assert_eq!(js_stringify(&back), s, "not idempotent");
    }
}

/// Property: random *number-heavy* values keep number semantics.
#[test]
fn property_numbers() {
    let mut rng = StdRng::seed_from_u64(42);
    for _ in 0..5000 {
        let f = random_float(&mut rng);
        let s = js_f64(f);
        let back: f64 = s.parse().expect("parses as f64");
        assert_eq!(back.to_bits(), f.to_bits(), "lost precision: {s}");
        // No leading '+', no leading zeros, no ".0" suffix, no "Infinity".
        if f != 0.0 {
            assert!(!s.starts_with('+'));
            if s.contains('.') && !s.contains('e') {
                assert!(!s.ends_with(".0"), "{s}");
            }
        }
    }
}

// ---- generators -----------------------------------------------------------

fn gen_string(rng: &mut StdRng, tag: usize) -> String {
    // Include every JSON-sensitive class, plus a unique tag so object keys stay
    // distinct.
    const POOL: &[char] = &[
        'a', 'Z', '0', ' ', '"', '\\', '/', '\u{0}', '\u{1}', '\u{7}', '\u{1f}', '\n', '\t', '\r',
        '\u{8}', '\u{c}', '\u{7f}', 'é', '世', '😀', '\u{2028}', '\u{2029}', '\u{feff}',
    ];
    let n = rng.gen_range(0..6);
    let mut s = String::new();
    for _ in 0..n {
        s.push(POOL[rng.gen_range(0..POOL.len())]);
    }
    s.push_str(&format!("#{tag}"));
    s
}

fn random_float(rng: &mut StdRng) -> f64 {
    loop {
        let f = match rng.gen_range(0..4) {
            0 => rng.gen::<f64>().mul_add(2.0, -1.0), // [-1, 1)
            1 => rng.gen::<f64>() * 10f64.powi(rng.gen_range(-320..=308)),
            _ => f64::from_bits(rng.gen()),
        };
        if f.is_finite() && f != 0.0 {
            return f;
        }
    }
}

/// A finite float that is *not* an integer, so JSON round-tripping keeps it in
/// serde_json's `Float` variant (an integral float would re-parse as `PosInt`).
fn random_nonintegral(rng: &mut StdRng) -> f64 {
    loop {
        let mag = rng.gen::<f64>() * 10f64.powi(rng.gen_range(-300..=14));
        let f = if rng.gen::<bool>() { mag } else { -mag };
        if f.is_finite() && f.fract() != 0.0 {
            return f;
        }
    }
}

fn gen_number(rng: &mut StdRng) -> Number {
    match rng.gen_range(0..2) {
        // Integers inside ±2^53: exactly representable as a JS Number.
        0 => Number::from(rng.gen_range(-(1i64 << 53)..=(1i64 << 53))),
        // Non-integral floats (so re-parsing yields the same Float variant).
        _ => Number::from_f64(random_nonintegral(rng)).expect("finite"),
    }
}

fn gen_value(rng: &mut StdRng, depth: u32) -> Value {
    match rng.gen_range(0..6) {
        0 => Value::Null,
        1 => Value::Bool(rng.gen()),
        2 | 3 => Value::Number(gen_number(rng)),
        4 if depth > 0 => {
            let n = rng.gen_range(0..4);
            Value::Array((0..n).map(|_| gen_value(rng, depth - 1)).collect())
        }
        5 if depth > 0 => {
            let n = rng.gen_range(0..4);
            let mut map = serde_json::Map::new();
            for i in 0..n {
                map.insert(gen_string(rng, i), gen_value(rng, depth - 1));
            }
            Value::Object(map)
        }
        _ => {
            let tag = rng.gen_range(0..16);
            Value::String(gen_string(rng, tag))
        }
    }
}
