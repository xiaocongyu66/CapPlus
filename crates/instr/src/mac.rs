//! Verification of the result MAC emitted by the probe script.
//!
//! The generated client (see `core/src/instrumentation.js`, search for
//! `cap-instr`) signs
//! `['cap-instr', id, String(ts), JSON.stringify(state), JSON.stringify(p)].join('|')`
//! with HMAC-SHA256 keyed by the ASCII bytes of the 32-hex-char session
//! `macKey` and posts the lowercase hex digest as `result.mac`.
//!
//! The server receives `state` and `p` as *parsed* JSON, so verifying the MAC
//! requires re-serialising them exactly the way the browser's `JSON.stringify`
//! did. [`js_stringify`] implements that canonicalisation:
//!
//! * object keys keep the order they had in the incoming JSON text (this
//!   requires `serde_json`'s `preserve_order` feature — enabled in this
//!   crate's `Cargo.toml`),
//! * array order is preserved,
//! * strings use the same escaping as `JSON.stringify` (`\"`, `\\`, the
//!   short escapes `\b \t \n \f \r`, `\u00XX` for the remaining control
//!   characters, raw UTF-8/UTF-16 code units otherwise — `/` and U+2028/U+2029
//!   are *not* escaped),
//! * numbers follow ECMAScript `Number::toString` (see [`js_f64`]).
//!
//! Parsing must also be exact: this crate enables serde_json's
//! `float_roundtrip` feature, because without it the fast float parser is off
//! by one ulp on some values, which changes the digits re-serialised here and
//! silently breaks verification.
//!
//! Known deviations (unreachable from a genuine client, because the client
//! sends `JSON.stringify` output that serde_json parses back into the same
//! shape):
//!
//! 1. **Integers outside ±2^53.** `JSON.stringify` rounds every `Number` to
//!    f64, so `9007199254740993` is sent as `9007199254740992`. serde_json
//!    parses the literal `9007199254740993` exactly (as `u64`), and we emit it
//!    verbatim. A genuine client can never produce that literal.
//! 2. **Lone surrogates.** (ES2019+) `JSON.stringify` emits `\uD800`-style
//!    escapes for unpaired surrogates; serde_json rejects such a payload
//!    outright, so it fails earlier than MAC checks. Probe data comes from
//!    browser APIs and is well-formed, so this cannot arise in practice.
//! 3. **JS property enumeration order.** We only reproduce the order found in
//!    the incoming text, not JS's "integer index keys first, ascending" rule.
//!    That is sufficient: the client's own `JSON.stringify` already applied
//!    that rule before sending, so the text we parse is already in JS order.
//!    (Duplicate keys behave identically: last value, first position.)
//! 4. **Integral floats constructed in memory.** `Number::from_f64(1.0)` is
//!    canonicalised to `1`, which re-parses as an integer rather than a float;
//!    parsed JSON never contains a float that prints as an integer.

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Serialise `v` the way `JSON.stringify` (no spacing) does, byte for byte.
pub fn js_stringify(v: &Value) -> String {
    let mut out = String::new();
    write_value(v, &mut out);
    out
}

fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&js_number(n)),
        Value::String(s) => write_js_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, val)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_js_string(k, out);
                out.push(':');
                write_value(val, out);
            }
            out.push('}');
        }
    }
}

/// Append a JSON string literal, escaped like `JSON.stringify`.
fn write_js_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0A}' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\u{0D}' => out.push_str("\\r"),
            // Remaining C0 controls use the \u00XX form, lowercase hex.
            c if (c as u32) < 0x20 => {
                out.push_str("\\u00");
                let b = c as u32;
                out.push(hex_digit_lower(b >> 4));
                out.push(hex_digit_lower(b & 0xF));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn hex_digit_lower(n: u32) -> char {
    match n & 0xF {
        0..=9 => char::from(b'0' + (n & 0xF) as u8),
        _ => char::from(b'a' + ((n & 0xF) - 10) as u8),
    }
}

/// Format a JSON number the way `String(number)` does in JavaScript.
fn js_number(n: &serde_json::Number) -> String {
    // Kept as an integer by serde_json: emit the decimal digits verbatim.
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    match n.as_f64() {
        Some(f) => js_f64(f),
        // serde_json never produces a Number that is neither int nor float,
        // but stay total rather than panicking.
        None => "null".to_string(),
    }
}

/// ECMAScript `Number::toString` (radix 10) for a finite/infinite f64.
///
/// The *digits* come from ryu's shortest, correctly rounded (round-to-nearest)
/// representation — the same tie-breaking V8 uses. Rust's own `Display`/`{:e}`
/// picks a different representative for a few values (e.g. the bit pattern
/// `43196cfddcdd46d1`), which would break MAC parity. Only the layout rule is
/// re-implemented, because Rust never switches to exponential notation outside
/// the JS window `1e-7 .. 1e21`.
pub fn js_f64(f: f64) -> String {
    if !f.is_finite() {
        // JSON.stringify serialises NaN/±Infinity as null.
        return "null".to_string();
    }
    if f == 0.0 {
        // Covers -0.0: String(-0) === "0".
        return "0".to_string();
    }
    let neg = f.is_sign_negative();
    let mag = f.abs();

    let (digits, n) = shortest_digits(mag);
    let k = digits.len() as i32;
    // value = digits x 10^(n - k)

    let mut out = String::new();
    if neg {
        out.push('-');
    }
    let chars: Vec<char> = digits.chars().collect();

    if k <= n && n <= 21 {
        // integer with trailing zeros
        out.push_str(&digits);
        for _ in 0..(n - k) {
            out.push('0');
        }
    } else if 0 < n && n <= 21 {
        // decimal point inside the digits
        let split = n as usize;
        out.extend(&chars[..split]);
        out.push('.');
        out.extend(&chars[split..]);
    } else if -6 < n && n <= 0 {
        // 0.000...digits
        out.push_str("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        // exponential form
        let e = n - 1;
        if k == 1 {
            out.push_str(&digits);
        } else {
            out.push(chars[0]);
            out.push('.');
            out.extend(&chars[1..]);
        }
        out.push('e');
        if e >= 0 {
            out.push('+');
        } else {
            out.push('-');
        }
        out.push_str(&e.abs().to_string());
    }
    out
}

/// Shortest correctly-rounded decimal digits of a finite, positive f64.
///
/// Returns `(digits, n)` with `digits` free of leading/trailing zeros and
/// `value == 0.digits * 10^n` — i.e. `n` is ECMAScript's "position of the
/// decimal point" and `digits.len()` its `k`.
fn shortest_digits(mag: f64) -> (String, i32) {
    // ryu's "pretty" layout never needs more than 24 bytes.
    let mut buf = ryu::Buffer::new();
    let s = buf.format_finite(mag);

    // Exponential form: "1e30", "1.234e-10", ...
    if let Some((mant, exp)) = s.split_once('e') {
        let e: i32 = exp.parse().unwrap_or(0);
        let digits: String = mant.chars().filter(|c| *c != '.').collect();
        return (digits, e + 1);
    }

    // Plain form: "12.34", "0.001234", "12340000000.0".
    let (int_part, frac_part) = s.split_once('.').unwrap_or((s, ""));
    let int_trim = int_part.trim_start_matches('0');
    if int_trim.is_empty() {
        // 0.<zeros><digits>: n = -(number of zeros after the point)
        let zeros = frac_part.len() - frac_part.trim_start_matches('0').len();
        (frac_part.trim_start_matches('0').to_string(), -(zeros as i32))
    } else {
        let mut digits = String::with_capacity(int_trim.len() + frac_part.len());
        digits.push_str(int_trim);
        digits.push_str(frac_part);
        while digits.len() > 1 && digits.ends_with('0') {
            digits.pop();
        }
        (digits, int_trim.len() as i32)
    }
}

/// Verify `result.mac` for a probe result.
///
/// Rebuilds `cap-instr|{id}|{ts}|{state}|{p}` with [`js_stringify`], computes
/// HMAC-SHA256 keyed by the ASCII bytes of `mac_key_hex` and compares it with
/// `mac_hex` (lowercase or uppercase hex) in constant time. Returns `false`
/// for an empty key, a wrong-length digest and any non-hex input; never panics.
pub fn verify_result_mac(
    mac_key_hex: &str,
    id: &str,
    ts: i64,
    state: &Value,
    p: &Value,
    mac_hex: &str,
) -> bool {
    if mac_key_hex.is_empty() {
        return false;
    }
    let canon = format!(
        "cap-instr|{}|{}|{}|{}",
        id,
        ts,
        js_stringify(state),
        js_stringify(p)
    );

    let mut mac = match Hmac::<Sha256>::new_from_slice(mac_key_hex.as_bytes()) {
        Ok(m) => m,
        // HMAC accepts any key length; keep the invariant without panicking.
        Err(_) => return false,
    };
    mac.update(canon.as_bytes());
    let expected = mac.finalize().into_bytes();

    let got = match decode_hex(mac_hex) {
        Some(bytes) => bytes,
        None => return false,
    };
    if got.len() != expected.len() {
        return false;
    }
    expected.as_slice().ct_eq(got.as_slice()).into()
}

/// Strict hex decoder; returns `None` on any non-hex byte or odd length.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
