//! Small RNG + identifier generator.
//!
//! `Rng` wraps `StdRng` so every random draw used by the generator flows
//! through one place. `generate()` seeds from OS entropy; `generate_with_seed()`
//! seeds deterministically, which the tests use to pin the output.

use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng as _, SeedableRng};
use std::collections::HashSet;

pub struct Rng(StdRng);

impl Rng {
    pub fn from_entropy() -> Self {
        Rng(StdRng::from_entropy())
    }

    pub fn from_seed(seed: u64) -> Self {
        Rng(StdRng::seed_from_u64(seed))
    }

    /// Inclusive integer range, mirroring the JS `fastRnd(a, b)` helper.
    pub fn inclusive(&mut self, a: i64, b: i64) -> i64 {
        if b <= a {
            return a;
        }
        self.0.gen_range(a..=b)
    }

    /// Uniform integer in `0..n` (0 when `n == 0`).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.0.gen_range(0..n) }
    }

    /// Uniform float in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        self.0.r#gen::<f64>()
    }

    /// Random lowercase hex string of `bytes * 2` chars.
    pub fn hex(&mut self, bytes: usize) -> String {
        let mut v = Vec::with_capacity(bytes);
        for _ in 0..bytes {
            v.push(self.0.r#gen::<u8>());
        }
        crate::crypto::hex(&v)
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        items.shuffle(&mut self.0);
    }
}

/// Identifier alphabet, identical to the JS generator: an ASCII letter first,
/// then letters/digits (`^[a-z][a-z0-9]*$`).
const VAR_LETTERS: &[u8; 26] = b"abcdefghijklmnopqrstuvwxyz";
const VAR_CHARS: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// Names that must never be produced as local variables: they are referenced by
/// the emitted snippets (globals / browser objects) and shadowing them would
/// change or break the script. The JS generator takes its chances here; we
/// guarantee it.
fn reserved(name: &str) -> bool {
    matches!(
        name,
        "window"
            | "document"
            | "navigator"
            | "screen"
            | "crypto"
            | "parent"
            | "self"
            | "top"
            | "console"
            | "globalThis"
            | "global"
            | "process"
            | "require"
            | "module"
            | "eval"
            | "arguments"
            | "undefined"
            | "Notification"
            | "Worker"
            | "Blob"
            | "URL"
            | "Promise"
            | "Object"
            | "Array"
            | "String"
            | "Number"
            | "Function"
            | "Symbol"
            | "Math"
            | "Date"
            | "JSON"
            | "Error"
            | "TextEncoder"
            | "Uint8Array"
            | "WebGLRenderingContext"
            | "HTMLCanvasElement"
            | "CanvasRenderingContext2D"
            | "EventTarget"
            | "CustomEvent"
            | "MimeTypeArray"
            | "Map"
            | "Set"
            | "WeakMap"
            | "WeakSet"
            | "RegExp"
            | "Boolean"
            | "parseInt"
            | "parseFloat"
            | "isNaN"
            | "isFinite"
            | "encodeURI"
            | "decodeURI"
            | "encodeURIComponent"
            | "decodeURIComponent"
            | "BigInt"
            | "Proxy"
            | "Reflect"
            | "Intl"
            | "WebAssembly"
            | "TextDecoder"
            | "RTCPeerConnection"
            | "MimeType"
            | "HTMLElement"
            | "HTMLDocument"
            | "Window"
            | "Document"
            | "Navigator"
            | "Node"
            | "outerWidth"
            | "outerHeight"
    )
}

/// Hands out unique, valid JS identifiers for one generated script.
pub struct Namer {
    used: HashSet<String>,
}

impl Namer {
    pub fn new() -> Self {
        Namer {
            used: HashSet::new(),
        }
    }

    /// Fresh identifier. `len = None` picks 4..=10 chars (like JS `rVar()`).
    pub fn var(&mut self, rng: &mut Rng, len: Option<usize>) -> String {
        loop {
            let n = match len {
                Some(l) => l.max(1),
                None => rng.inclusive(4, 10) as usize,
            };
            let mut s = String::with_capacity(n);
            s.push(VAR_LETTERS[rng.below(26) as usize] as char);
            for _ in 1..n {
                s.push(VAR_CHARS[rng.below(36) as usize] as char);
            }
            if !reserved(&s) && self.used.insert(s.clone()) {
                return s;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_are_inclusive() {
        let mut r = Rng::from_seed(7);
        for _ in 0..10_000 {
            let v = r.inclusive(10, 250);
            assert!((10..=250).contains(&v));
        }
        assert_eq!(r.inclusive(5, 5), 5);
        assert_eq!(r.inclusive(9, 1), 9); // degenerate range clamps
    }

    #[test]
    fn unit_is_in_range() {
        let mut r = Rng::from_seed(9);
        for _ in 0..1000 {
            let u = r.unit();
            assert!((0.0..1.0).contains(&u));
        }
    }

    #[test]
    fn names_are_valid_and_unique() {
        let mut r = Rng::from_seed(11);
        let mut namer = Namer::new();
        let mut seen = HashSet::new();
        for _ in 0..500 {
            let v = namer.var(&mut r, None);
            assert!(v.len() >= 4 && v.len() <= 10);
            assert!(v.chars().next().unwrap().is_ascii_lowercase());
            assert!(
                v.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            );
            assert!(seen.insert(v));
        }
    }

    #[test]
    fn edition_2024_draws_preserve_seeded_sequence() {
        let mut wrapped = Rng::from_seed(2024);
        let mut reference = StdRng::seed_from_u64(2024);
        for bytes in [0, 1, 16, 32] {
            assert_eq!(wrapped.unit().to_bits(), reference.r#gen::<f64>().to_bits());
            let expected: Vec<u8> = (0..bytes).map(|_| reference.r#gen::<u8>()).collect();
            assert_eq!(wrapped.hex(bytes), crate::crypto::hex(&expected));
        }
    }

    #[test]
    fn hex_len() {
        let mut r = Rng::from_seed(3);
        assert_eq!(r.hex(16).len(), 32);
        assert!(r.hex(16).chars().all(|c| c.is_ascii_hexdigit()));
    }
}
