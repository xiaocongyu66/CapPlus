//! State computation.
//!
//! The probe's "state" is a handful of int32 arithmetic ops the client must
//! evaluate; `expected_vals` is the value the *same* equations produce on the
//! server side. We therefore generate the JS text and the expected result from
//! the same random draws, keeping the two in lockstep.
//!
//! Parity notes
//! ------------
//! * `~`, `^`, `|`, `&` follow JS int32 semantics (`toInt32` after every op).
//! * op 4 (`fnHelper`) is a pure algebraic helper identical to the JS version.
//! * op 5 (`domHelper`) in the reference builds a DOM node chain and sums
//!   `innerText` along it. That value depends on layout (`innerText` of a node
//!   whose children were just removed is `""`, i.e. `parseInt` → `NaN` → 0),
//!   yet the reference's own `expectedVals` mock walks an in-memory object
//!   chain, so the two disagree. We emit a **pure-JS** equivalent of the mock
//!   (no DOM access) so `expected_vals` provably equal what the script computes
//!   in any browser. Documented deviation; shape of the op is preserved.

use crate::rng::{Namer, Rng};

/// JS `n | 0` for a value already produced by int32 arithmetic.
#[inline]
pub fn to_int32(n: i64) -> i32 {
    n as i32
}

/// One chain step: a node carrying `text`, parented at `parent`.
struct Node {
    parent: Option<usize>,
    text: i32,
}

fn build_chain(chain: &mut Vec<Node>, start: usize, mut v: i32) -> usize {
    let mut cur = start;
    for _ in 0..8 {
        let idx = chain.len();
        chain.push(Node {
            parent: Some(cur),
            text: v,
        });
        if v & 1 == 0 {
            cur = idx;
        }
        v >>= 1;
    }
    cur
}

fn walk(chain: &[Node], mut node: usize) -> i32 {
    let mut sum: i64 = 0;
    while let Some(parent) = chain[node].parent {
        sum += chain[node].text as i64;
        node = parent;
    }
    (sum % 256) as i32
}

/// Mock of the DOM-walk helper, used to compute the expected value.
pub fn dom_sum_mock(x: i32, y: i32, z: i32) -> i32 {
    let mut chain = vec![Node {
        parent: None,
        text: 0,
    }];
    let mut cur = 0usize;
    cur = build_chain(&mut chain, cur, x);
    cur = build_chain(&mut chain, cur, y);
    cur = build_chain(&mut chain, cur, z);
    walk(&chain, cur)
}

pub struct StatePlan {
    pub vars: [String; 4],
    pub init_vals: [i64; 4],
    pub expected: [i64; 4],
    /// Starts with the helper declarations (as in the JS generator), so the
    /// whole block can be dropped into the async function verbatim.
    pub client_eqs: String,
}

pub fn plan_state(rng: &mut Rng, namer: &mut Namer) -> StatePlan {
    let vars = [
        namer.var(rng, Some(12)),
        namer.var(rng, Some(12)),
        namer.var(rng, Some(12)),
        namer.var(rng, Some(12)),
    ];

    let init_vals = [
        rng.inclusive(10, 250),
        rng.inclusive(10, 250),
        rng.inclusive(10, 250),
        rng.inclusive(10, 250),
    ];
    let mut vals = [
        init_vals[0] as i32,
        init_vals[1] as i32,
        init_vals[2] as i32,
        init_vals[3] as i32,
    ];

    let correct_key = rng.inclusive(1000, 9000) as i32;
    let mut bad_key = rng.inclusive(1000, 9000) as i32;
    while bad_key == correct_key {
        bad_key = rng.inclusive(1000, 9000) as i32;
    }
    vals[0] = vals[0] ^ correct_key;

    let fn_helper = namer.var(rng, None);
    let dom_helper = namer.var(rng, None);

    let helper_decls = format!(
        "function {f}(a,b,c){{function F(d){{this.v=function(){{return this.k^d;}}}};var p={{k:c}};var i=new F(a);i.k=b;F.prototype=p;return i.v()|(new F(b)).v();}}",
        f = fn_helper
    ) + &format!(
        "function {d}(x,y,z){{var root={{}};function A(p,v){{for(var i=0;i<8;i++){{var c={{p:p,t:v}};if((v&1)===0)p=c;v=v>>1;}}return p;}}function B(n,r,s){{if(!n||n===r)return s%256;return B(n.p,r,s+n.t);}}return B(A(A(A(root,x),y),z),root,0)|0;}}",
        d = dom_helper
    );

    let v = &vars;
    let mut eq = String::with_capacity(4096);
    eq.push_str(&helper_decls);
    eq.push_str(&format!(
        "{v0} = {v0} ^ (navigator.userAgent ? {ck} : {bk});",
        v0 = v[0],
        ck = correct_key,
        bk = bad_key
    ));

    for _ in 0..20 {
        let op = rng.inclusive(0, 5) as u8;
        let dest = rng.inclusive(0, 3) as usize;
        let src1 = rng.inclusive(0, 3) as usize;
        let src2 = rng.inclusive(0, 3) as usize;
        let src3 = rng.inclusive(0, 3) as usize;
        let vd = &v[dest];
        let vs1 = &v[src1];
        let vs2 = &v[src2];
        let vs3 = &v[src3];

        match op {
            0 => {
                eq.push_str(&format!("{vd} = ~({vd} & {vs1});"));
                vals[dest] = !(vals[dest] & vals[src1]);
            }
            1 => {
                eq.push_str(&format!("{vd} = {vd} ^ {vs1};"));
                vals[dest] ^= vals[src1];
            }
            2 => {
                eq.push_str(&format!("{vd} = {vd} | {vs1};"));
                vals[dest] |= vals[src1];
            }
            3 => {
                eq.push_str(&format!("{vd} = {vd} & {vs1};"));
                vals[dest] &= vals[src1];
            }
            4 => {
                eq.push_str(&format!("{vd} = {fh}({vs1}, {vs2}, {vd});", fh = fn_helper));
                vals[dest] = (vals[src2] ^ vals[src1]) | (vals[dest] ^ vals[src2]);
            }
            _ => {
                eq.push_str(&format!("{vd} = {dh}({vs1}, {vs2}, {vs3});", dh = dom_helper));
                vals[dest] = dom_sum_mock(vals[src1], vals[src2], vals[src3]);
            }
        }
    }

    let mut expected = [0i64; 4];
    for i in 0..4 {
        let salt = rng.inclusive(100_000, 999_999) as i32;
        eq.push_str(&format!(
            "{v} = (({v}^{s})&0x7FFFFFFF)%900000+100000;",
            v = vars[i],
            s = salt
        ));
        vals[i] = ((vals[i] ^ salt) & 0x7fff_ffff) % 900_000 + 100_000;
        expected[i] = vals[i] as i64;
    }

    StatePlan {
        vars,
        init_vals,
        expected,
        client_eqs: eq,
    }
}


/// JS parity tests are the only check that the Rust port matches the reference
/// implementation. A missing toolchain must fail the suite, not silently pass:
/// set `CAP_SKIP_JS_PARITY=1` to skip deliberately (e.g. on a machine without
/// bun or the reference tree).
fn parity_required(reason: &str) {
    if std::env::var("CAP_SKIP_JS_PARITY").as_deref() == Ok("1") {
        eprintln!("SKIP (CAP_SKIP_JS_PARITY=1): {reason}");
        return;
    }
    panic!("{reason}; install bun and the reference tree, or set CAP_SKIP_JS_PARITY=1");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::Command;

    fn bun_available() -> bool {
        Command::new("bun")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn dom_mock_is_bounded() {
        for x in [-1000, -1, 0, 1, 2, 255, 65535, 1 << 20] {
            for y in [-7, 0, 3, 90] {
                let v = dom_sum_mock(x, y, 0);
                assert!((-255..256).contains(&v));
            }
        }
        // All-odd / zero-shift chains degenerate to 0.
        assert_eq!(dom_sum_mock(0, 0, 0), 0);
    }

    #[test]
    fn expected_vals_in_range_and_vars_valid() {
        let mut rng = Rng::from_seed(42);
        let mut namer = Namer::new();
        let plan = plan_state(&mut rng, &mut namer);
        for v in &plan.expected {
            assert!((100_000..1_000_000).contains(v), "{}", v);
        }
        for v in &plan.vars {
            assert!(v.starts_with(|c: char| c.is_ascii_lowercase()));
            assert!(v.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        }
    }

    /// Runs the *emitted* equations in a JS engine and checks that the resulting
    /// state equals `expected`. This is the real parity test for the ops.
    #[test]
    fn emitted_equations_match_expected_vals() {
        if !bun_available() {
            parity_required("bun not available");
            return;
        }
        for seed in [1u64, 2, 3, 4, 5, 99, 12345] {
            let mut rng = Rng::from_seed(seed);
            let mut namer = Namer::new();
            let plan = plan_state(&mut rng, &mut namer);
            let js = format!(
                // Shadow the real `navigator` with a parameter — a top-level
                // `var navigator` does not override Bun's global getter.
                "(function(navigator){{\n\
                 var {v0}={i0};var {v1}={i1};var {v2}={i2};var {v3}={i3};\n\
                 {eq}\n\
                 console.log(JSON.stringify([{v0},{v1},{v2},{v3}]));\n\
                 }})({{userAgent:'Mozilla/5.0 (X11; Linux x86_64) Test/1.0'}});",
                v0 = plan.vars[0],
                v1 = plan.vars[1],
                v2 = plan.vars[2],
                v3 = plan.vars[3],
                i0 = plan.init_vals[0],
                i1 = plan.init_vals[1],
                i2 = plan.init_vals[2],
                i3 = plan.init_vals[3],
                eq = plan.client_eqs,
            );
            let path = std::env::temp_dir().join(format!(
                "cap-instr-state-{}-{}.js",
                std::process::id(),
                seed
            ));
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(js.as_bytes()).unwrap();
            drop(f);
            let out = Command::new("bun").arg(&path).output().unwrap();
            let _ = std::fs::remove_file(&path);
            assert!(
                out.status.success(),
                "bun failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let got: Vec<i64> =
                serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
            assert_eq!(got, plan.expected.to_vec(), "seed {}", seed);
        }
    }

    /// The UA branch is present and uses two different keys. (We cannot assert
    /// that a falsy UA yields a different *final* state: the 20 random ops can
    /// wash an input difference out — the JS reference has the same property,
    /// which is why it only checks the truthy path.)
    #[test]
    fn ua_branch_uses_two_distinct_keys() {
        let mut rng = Rng::from_seed(7);
        let mut namer = Namer::new();
        let plan = plan_state(&mut rng, &mut namer);
        let eq = &plan.client_eqs;
        assert!(eq.contains("navigator.userAgent ?"));
        let start = eq.find("navigator.userAgent ?").unwrap();
        let tail = &eq[start..];
        let colon = tail.find(':').unwrap();
        let qmark = tail.find('?').unwrap();
        let ck = tail[qmark + 1..colon].trim();
        let end_num = tail[colon + 1..].find(')').unwrap();
        let bk = tail[colon + 1..colon + 1 + end_num].trim();
        assert_ne!(ck, bk, "correct/bad keys must differ");
        assert!(ck.parse::<i32>().is_ok() && bk.parse::<i32>().is_ok());
    }
}

