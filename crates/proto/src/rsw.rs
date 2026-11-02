//! RSW time-lock puzzle — port of `core/src/rsw.js`.
//!
//! Minting computes, for a random `r`:
//!   x = g^r mod N,  y = h^r mod N   with  h = g^(2^t) mod N
//! both evaluated with CRT over (p, q) so a mint costs ~2·log(r) modular
//! squarings instead of 2^t. Verification is just a hex comparison against the
//! `y` sealed in the challenge.

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::RngCore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RswKeypair {
    pub n: BigUint,
    pub p: BigUint,
    pub q: BigUint,
    pub bits: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Minted {
    pub x_hex: String,
    pub y_hex: String,
}

fn biguint_from_bytes(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

fn hex_of(value: &BigUint, byte_len: Option<usize>) -> String {
    let s = value.to_str_radix(16);
    match byte_len {
        Some(len) => {
            let target = len * 2;
            if s.len() < target {
                format!("{}{}", "0".repeat(target - s.len()), s)
            } else {
                s
            }
        }
        None => s,
    }
}

fn mod_sub(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    // (a - b) mod m, with a, b < m.
    if a >= b {
        (a - b) % m
    } else {
        m - ((b - a) % m)
    }
}

/// (a^-1) mod m for coprime a, m.
pub fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a = BigInt::from_biguint(Sign::Plus, a % m);
    let m_int = BigInt::from_biguint(Sign::Plus, m.clone());
    let eg = a.extended_gcd(&m_int);
    if !eg.gcd.is_one() {
        return None;
    }
    let x = eg.x % &m_int;
    let x = if x.sign() == Sign::Minus {
        x + &m_int
    } else {
        x
    };
    x.to_biguint()
}

fn is_probable_prime(n: &BigUint, rounds: usize) -> bool {
    if n < &BigUint::from(2u32) {
        return false;
    }
    for small in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31] {
        let p = BigUint::from(small);
        if n == &p {
            return true;
        }
        if (n % &p).is_zero() {
            return false;
        }
    }
    let one = BigUint::one();
    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut r = 0u32;
    while d.is_even() {
        d >>= 1;
        r += 1;
    }
    let byte_len = (n.bits() as usize + 7) >> 3;
    let n_minus_3 = n - BigUint::from(3u32);
    let mut rng = rand::thread_rng();
    let mut buf = vec![0u8; byte_len];
    'outer: for _ in 0..rounds.max(1) {
        // Random base in [2, n-2].
        let mut a;
        loop {
            rng.fill_bytes(&mut buf);
            a = biguint_from_bytes(&buf) % &n_minus_3;
            if a >= BigUint::from(2u32) {
                break;
            }
        }
        let mut x = a.modpow(&d, n);
        if x.is_one() || x == n_minus_one {
            continue;
        }
        for _ in 0..r.saturating_sub(1) {
            x = (&x * &x) % n;
            if x == n_minus_one {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

fn random_prime(bits: usize) -> BigUint {
    assert!(bits >= 4, "rsw prime must have at least 4 bits");
    let byte_len = (bits + 7) >> 3;
    let mut rng = rand::thread_rng();
    let mut buf = vec![0u8; byte_len];
    loop {
        rng.fill_bytes(&mut buf);
        let mut x = biguint_from_bytes(&buf);
        x |= BigUint::from(1u32); // odd
        x |= BigUint::one() << (bits - 1); // top bit
        x |= BigUint::one() << (bits - 2); // second top bit (JS parity)
        let mask = (BigUint::one() << bits) - 1u32;
        x &= mask;
        // 40 rounds: false-positive bound 4^-40 (~8e-25). Four rounds (1/256)
        // is not acceptable for a keypair that lives for the whole process.
        if is_probable_prime(&x, 40) {
            return x;
        }
    }
}

/// Generate a keypair. Matches `generateRswKeypair` (two `bits/2` primes whose
/// product has `2*(bits/2)` bits because both have their top two bits set).
pub fn generate_keypair(bits: usize) -> RswKeypair {
    assert!(bits.is_multiple_of(2), "rsw bits must be even");
    let p = random_prime(bits >> 1);
    let mut q = random_prime(bits >> 1);
    while q == p {
        q = random_prime(bits >> 1);
    }
    let n = &p * &q;
    RswKeypair { n, p, q, bits }
}

pub fn serialize_keypair(kp: &RswKeypair) -> serde_json::Value {
    serde_json::json!({
        "N": kp.n.to_str_radix(10),
        "p": kp.p.to_str_radix(10),
        "q": kp.q.to_str_radix(10),
        "bits": kp.bits,
    })
}

pub fn deserialize_keypair(v: &serde_json::Value) -> Option<RswKeypair> {
    let parse = |key: &str| -> Option<BigUint> {
        v.get(key)
            .and_then(|x| x.as_str())
            .and_then(|s| BigUint::parse_bytes(s.as_bytes(), 10))
    };
    let n = parse("N")?;
    let p = parse("p")?;
    let q = parse("q")?;
    if n.is_zero() || p.is_zero() || q.is_zero() {
        return None;
    }
    let bits = v
        .get("bits")
        .and_then(|b| b.as_u64())
        .map(|b| b as usize)
        .unwrap_or_else(|| n.bits() as usize);
    Some(RswKeypair { n, p, q, bits })
}

/// CRT-optimised minter, mirroring `buildRswMinter`.
#[derive(Debug, Clone)]
pub struct RswMinter {
    pub n: BigUint,
    pub t: u64,
    pub g: BigUint,
    pub h: BigUint,
    pub modulus_bytes: usize,
    pub n_hex: String,
    pub g_hex: String,
    pub h_hex: String,
    pm1: BigUint,
    qm1: BigUint,
    gp: BigUint,
    gq: BigUint,
    hp: BigUint,
    hq: BigUint,
    qinv_p: BigUint,
    q: BigUint,
    p: BigUint,
}

impl RswMinter {
    pub fn build(kp: &RswKeypair, t: u64, g: Option<BigUint>) -> Option<Self> {
        let p = kp.p.clone();
        let q = kp.q.clone();
        let n = kp.n.clone();
        let modulus_bytes = (n.bits() as usize).div_ceil(8);
        let g = match g {
            Some(g) => g,
            None => {
                let mut buf = vec![0u8; modulus_bytes];
                rand::thread_rng().fill_bytes(&mut buf);
                let n_minus_3 = &n - BigUint::from(3u32);
                (biguint_from_bytes(&buf) % &n_minus_3) + BigUint::from(2u32)
            }
        };
        let pm1 = &p - BigUint::one();
        let qm1 = &q - BigUint::one();
        let two = BigUint::from(2u32);
        let tt = BigUint::from(t);
        let e_p = two.modpow(&tt, &pm1);
        let e_q = two.modpow(&tt, &qm1);
        let gp = &g % &p;
        let gq = &g % &q;
        let hp = gp.modpow(&e_p, &p);
        let hq = gq.modpow(&e_q, &q);
        let qinv_p = modinv(&(&q % &p), &p)?;
        let mut minter = Self {
            n,
            t,
            g,
            h: BigUint::zero(),
            modulus_bytes,
            n_hex: String::new(),
            g_hex: String::new(),
            h_hex: String::new(),
            pm1,
            qm1,
            gp,
            gq,
            hp,
            hq,
            qinv_p,
            q,
            p,
        };
        let h = minter.crt_combine(&minter.hp.clone(), &minter.hq.clone());
        minter.h = h;
        minter.n_hex = hex_of(&minter.n, Some(modulus_bytes));
        minter.g_hex = hex_of(&minter.g, Some(modulus_bytes));
        minter.h_hex = hex_of(&minter.h, Some(modulus_bytes));
        Some(minter)
    }

    fn crt_combine(&self, ap: &BigUint, aq: &BigUint) -> BigUint {
        let s = mod_sub(ap, aq, &self.p);
        let s = (s * &self.qinv_p) % &self.p;
        aq + &self.q * s
    }

    pub fn mint(&self) -> Minted {
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        self.mint_with_r(&biguint_from_bytes(&buf))
    }

    pub fn mint_with_r(&self, r: &BigUint) -> Minted {
        let rp = r % &self.pm1;
        let rq = r % &self.qm1;
        let xp = self.gp.modpow(&rp, &self.p);
        let xq = self.gq.modpow(&rq, &self.q);
        let yp = self.hp.modpow(&rp, &self.p);
        let yq = self.hq.modpow(&rq, &self.q);
        let x = self.crt_combine(&xp, &xq);
        let y = self.crt_combine(&yp, &yq);
        Minted {
            x_hex: hex_of(&x, Some(self.modulus_bytes)),
            y_hex: hex_of(&y, Some(self.modulus_bytes)),
        }
    }
}

/// Hex comparison with the JS normalisation (`0x` prefix, case, leading zeros).
pub fn verify_solution(expected_y_hex: &str, claimed_y_hex: &str) -> bool {
    // A literally empty claim normalises to "" and would otherwise match an
    // empty expectation. "0"/"000" stay valid (y can legitimately be zero).
    if claimed_y_hex.trim().is_empty() {
        return false;
    }
    fn norm(s: &str) -> String {
        let s = s.strip_prefix("0x").unwrap_or(s).to_ascii_lowercase();
        s.trim_start_matches('0').to_string()
    }
    norm(expected_y_hex) == norm(claimed_y_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf(v: &serde_json::Value) -> BigUint {
        BigUint::parse_bytes(v.as_str().unwrap().as_bytes(), 10).unwrap()
    }

    /// Known-answer vector generated with the JavaScript implementation
    /// (`buildRswMinter` + a fixed r): h, x and y must match bit-for-bit.
    #[test]
    fn matches_js_known_answer_vector() {
        let v: serde_json::Value = serde_json::json!({
            "N": "10381841515623270453844849984491666595915896350211972610022161899551025968457232789995938463569910848593895804859562169708880112394582892229253499888239143",
            "p": "112011221874670573598896778677327637112599993159042196262384674077112849502937",
            "q": "92685726857256493786257718879049659532311097547261283275846217072597755075839",
            "t": 10000,
            "g": "987654321",
            "h": "3166513324990640182292133519600315133651800674221085243676384325917730501923994385341096719337843137473179409150050758884198722475736992160001819275576186",
            "r": "81985529216486895",
            "x": "4c0080e67a786942dd4c93f0508844abe0453a86f1c2a3a2c643ba60fc68c0ed59ae1c528163608086d92159c04ddaa16a9575125b3619ca0e59b46ca3173c96",
            "y": "22f4c80ef1d170a116ba444219f2e6fea72430fb2af47ab5d7e58abcfde0c11d6a5accc23f3086aa65777f8af707d941279434032aafcbe2f7ac01fd11d6bfdb",
            "modulusBytes": 64
        });
        let kp = deserialize_keypair(&v).unwrap();
        let g = buf(&v["g"]);
        let minter = RswMinter::build(&kp, 10_000, Some(g)).unwrap();
        assert_eq!(minter.h.to_str_radix(10), v["h"].as_str().unwrap());
        assert_eq!(
            minter.modulus_bytes,
            v["modulusBytes"].as_u64().unwrap() as usize
        );

        let minted = minter.mint_with_r(&buf(&v["r"]));
        assert_eq!(minted.x_hex, v["x"].as_str().unwrap());
        assert_eq!(minted.y_hex, v["y"].as_str().unwrap());
    }

    #[test]
    fn mint_and_verify_roundtrip() {
        let kp = generate_keypair(512);
        let minter = RswMinter::build(&kp, 1_000, Some(BigUint::from(12345u32))).unwrap();
        let m = minter.mint();
        assert!(verify_solution(&m.y_hex, &m.y_hex));
        assert!(!verify_solution(&m.y_hex, &m.x_hex));
        // 0x/leading zero normalisation matches the JS behaviour.
        assert!(verify_solution("00ab", "0x00AB"));
        assert!(verify_solution("000", "0"));
    }

    #[test]
    fn keypair_serde_roundtrip() {
        let kp = generate_keypair(256);
        let v = serialize_keypair(&kp);
        let back = deserialize_keypair(&v).unwrap();
        assert!(kp.user_eq(&back));
    }

    impl RswKeypair {
        fn user_eq(&self, other: &Self) -> bool {
            self.n == other.n && self.p == other.p && self.q == other.q
        }
    }
}
