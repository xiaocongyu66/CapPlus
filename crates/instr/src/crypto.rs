//! Hashing helpers.
//!
//! The generator only needs SHA-256 (for `script_hash`) and a hex encoder for
//! random ids / MAC keys. HMAC itself is performed by the browser (WebCrypto)
//! and re-checked by the server, so it is not needed here.

use sha2::{Digest, Sha256};

/// Lowercase hex encoding of a byte slice.
pub fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

/// SHA-256 of the UTF-8 bytes of `s`, as lowercase hex (64 chars).
///
/// This is exactly what the JS side stores as `scriptHash` (computed over the
/// same utf8 bytes the widget executes).
pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex(&h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_hex("").len(), 64);
    }

    #[test]
    fn hex_padding() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }
}
