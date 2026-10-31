//! Cap proof-of-work protocols.
//!
//! Implemented: `rsw` (Rivest–Shamir–Wagner time-lock puzzle), a 1:1 port of
//! `core/src/rsw.js`, and `hashwx`, a port of `core/src/hashwx.js` that runs
//! the same WASM hash module through `wasmi` for bit-compatible verification.

pub mod hashwx;
pub mod rsw;

pub use hashwx::verify_solution as verify_hashwx_solution;
pub use hashwx::{
    DEFAULT_HASHWX_CHALLENGE_COUNT, DEFAULT_HASHWX_DIFFICULTY, DEFAULT_HASHWX_NONCES_PER_HASH,
    HASHWX_CHALLENGE_SIZE, HASHWX_SEED_SIZE, HashwxSpec, MAX_HASHWX_CHALLENGE_COUNT,
    MAX_HASHWX_DIFFICULTY, MAX_HASHWX_NONCES_PER_HASH, hash_nonce, hashwx_seed, hashwx_target,
    mint_challenges, parse_nonce,
};
pub use rsw::{
    Minted, RswKeypair, RswMinter, deserialize_keypair, generate_keypair, serialize_keypair,
    verify_solution,
};
