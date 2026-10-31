# CapPlus

Rust port of Cap (self-hosted CAPTCHA). Verified-embed-only, Turnstile-compatible
verification, single ~1.3 MB static binary.

## Crates
| crate | role | tests |
|---|---|---|
| `cap-core` | prng / sha256 / HS256 JWT / sha256-pow / session bind | 6 |
| `cap-proto` | RSW time-lock puzzle + hashwx (wasmi, KAT-tested) | 12 |
| `cap-instr` | probe-script generator + JS-compatible MAC canonicaliser | 36 |
| `cap-detect` | probe detector (57 checks, parity-tested vs JS) + trust scoring | 95 |
| `cap-kv` | Redis key/value layer (shared by store + admin) | — |
| `cap-store` | Redis repository (verification flow) | 7 |
| `cap-verify` | Turnstile siteverify contract | 25 |
| `cap-embed` | embed iframe + parent loader | 17 |
| `cap-admin` | management API (+ single-admin 2FA, share links, blocked IPs, geo stats) | 19 |
| `cap-assets` | widget/wasm cache + release publishing (zip upload, auto JS protection) | 38 |
| `cap-server` | axum wiring (v1 sha256-pow, v2 rsw + instrumentation + detection) | smoke |

## Run
```bash
cargo build --release -p cap-server
./target/release/cap-server
# first start creates ./cappro/config.toml with a generated admin key
```

Configuration lives in **`cappro/`** next to the binary (`CAPPRO_DIR` to move
it; mount a volume there in Docker):

```text
cappro/
├── config.toml   settings — environment variables still override
├── releases/     published widget bundles (kept for rollback)
└── tmp/          upload scratch space
```

Storage is Redis (`storage.redis_url` in config.toml, else `REDIS_URL`,
default `redis://127.0.0.1:6379`).

## Status (2026-10-30)
- Protocols: `sha256-pow` (v1), `rsw` (v2, AES-256-GCM sealed expectations),
  `instrumentation` (v2, generated probe + state check + detection/trust).
- Verified end-to-end with the real JS widget inside the cross-origin iframe:
  solve → redeem (Origin==Host, verified marker) → siteverify (consume-once).
- Headless Chromium scores 0 / hostile and is denied when `blockOnDeny`.
- Memory: ~1.3 MB binary, peak RSS ≈ 3 MB (Bun build: ~53 MB).
- `hashwx` runs the original WASM hash module via `wasmi` (bit-identical), and
  instrumentation results are HMAC-verified (`instr_mac_mismatch` on tamper).
- TODO: geo/IP database, demo mode, edge/WASM deployment.

See `MIGRATION.md` for the Bun → Rust cutover runbook (shared Redis, per-key rollout, rollback).

## Front-end releases (zip upload + auto protection)

Settings → **Front-end** in the dashboard uploads a zip of the verification
widget (`widget.js`, `cap_wasm.js`, `*.wasm`, `embed.js`, …). The server:

1. validates the archive (stored/deflate, ≤32 MB, no path traversal),
2. keeps the original zip under `cappro/releases/<id>/source.zip`,
3. obfuscates + encrypts every `.js` file automatically (idempotent — already
   protected files are left alone),
4. serves the processed files from `/assets/*`, taking priority over the CDN.

Every older release stays on disk, so the panel can activate any of them
(one-click rollback) or delete the ones no longer needed.

```bash
curl -X POST https://cap.example.com/server/releases \
  -H "Authorization: Bearer $(printf '{"token":"…","hash":"…"}' | base64 -w0)" \
  -H "Content-Type: application/zip" --data-binary @widget.zip
```

## Admin panel

The official Cap dashboard (`cap/standalone/public/`) is served directly from
the source tree — no build step, no copy. The Rust server auto-discovers it at
`../cap/standalone/public` (or set `ADMIN_LEGACY_DIR`).

```bash
SERVER_PORT=3001 ADMIN_KEY=… ./target/release/cap-server
#  /        → dashboard (cap_authed cookie) or login
#  /login   → login page
#  /public/* → css/js/fonts/charts
#  /share   → public share page
```
