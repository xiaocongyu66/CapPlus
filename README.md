# CapPlus

Rust port of Cap (self-hosted CAPTCHA). Verified-embed-only, Turnstile-compatible
verification, single static binary (~6.8 MB release build; opt-level 3 for
throughput, mimalloc allocator).

## Crates
| crate | role | tests |
|---|---|---|
| `cap-core` | prng / sha256 / HS256 JWT / sha256-pow / session bind | 6 |
| `cap-proto` | RSW time-lock puzzle + hashwx (wasmi, KAT-tested) | 12 |
| `cap-instr` | probe-script generator + JS-compatible MAC canonicaliser | 36 |
| `cap-detect` | probe detector (57 checks, parity-tested vs JS) + trust scoring | 95 |
| `cap-kv` | Redis key/value layer (shared by store + admin) | — |
| `cap-ipdb` | MMDB reader (24/28/32-bit trees) + DB-IP/MaxMind downloader | 7 |
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
- Memory: ~6.8 MB binary (opt-level 3 + mimalloc), small steady-state RSS.
- `hashwx` runs the original WASM hash module via `wasmi` (bit-identical), and
  instrumentation results are HMAC-verified (`instr_mac_mismatch` on tamper).
- IP geolocation: DB-IP Lite (free) and MaxMind GeoLite2 downloads are
  handled in-process with a built-in MMDB reader; country/ASN are recorded per
  verified solve, and proxy headers override the database when configured.
- Request filtering (`blockNonBrowserUA`, required headers), blocked IPs
  (exact / CIDR / country / ASN), CORS for cross-origin widgets, and
  per-key-or-global rate limiting with `metrics:ratelimited`.
- Asset-integrity chain: the operator's WASM/widget SHA-256 baseline is
  sealed into the challenge token and checked at redeem, including the
  RFC-9421-style request proof (`nonce|ts|solutions|hashes`).
- Instrumentation outcomes (`instr_blocked`, `instr_timeout`, sealed expiry,
  accept-language cross-check) are enforced at redeem.
- `DEMO_MODE=true` serves the dashboard without login, with seven synthetic
  keys, charts, geo data and blocked IPs.
- Latency metrics, siteverify rate limiting, `SERVER_HOSTNAME`, `RSW_BITS`,
  `RATELIMIT_IP_HEADER`.
- TODO: edge/WASM deployment.

See `MIGRATION.md` for the Bun → Rust cutover runbook (shared Redis, per-key rollout, rollback).

## Source layout

| path | contents |
|---|---|
| `crates/` | Rust server, admin API, detection, storage, assets |
| `frontend/` | admin dashboard (`cap/standalone/public`) — served by the Rust server and embedded in the binary |
| `widget-source/` | the verification widget sources (`cap.js`, `worker.js`, `cap.css`, i18n, floating widget) plus its build script and tests |
| `wasm-source/` | the `cap_wasm` / `hashwx` WASM crate and its browser/node build outputs |

The widget and dashboard come from the upstream Cap project (Apache-2.0, see `LICENSE`).
Build the widget with `cd widget-source && bun install && bun run build`, then zip
`widget-source/src/*.js` + `*.wasm` and publish it from **Settings → Front-end**.

## Building the protected widget

`bun run build` only applies the upstream obfuscator. Anything served directly
(CDN, another host) must also go through the protector, or the bundle ships
without the encryption shell and the hidden notice:

```bash
cd widget-source && bun run build && cd ..
cargo run --release -p cap-assets --bin cap-protect -- widget-source/src -o widget-dist
# protected N JS file(s), copied M other file(s), left E ES module(s) unchanged
```

`cap-protect` obfuscates + RC4-encrypts `.js`/`.mjs`, copies wasm/css/images,
and leaves ES modules (`import.meta`) untouched so the wasm-bindgen glue keeps
working. Publishing a zip through the dashboard or `POST /server/releases`
applies the same transform server-side, so that path is always protected.

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

## IP geolocation

Settings → **IP data** can download **DB-IP Lite** (free, no key) or
**MaxMind GeoLite2** (needs a license key) into `cappro/ipdb/`. The server
parses the `.mmdb` files itself and records a country/ASN tally for every
verified solve, which drives the Location / Networks charts. If you already
send country or ASN headers from your proxy, configure them under **Proxy
headers** and they take priority over the local database.

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
