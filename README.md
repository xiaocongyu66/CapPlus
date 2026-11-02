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

### Reverse proxy: Caddy / Traefik / nginx

建议设置 `CAP_TRUST_PROXY=true` 和 `CAP_PROXY_SECRET=<random>`，并让反代覆盖
`x-cap-proxy-secret`。配置 secret 后必须匹配，地址白名单不能绕过错误或缺失的 secret。

无 secret 的部署必须显式设置 `CAP_TRUSTED_PEER_CIDRS`，例如仅本机反代使用
`127.0.0.1/32,::1/128`。该名单只授权直接连接的代理；私网和回环地址不再自动可信。
启用代理信任却未配置 secret 或直接来源名单会启动失败。
`CAP_TRUSTED_PROXY_CIDRS` 仅指定 XFF 中可剥离的中间代理跳，不能替代直接来源名单。
默认取最右客户端地址（包括私网客户端），仅剥离显式可信中间跳。

```caddyfile
# Caddyfile
example.com {
    reverse_proxy 127.0.0.1:3000 {
        header_up x-cap-proxy-secret {env.CAP_PROXY_SECRET}
    }
}
```

```yaml
# Traefik (labels on the cap-server service)
- "traefik.http.middlewares.cap-headers.headers.customrequestheaders.x-cap-proxy-secret=${CAP_PROXY_SECRET}"
- "traefik.http.routers.cap.middlewares=cap-headers"
```

Both set `X-Forwarded-For` / `X-Forwarded-Proto` themselves; the server derives
the `tls` signal from the forwarded proto, so plain-HTTP bots are penalised.

For JA3/JA4 and HTTP/2 fingerprinting, a proxy or plugin that can see the
ClientHello must send a signed header (HMAC-SHA256 hex of the raw value with
`CAP_PROXY_SECRET`):

```text
x-cap-net-fp:     {"tls":true,"ja4Browser":true,"ja3Browser":true,
                   "http2Browser":true,"uaMismatch":false}
x-cap-net-fp-sig: <hex>
```

Caddy and Traefik do not compute these natively; without such a header the
server simply has no network signals (no honest client is penalised).

Embed sessions are enforced by default: `challenge` and `redeem` must come from
the same signed embed page (`CAP_REQUIRE_VSESS=0` disables this for direct API
clients; a token then still works only for the site key that minted it).

Enforcement only applies to keys with `corsOrigins` configured: a key without
an origin allowlist cannot be framed at all, so it keeps working without the
embed session (and without the extra binding).

This binding prevents a token obtained in one framing from being redeemed in
another. It is not proof that a browser ran the page: the embed page is public,
so a script can fetch its own context. Likewise the `hostname` returned by
`siteverify` is the framing origin claimed by that challenge, not a
server-verified statement about where the solve happened; do not use it as an
origin-security check.

Only `X-Forwarded-For` is trusted by default. Proxies such as Caddy and Traefik
neither set nor strip `CF-Connecting-IP` / `X-Real-IP`, so those headers are
ignored unless you point `RATELIMIT_IP_HEADER` at the one your proxy actually
overwrites.

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
4. 从 `/assets/*` 提供当前选择的发布资源。未选择发布时使用二进制内嵌资源；
   已选择发布缺文件返回 404，配置损坏返回 503，不从 CDN 或其他版本补齐。

服务端不再启动后台 CDN 刷新。旧 `ENABLE_ASSETS_SERVER`、`CACHE_HOST`、
`WIDGET_VERSION`、`WASM_VERSION` 配置不再触发该刷新；自定义 `EMBED_WIDGET_URL`
仍可能指向外部资源，严格离线部署需自行确认其来源。

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
