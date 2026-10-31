# 从 Bun 版切到 Rust 版

两套实现**共用同一份 Redis schema**（`key:*`、`token:*`、`bind:*`、`verified:*`、
`blocklist:*`、`rl:*`、`settings:*`、`apikeys`、`sessions`、`settings:rsw_keypair`），
所以可以并存、按站点灰度、随时回滚。

---

## 1. 能力对照

| 能力 | Bun 版 | Rust 版 |
|---|---|---|
| 协议 `sha256-pow` (v1) | ✅ | ✅ |
| 协议 `rsw` (v2) | ✅ | ✅（与 JS 逐位一致，有 KAT） |
| 协议 `hashwx` (v2) | ✅ | ✅（wasmi 执行同一 wasm） |
| instrumentation 下发 + state 校验 | ✅ | ✅ |
| instrumentation MAC 校验 | ✅ | ✅（JS 兼容的 canonical JSON） |
| 探针检测（57 项 check）+ 信任分 | ✅ | ✅（与 JS 逐 check 一致） |
| verified-embed（`/embed.js`、`/embed/:siteKey`） | ✅ | ✅ |
| `/siteverify`（Turnstile 契约）、`/validate` | ✅ | ✅ |
| 管理 API：login / keys / settings / sessions / apikeys / integrity / about | ✅ | ✅ |
| 资产分发 `/assets/*` | ✅（Redis 缓存） | ✅（内存缓存 + 24h 刷新） |
| IP 地理库、share links、demo 模式、登录限流 | ✅ | ❌（见 §6） |

Rust 版**只支持 verified-embed**：`redeem` 必须来自 Cap 自己 origin 的 iframe
（`Origin == Host`），同源直连的旧模式会被 `403 verified_session_required` 拒绝。
所以 Cap 必须挂在**独立 origin**（子域即可，例如 `cap.example.com`）。

---

## 2. 环境变量

| 变量 | 说明 |
|---|---|
| `REDIS_URL` | 与 Bun 版共用同一个实例 |
| `SERVER_PORT` | 监听端口（默认 3000） |
| `ADMIN_KEY` | 管理密钥；不设则管理 API 返回 503 |
| `ENABLE_ASSETS_SERVER=true` | 启动时从 CDN 拉取 widget/wasm 并缓存（`/assets/*`） |
| `CACHE_HOST` / `WIDGET_VERSION` / `WASM_VERSION` | 资产来源（默认 jsDelivr / latest，生产请固定版本） |
| `EMBED_WIDGET_URL` | 覆盖 embed 页面里组件的 URL（默认 `/assets/widget.js`） |
| `CAP_TRUST_PROXY` + `CAP_PROXY_SECRET` | 反代信任规则：无 secret 时只信任本机/内网对端 |
| `RUST_LOG` | 未使用；日志走 stderr（`[redeem] …`、`[cap] assets …`） |

---

## 3. 部署（systemd + nginx 示例）

```ini
# /etc/systemd/system/cap.service
[Service]
Environment=REDIS_URL=redis://127.0.0.1:6379
Environment=SERVER_PORT=3000
Environment=ADMIN_KEY=change-me
Environment=ENABLE_ASSETS_SERVER=true
ExecStart=/usr/local/bin/cap-server
Restart=always
MemoryMax=128M
```

```nginx
server {
  server_name cap.example.com;
  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

如果 nginx 不在本机，请设置 `CAP_TRUST_PROXY=true` + `CAP_PROXY_SECRET=…`，并让
nginx 发送 `x-cap-proxy-secret`。

---

## 4. 切换步骤（按站点灰度）

灰度的最小单位是**站点 key**：同一个 key 的 challenge 和 redeem 必须由同一个后端处理，
因为挑战的期望值密封在服务端签发的 token 里。两种可行做法：

**A. 按 key 分批（推荐）**
1. 部署 Rust 到新端口（如 `:3001`），连同一个 Redis。
2. 新建一个测试 key（`POST /server/keys`，`protocol: "rsw"`），用
   `<script src="https://cap.example.com:3001/embed.js">` 在测试页验证一遍。
3. 用反代按 path/子域把**部分 key 前缀**路由到 Rust，其余仍走 Bun；
   或直接改这些 key 的 `protocol` 并让流量切到 Rust（两者不要交叉）。
4. 观察 `metrics:verified:*` / `metrics:failed:*` 与 `[redeem] trust …` 日志。
5. 全量后保留 Bun 实例只读 24h（token TTL 2h）以便回滚。

**B. 一次性切换**
停 Bun → 起 Rust → 切 DNS/反代。因为 Redis 状态互通，回滚只需切回。

**回滚**：把流量切回 Bun 即可；Rust 写入的 `token:*`/`bind:*`/`verified:*`/`blocklist:*`
Bun 版完全兼容（`verified:` 是新增键，Bun 版忽略它）。

---

## 5. 切换前的数据检查

1. **旧 secretHash**：Bun 历史版本可能用 argon2 存 `secretHash`。Rust 版**不支持**
   argon2（返回 `invalid-input-secret`）。切换前对每个 key 执行一次 `rotate-secret`，
   或在 Bun 端触发一次校验完成 `argon2 → sha256:` 迁移。
2. **rsw keypair**：Rust 从 `settings:rsw_keypair` 读取（与 Bun 相同字段
   `N/p/q/bits/version/created`）。若从未生成过，先在管理面板/接口生成一次。
3. **integrity 基线**：如果开了完整性校验，确认 `settings:integrity` 里的
   widget/WASM 哈希与当前发布的资产一致（切换本身不改变资产）。
4. **代理信任**：确认 `X-Forwarded-For` 只在可信代理后启用，否则绑定/限流会被伪造。

---

## 6. 行为差异（切换前必读）

- `redeem` 只接受来自 Cap origin 的请求（verified-embed）；同源嵌入必须迁移到
  `<cap-embed>` / iframe。
- 绑定语义：UA 必须显式转发（`body.userAgent` 或 `x-cap-client-ua`）；
  `requireSessionBind` 下 IP/host 必须存在且相等；verified 模式不记录 host。
- `/siteverify` 一律 HTTP 200 + `error-codes`（Turnstile 契约），只有请求格式错误是 400。
- 未实现：IP 地理库（`/settings/ipdb*`、geo 统计）、share links、demo 模式、
  登录限流、`/settings/rsw/ensure`（可在 Bun 或手动生成）。
- 管理 API 差异：`GET /keys` 会带上 `config`；校验错误返回 400（Elysia 是 422）；
  `integrity` 的 `refetch` 返回 `unsupported_in_rust_port`（不联网拉取）。

---

## 7. 验收清单

```bash
# 1. 健康
curl -s https://cap.example.com/health                     # {"status":"ok"}

# 2. 管理登录
curl -s -X POST https://cap.example.com/auth/login \
  -H 'content-type: application/json' -d '{"admin_key":"…"}'

# 3. 资产
curl -sI https://cap.example.com/assets/widget.js          # 200 application/javascript

# 4. 完整流程（浏览器打开嵌入页，应出现组件并得到 token）
#    后端 verify 同 Bun 版：POST /<siteKey>/siteverify {secret, response, remoteip}
```
