# 从 Bun 版切到 Rust 版

两套实现使用部分相同的 Redis 键，但**不能据此认定认证写入协议兼容或可随时回滚**。当前恢复码消费和 2FA 发布采用版本化集合与原子操作，旧实现可能恢复已消费的快照。

## 本轮升级的认证前置条件

1. 升级前确认有可用 TOTP 或有效管理会话；失去这两种渠道后，不能依赖旧恢复码登录新版。
2. 停止全部旧认证写入实例并排空在途请求，再切换到新版。禁止新旧认证写者混跑，也不能直接回滚到旧认证写者。
3. 历史恢复码集合在新版中失效。通过有效管理会话执行 setup，再用新 secret 的 TOTP 确认 enable，保存新恢复码。**禁止给旧恢复码数组手工补 `recoveryVersion` 字段。**
4. 普通 TOTP 登录不依赖恢复码集合版本。状态中的 `recoveryRegenerationRequired` 表示需要重新生成恢复码。
5. 普通 Redis 连接不全局要求 Redis 7；但站点创建与 TOTP 配置发布要求 Redis 7.0+ 的脚本 ACL 检查能力及对应命令权限。能力或权限不足时相关操作失败，不降级为非原子写入。

以下历史迁移说明不构成跨版本协议兼容保证；按站点灰度只能在验证目标版本的实际协议与数据兼容性后使用，并始终满足上述认证单写者限制。

---

## 安全配置升级检查

- 无 secret 的代理部署需配置 `CAP_TRUSTED_PEER_CIDRS`，范围只包含实际直连代理；仅配置中间跳名单不够。启用信任却无 secret 和直接名单时启动失败。
- `settings:filtering` 的开关必须是 JSON boolean，请求头列表必须全是字符串；`settings:ratelimit` 的 max/duration 必须为整数。历史浮点值如 `30.0` 应迁移为 `30`，字符串布尔应修正，不能再依赖错误配置静默回退。
- 配置不存在、合法字段级 null 保持兼容；顶层 null 和损坏配置返回不可用。运行时既有 max<=0 禁用、duration 最小1ms 语义保持，管理写入仍遵循原有正数范围。
- `/assets/*` 仅使用面板选择的发布，未选择时使用当前二进制内嵌完整资源。显式发布缺文件返回404，配置损坏返回503，不跨来源补齐。后台 CDN 刷新已移除；自定义外部 widget URL 仍由部署者控制。

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
| 资产分发 `/assets/*` | ✅（Redis 缓存） | ✅（活动发布或二进制内嵌资源，无后台 CDN 刷新） |
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
| `ENABLE_ASSETS_SERVER` | 已弃用并忽略，不再启动后台 CDN 刷新 |
| `CACHE_HOST` / `WIDGET_VERSION` / `WASM_VERSION` | 保留旧配置解析，不再用于服务端资源下载 |
| `EMBED_WIDGET_URL` | 覆盖 embed 页面里组件的 URL（默认 `/assets/widget.js`） |
| `CAP_TRUST_PROXY` + `CAP_PROXY_SECRET` | 启用反代信任；配置 secret 时必须正确匹配，地址名单不能绕过 |
| `CAP_TRUSTED_PEER_CIDRS` | 无 secret 时必填的直接代理来源名单，逗号分隔；不再默认信任私网或回环 |
| `CAP_TRUSTED_PROXY_CIDRS` | 仅用于剥离 XFF 中间代理跳，不能授权直接连接来源 |
| `RUST_LOG` | 未使用；日志走 stderr（`[redeem] …`、`[cap] assets …`） |

---

## 3. 部署（systemd + nginx 示例）

```ini
# /etc/systemd/system/cap.service
[Service]
Environment=REDIS_URL=redis://127.0.0.1:6379
Environment=SERVER_PORT=3000
Environment=ADMIN_KEY=change-me
Environment=CAP_TRUST_PROXY=true
Environment=CAP_TRUSTED_PEER_CIDRS=127.0.0.1/32,::1/128
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
5. 全量后可保留旧程序作为排查材料，但不得恢复旧认证写入。不同版本的在途挑战和验证令牌兼容性须单独验证，不能按固定等待时间推定安全回滚。

**B. 一次性切换**
停止并排空旧认证请求 → 确认 TOTP/管理会话可用 → 启动新版 → 切换 DNS/反代 → 重新生成恢复码并验证登录。

**回滚**：不能直接切回旧认证写者。必须先确认目标版本支持当前恢复码消费、2FA 配置发布和挑战环境记录格式；不支持时需要独立设计认证数据迁移，不能恢复可能包含已消费恢复码的旧快照。

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
