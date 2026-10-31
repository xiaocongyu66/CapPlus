/*
 * Lightweight i18n overlay for the Cap dashboard.
 *
 * The dashboard is rendered from template strings, so instead of keying every
 * string we translate the rendered DOM: exact-match dictionary entries for
 * text nodes, plus a handful of patterns for counts. A MutationObserver keeps
 * re-rendered panels translated. Switching back to English restores the
 * original text from a WeakMap — no reload, no lost UI state.
 *
 * Skips code blocks, inputs, scripts and SVG so snippets are never touched.
 */
(function () {
  "use strict";

  var STORE_KEY = "cap-dashboard-lang";
  var lang = "en"; // resolved below

  var DICT = {
    // ---- shell / nav -------------------------------------------------------
    "New key": "新建密钥",
    "Settings": "设置",
    "Search keys...": "搜索密钥…",
    "Search networks": "搜索网络",
    "Logout": "退出登录",
    "Open menu": "打开菜单",
    "Add Cap to your site in 60 seconds": "60 秒把 Cap 接入你的网站",
    "Create a sitekey, paste two snippets, you're live.":
      "创建一个站点密钥，粘贴两段代码，即可上线。",
    "Create your first key": "创建你的第一个密钥",
    "1. Name your key": "1. 命名密钥",
    "2. Copy the snippets": "2. 复制代码片段",
    "3. Ship": "3. 上线",
    "Read the docs →": "阅读文档 →",
    "No keys yet!": "还没有密钥！",
    "No keys yet": "还没有密钥",
    "No matching keys": "没有匹配的密钥",
    "Untitled key": "未命名密钥",
    // ---- keys --------------------------------------------------------------
    "API key": "API 密钥",
    "API keys": "API 密钥",
    "No API keys yet": "还没有 API 密钥",
    "Site key": "站点密钥",
    "Site Key": "站点密钥",
    "Site key access": "站点密钥权限",
    "Secret key": "密钥",
    "New secret key": "新密钥",
    "Key name": "密钥名称",
    "Name": "名称",
    "Label": "标签",
    "Value": "值",
    "Type": "类型",
    "Create": "创建",
    "Copy": "复制",
    "Copied": "已复制",
    "Save": "保存",
    "Saved": "已保存",
    "Cancel": "取消",
    "Delete": "删除",
    "Remove": "移除",
    "Add": "添加",
    "Done": "完成",
    "Close": "关闭",
    "Edit": "编辑",
    "Update": "更新",
    "Open key": "打开密钥",
    "Rotate": "轮换",
    "Rotate Secret?": "轮换密钥？",
    "Rotated secret key": "已轮换密钥",
    "Revoke": "吊销",
    "Revoke share link?": "吊销分享链接？",
    "Permanent": "永久",
    "Never": "永不",
    "Expires": "过期时间",
    "Expired": "已过期",
    "Active": "启用",
    "Disabled": "已禁用",
    "Verified": "已验证",
    "Failed": "失败",
    "Error": "错误",
    "Warning": "警告",
    "Danger zone": "危险操作",
    // ---- configuration -----------------------------------------------------
    "Configuration": "配置",
    "Challenge protocol": "挑战协议",
    "SHA-256 proof of work": "SHA-256 工作量证明",
    "RSW time-lock puzzle": "RSW 时间锁难题",
    "HashWX difficulty": "HashWX 难度",
    "HashWX difficulty ": "HashWX 难度",
    "RSW difficulty": "RSW 难度",
    "RSW difficulty ": "RSW 难度",
    "Difficulty": "难度",
    "Challenge count": "挑战数量",
    "Challenges": "挑战",
    "Obfuscation level": "混淆等级",
    "Obfuscation level ": "混淆等级 ",
    "Instrumentation": "环境探测",
    "Enable instrumentation (recommended)": "启用环境探测（推荐）",
    "Enable instrumentation challenges": "启用环境探测挑战",
    "Attempt to block headless browsers": "尝试拦截无头浏览器",
    "Obfuscate to an extreme": "极致混淆",
    "Security": "安全",
    "Require session binding": "要求会话绑定",
    "Allow unbound tokens": "允许未绑定令牌",
    "Require verified session": "要求已验证会话",
    "Block on deny": "拒绝时直接拦截",
    "Auto-block on deny": "拒绝时自动封禁",
    "Block duration (ms)": "封禁时长（毫秒）",
    "Restrict allowed origins": "限制允许的来源",
    "Allowed origins": "允许的来源",
    "Add an origin…": "添加来源…",
    "Add an origin": "添加来源",
    "Rate limiting": "速率限制",
    "Global rate limit": "全局限流",
    "Max requests": "最大请求数",
    "Requests allowed per window": "每窗口允许的请求数",
    "Window (ms)": "窗口（毫秒）",
    "Request filtering": "请求过滤",
    "Block requests missing common browser headers.":
      "拦截缺少常见浏览器请求头的请求。",
    "Required headers": "必需的请求头",
    "Proxy headers": "代理请求头",
    "IP header": "IP 请求头",
    "Presets": "预设",
    "Request headers": "请求头",
    // ---- analytics ---------------------------------------------------------
    "Challenges": "挑战",
    "Avg. duration": "平均耗时",
    "Avg duration": "平均耗时",
    "Duration": "耗时",
    "Today": "今天",
    "Yesterday": "昨天",
    "Last 7 days": "最近 7 天",
    "Last 30 days": "最近 30 天",
    "Last 3 months": "最近 3 个月",
    "Sessions": "会话",
    "Share links": "分享链接",
    "No share links yet": "还没有分享链接",
    "New share link": "新建分享链接",
    "Untitled link": "未命名链接",
    "Link": "链接",
    "Share link created": "分享链接已创建",
    "Share links are not available in demo mode": "演示模式不支持分享链接",
    "Share links are not available in demo mode.": "演示模式不支持分享链接。",
    // ---- geo / networks ----------------------------------------------------
    "Location": "位置",
    "Networks": "网络",
    "Country": "国家",
    "Provider": "服务商",
    "Platform": "平台",
    "OS": "操作系统",
    "Main": "主要",
    "Frontend": "前端",
    "Country header": "国家请求头",
    "Country code": "国家代码",
    "Country & ASN data": "国家与 ASN 数据",
    "ASN / Network header": "ASN / 网络请求头",
    "IP address": "IP 地址",
    "IP range (CIDR)": "IP 范围（CIDR）",
    "No network data yet.": "还没有网络数据。",
    "No location data yet.": "还没有位置数据。",
    "No platform data yet.": "还没有平台数据。",
    "No OS data yet.": "还没有操作系统数据。",
    "Map view": "地图视图",
    "Select country...": "选择国家…",
    "Block rules": "拦截规则",
    "No block rules yet": "还没有拦截规则",
    "Blocked": "已拦截",
    "Allow": "允许",
    "Block": "拦截",
    // ---- verification / integrations --------------------------------------
    "Server verification": "服务端验证",
    "Frontend integration": "前端接入",
    "Copy the snippets": "复制代码片段",
    "AI prompt": "AI 提示词",
    "Copy prompt": "复制提示词",
    "Geolocation": "地理位置",
    "MaxMind GeoLite2": "MaxMind GeoLite2",
    "MaxMind GeoLite2 (free, needs license key)":
      "MaxMind GeoLite2（免费，需要许可证密钥）",
    "MaxMind account ID": "MaxMind 账户 ID",
    "MaxMind license key": "MaxMind 许可证密钥",
    "MaxMind account ID:": "MaxMind 账户 ID：",
    "MaxMind license key:": "MaxMind 许可证密钥：",
    "Your MaxMind account ID": "你的 MaxMind 账户 ID",
    "Your GeoLite2 license key": "你的 GeoLite2 许可证密钥",
    "IPInfo": "IPInfo",
    "IPInfo token": "IPInfo 令牌",
    "Your IPInfo API token": "你的 IPInfo API 令牌",
    "Nginx": "Nginx",
    "Vercel": "Vercel",
    "Cloudflare": "Cloudflare",
    // ---- dialogs / toasts --------------------------------------------------
    "Are you sure?": "确定吗？",
    "This will permanently delete this API key.":
      "此操作将永久删除该 API 密钥。",
    "Please check your input values.": "请检查输入内容。",
    "Validation error": "校验错误",
    "Unauthorized": "未授权",
    "Not authenticated": "未登录",
    "Something went wrong": "出了点问题",
    "Settings saved": "设置已保存",
    "Copied to clipboard": "已复制到剪贴板",
    "Preparing RSW keypair…": "正在生成 RSW 密钥对…",
    "Loading...": "加载中…",
    "Loading…": "加载中…",
    "Search": "搜索",
    "Filter": "筛选",
    "All": "全部",
    "None": "无",
    "Yes": "是",
    "No": "否",
    "On": "开",
    "Off": "关",
    "Enabled": "已启用",
    "Turn on": "开启",
    "Turn off": "关闭",
    "Unknown": "未知",
    "example.com": "example.com",
    "Range": "范围",
    "count": "计数",
    // ---- login -------------------------------------------------------------
    "The self-hosted CAPTCHA for the modern web.":
      "面向现代 Web 的自托管 CAPTCHA。",
    "Admin key": "管理密钥",
    "Continue to Cap": "进入 Cap",
    "Report issues": "反馈问题",
    "Powered by Cap": "由 Cap 提供支持",
    "Invalid admin key": "管理密钥错误",
    "Enter your admin key": "请输入管理密钥",
    // ---- misc --------------------------------------------------------------
    "Documentation": "文档",
    "Docs": "文档",
    "Support": "支持",
    "Version": "版本",
    "About": "关于",
    "Apply": "应用",
    "Reset": "重置",
    "Refresh": "刷新",
    "Export": "导出",
    "Import": "导入",
    "Test": "测试",
    "Tester": "测试器",
    // ---- extra coverage (dashboard panels) --------------------------------
    "About": "关于",
    "All site keys": "全部站点密钥",
    "All time": "全部时间",
    "ASN": "ASN",
    "Activity": "活动",
    "Integration": "接入",
    "Copy site key": "复制站点密钥",
    "Copy link": "复制链接",
    "Create link": "创建链接",
    "Current": "当前",
    "Clear": "清空",
    "Check our": "查看我们的",
    "documentation": "文档",
    "headers": "请求头",
    "read-only": "只读",
    "Demo mode": "演示模式",
    "Download & activate": "下载并启用",
    "Downloading...": "下载中…",
    "IP data": "IP 数据",
    "IP database": "IP 数据库",
    "IP Database": "IP 数据库",
    "DB-IP Lite (free, no key needed)": "DB-IP Lite（免费，无需密钥）",
    "IPInfo (API, needs token)": "IPInfo（API，需要令牌）",
    "Only selected site keys": "仅选中的站点密钥",
    "Header containing the 2-letter ISO country code":
      "包含两位 ISO 国家代码的请求头",
    "Header containing the ASN or network name": "包含 ASN 或网络名称的请求头",
    "Higher difficulty means slower solve time": "难度越高，求解越慢",
    "In 7 days": "7 天内",
    "In 30 days": "30 天内",
    "In 90 days": "90 天内",
    "HashWX proof of work": "HashWX 工作量证明",
    "Configure a lookup source in IP data settings to store location data.":
      "请在 IP 数据设置中配置查询源，以记录位置数据。",
    "Configure a lookup source in IP data settings to store network data.":
      "请在 IP 数据设置中配置查询源，以记录网络数据。",
    "Error loading keys": "加载密钥失败",
    "Failed to create key.": "创建密钥失败。",
    "Failed to delete key.": "删除密钥失败。",
    "Failed to load map data": "加载地图数据失败",
    "Failed to rotate secret key.": "轮换密钥失败。",
    "Failed to save configuration.": "保存配置失败。",
    "Failed to save security settings.": "保存安全设置失败。",
    // ---- session & verification -------------------------------------------
    "Session & verification": "会话与验证",
    "Abuse response": "处置策略",
    "Require verified session": "要求已验证会话",
    "Only accept tokens issued by the Cap-hosted embed iframe. Leave off for same-origin/path-mount installs.":
      "只接受由 Cap 托管的嵌入 iframe 签发的令牌。同源/子路径部署请关闭。",
    "Strict session binding": "严格会话绑定",
    "At verification, require the forwarded IP/host to match the challenge session (not just the UA).":
      "验证时要求转发的 IP/host 与挑战会话一致（不仅是 UA）。",
    "Allow unbound tokens": "允许未绑定令牌",
    "Skip session binding at verification entirely (legacy tokens, custom integrations).":
      "验证时完全跳过会话绑定（兼容旧令牌与自定义集成）。",
    "Reject low-trust solves": "拒绝低信誉求解",
    "A hostile reputation verdict rejects the solve instead of only reporting it.":
      "信誉判定为恶意时直接拒绝该次求解，而不仅仅是记录。",
    "Auto-block on deny": "拒绝时自动封禁",
    "Temporarily block the client IP after a denied solve.":
      "求解被拒绝后临时封禁该客户端 IP。",
    "Block duration (ms)": "封禁时长（毫秒）",
    "Throttle on restrict": "可疑时限速",
    "Slow down the client temporarily when the solve is only partially suspicious.":
      "当求解仅部分可疑时，临时对客户端限速。",
    "Throttle duration (ms)": "限速时长（毫秒）",
    "Probe variation": "探针变化",
    "Randomly drop part of the optional probe set per session (0 = keep everything).":
      "每次会话随机丢弃部分可选探针（0 = 全部保留）。",
    "Extended consistency probes": "扩展一致性探针",
    "WebGL, canvas, audio, emoji, worker, CDP and active capability probes.":
      "WebGL、canvas、音频、emoji、Worker、CDP 以及主动能力探针。",
    "Salt size": "盐长度",

    // ---- remaining dashboard strings --------------------------------------
    "List view": "列表视图",
    "Filter networks…": "筛选网络…",
    "e.g. 1.2.3.4": "例如 1.2.3.4",
    "e.g. Acme marketing team (optional)": "例如 Acme 市场团队（可选）",
    "e.g. CF-Connecting-IP": "例如 CF-Connecting-IP",
    "e.g. CF-IPCountry": "例如 CF-IPCountry",
    "e.g. CF-IPOrg": "例如 CF-IPOrg",
    "Copied!": "已复制！",
    "Drop this into your AI assistant to have it implement Cap end-to-end.":
      "把这段交给你的 AI 助手，即可端到端完成 Cap 的接入。",
    "Failed to generate the RSW keypair. Try again in a moment.":
      "生成 RSW 密钥对失败，请稍后重试。",
    "Choose how to resolve country and ASN for each IP. Use":
      "选择如何解析每个 IP 的国家与 ASN。使用",
    "e.g. Acme marketing team": "例如 Acme 市场团队",

    "Expected hashes per solve. Higher difficulty means slower solve time":
      "每次求解的期望哈希次数。难度越高，求解越慢。",
    "This may cause issues with testing or agent browsers and is not entirely foolproof.":
      "这可能会影响自动化测试或 AI 代理浏览器，且并非万无一失。",
    "Higher obfuscation may result in higher CPU usage.":
      "混淆等级越高，CPU 占用可能越高。",
    "Override the global rate limit for this key. Leave empty to use the global defaults (30 reqs / 5s).":
      "为此密钥覆盖全局限流。留空则使用全局默认值（30 次 / 5 秒）。",
    "Override the global filtering for this key. Leave unchecked to use global defaults.":
      "为此密钥覆盖全局过滤。不勾选则使用全局默认值。",
    "Block non-browser user agents": "拦截非浏览器 User-Agent",
    "Blocks requests from bots, scripts, and other non-browser clients (e.g. python-requests, curl).":
      "拦截来自机器人、脚本及其他非浏览器客户端（如 python-requests、curl）的请求。",
    "Require browser headers": "要求浏览器请求头",
    "Add rule": "添加规则",
    "New link": "新建链接",
    "Anyone with a link can view this key's stats. No login, no access to configuration or secrets.":
      "任何拿到链接的人都可以查看该密钥的统计信息，无需登录，且无法访问配置或密钥内容。",
    "Reset site secret": "重置站点密钥",
    "Delete key": "删除密钥",
    "Salt size": "盐长度",
    "Challenge size": "挑战长度",
    "Expected hashes per solve": "每次求解的期望哈希次数",
    "This may cause issues with testing or agent browsers": "这可能影响自动化测试或 AI 代理浏览器",
    "No keys match your search.": "没有匹配的密钥。",
    "Bun": "Bun",

    "Demo": "演示",
    // ---- front-end releases ------------------------------------------------
    "Front-end": "前端",
    "built-in": "内置",
    "Front-end releases": "前端发布",
    "Upload zip": "上传 zip",
    "Download": "下载",
    "Activate": "启用",
    "active": "当前",
    "No releases published yet. The widget is served from the CDN.":
      "还没有发布版本，验证组件将从 CDN 加载。",
    "Upload a zip with the verification widget files (widget.js, cap_wasm.js, hashwx.wasm, embed.js…). JavaScript is obfuscated and encrypted automatically. Older releases are kept, so you can switch back at any time.":
      "上传包含验证组件文件（widget.js、cap_wasm.js、hashwx.wasm、embed.js…）的 zip 包。JavaScript 会自动混淆并加密。旧版本会保留，可随时切回。",
    "Delete release?": "删除发布版本？",
    "The bundle will be removed from disk. The widget keeps serving the active release.":
      "该版本将从磁盘删除，验证组件继续使用当前启用的版本。",
    "Uploading": "正在上传",
    "Published": "已发布",
    "file(s) protected": "个文件已加密",
    "Upload failed.": "上传失败。",
    "Activation failed.": "启用失败。",
    // ---- dialogs / misc ----------------------------------------------------
    "Create key": "创建密钥",
    "Create API Key": "创建 API 密钥",
    "API key created": "API 密钥已创建",
    "Key created": "密钥已创建",
    "Delete API key?": "删除 API 密钥？",
    "Delete Key?": "删除密钥？",
    "Delete IP Database?": "删除 IP 数据库？",
    "Add block rule": "添加封禁规则",
    "Read-only": "只读",
    "Star on GitHub": "在 GitHub 上点星",
    "CORS": "CORS",
    "1 hour": "1 小时",
    "24 hours": "24 小时",
    "7 days": "7 天",
    "30 days": "30 天",
    "Can list keys and read stats, but can't create, change or delete anything.":
      "只能查看密钥和统计数据，不能创建、修改或删除任何内容。",
    "Copy it now, it won't be shown again. You can revoke it at any time from this page.":
      "请立即复制，此链接不会再显示。你可以随时在本页撤销。",
    "Make sure to copy this \u2014 it won\u2019t be shown again.":
      "请立即复制 \u2014 之后不再显示。",
    "Make sure to copy your API key \u2014 it won\u2019t be shown again.":
      "请立即复制你的 API 密钥 \u2014 之后不再显示。",
    "Make sure to copy your secret key \u2014 it won\u2019t be shown again.":
      "请立即复制你的密钥 \u2014 之后不再显示。",
    "Only these origins will be able to request challenges for this key.":
      "只有这些来源可以为该密钥发起验证请求。",
    "Only these origins will be able to request challenges. Individual keys can override this.":
      "只有这些来源可以发起验证请求，单个密钥可覆盖此设置。",
    "Time window in milliseconds (e.g. 5000 = 5s)":
      "时间窗口（毫秒，例如 5000 = 5 秒）",
    "Add an origin\u2026": "添加来源…",
    "Filter networks\u2026": "筛选网络…",
    "No site keys yet": "还没有站点密钥",
    "Set the header your reverse proxy uses to pass the client's real IP. Used for rate limiting, IP tracking, and geo lookups.":
      "设置反向代理传递客户端真实 IP 的请求头。用于速率限制、IP 追踪和地理位置查询。",
    "Default rate limit applied to all challenge endpoints. Individual keys can override these values in their configuration.":
      "应用于所有验证端点的默认速率限制。单个密钥可在其配置中覆盖这些值。",
    "Choose how to resolve country and ASN for each IP. Use":
      "选择如何解析每个 IP 的国家与 ASN。使用",
    "if your reverse proxy provides them, or download an":
      "请求头（如果反向代理提供），或下载一个",
    "for automatic lookups.": "以实现自动查询。",
    "Requests allowed per window": "每个窗口允许的请求数",
    "Window (ms)": "窗口（毫秒）",
    "Max requests": "最大请求数",

    "Block requests that don't look like they come from real browsers. Individual keys can override these defaults.":
      "拦截看起来不是来自真实浏览器的请求。单个密钥可覆盖这些默认值。",
    "The link shows challenge, verification and location stats for this key only. It can't change anything.":
      "该链接仅展示此密钥的验证、校验和位置统计，无法修改任何内容。",
    "for more frameworks and details.": "查看更多框架和细节。",
    // ---- login / share / tester pages --------------------------------------
    "Cap Standalone": "Cap 独立版",
    "Cap stats": "Cap 统计",
    "Challenge tester": "验证测试器",
    "Free, privacy-first, self-hosted CAPTCHA alternative.":
      "免费、隐私优先、可自托管的 CAPTCHA 替代方案。",
    "Get Cap for your site": "为你的网站接入 Cap",
    "Key ID:": "密钥 ID：",
    "Secret key:": "密钥：",
    "Show/hide password": "显示/隐藏密码",
    "No logs": "暂无日志",
    "Start": "开始",
    "e.g. 19d7e51172": "例如 19d7e51172",
    "e.g. sk-eOAdXZvmQecVrvh...": "例如 sk-eOAdXZvmQecVrvh...",

    "Mobile app": "移动应用",
    "Docs site": "文档站",
    "Shop front": "商店前台",
    "Dashboard app": "管理后台",


  };

  // Counts and simple templates the exact-match pass cannot cover.
  var PATTERNS = [
    [/^(\d+)\s+keys?$/i, "$1 个密钥"],
    [/^(\d+)\s+sessions?$/i, "$1 个会话"],
    [/^(\d+)\s+requests?$/i, "$1 个请求"],
    [/^(\d+)\s+days? ago$/i, "$1 天前"],
    [/^(\d+)\s+hours? ago$/i, "$1 小时前"],
    [/^(\d+)\s+minutes? ago$/i, "$1 分钟前"],
    [/^just now$/i, "刚刚"],
    [/^(\d+)\s*ms$/i, "$1 毫秒"],
    [/^(\d+)\s*s$/i, "$1 秒"],
    [/^(\d+)\s+recent sol(?:ve|ves)$/i, "$1 次近期求解"],
    [/^(\d+)\s+files?$/i, "$1 个文件"],
    [/^(\d+)\s+protected$/i, "$1 个已加密"],
    // Release row: "4 minutes ago · 3 files · 0.9 KB · 2 protected"
    [
      /^(.+?) · (\d+) files? · ([\d.]+ [KM]B) · (\d+) protected$/i,
      function (m) {
        return cnRelative(m[1]) + " · " + m[2] + " 个文件 · " + m[3] + " · " + m[4] + " 个已加密";
      },
    ],
    [/^expires in (.+)$/i, function (m) { return cnUnits(m[1]) + "后过期"; }],
    [
      /^[\u2022\u00b7] expires in (.+)$/i,
      function (m) { return "\u2022 " + cnUnits(m[1]) + "后过期"; },
    ],
    [/^created (.+)$/i, function (m) { return "创建于 " + cnUnits(m[1]); }],
    [
      /^in (\d+) (minutes?|hours?|days?|weeks?|months?)$/i,
      function (m) { return m[1] + " " + cnUnits(m[2]) + "内"; },
    ],
  ];

  var UNITS = {
    minute: "分钟",
    minutes: "分钟",
    hour: "小时",
    hours: "小时",
    day: "天",
    days: "天",
    week: "周",
    weeks: "周",
    month: "个月",
    months: "个月",
  };

  function cnRelative(text) {
    var t = String(text).trim();
    if (/^just now$/i.test(t)) return "刚刚";
    return cnUnits(t).replace(/\bago\b/gi, "前");
  }

  function cnUnits(text) {
    return String(text).replace(
      /\b(minutes?|hours?|days?|weeks?|months?)\b/gi,
      function (w) { return UNITS[w.toLowerCase()] || w; },
    );
  }

  var SKIP_TAGS = {
    SCRIPT: 1,
    STYLE: 1,
    CODE: 1,
    PRE: 1,
    TEXTAREA: 1,
    KBD: 1,
    SAMP: 1,
    SVG: 1,
    PATH: 1,
    CIRCLE: 1,
    RECT: 1,
    LINE: 1,
    POLYGON: 1,
    POLYLINE: 1,
    G: 1,
    CANVAS: 1,
    NOSCRIPT: 1,
  };
  var ATTRS = ["placeholder", "title", "aria-label"];

  var nodeOrig = new WeakMap();
  var attrOrig = new WeakMap();
  var busy = false;

  function lookup(text) {
    if (Object.prototype.hasOwnProperty.call(DICT, text)) return DICT[text];
    for (var i = 0; i < PATTERNS.length; i++) {
      var re = PATTERNS[i][0];
      var rule = PATTERNS[i][1];
      if (!re.test(text)) continue;
      if (typeof rule === "function") return rule(text.match(re));
      return text.replace(re, rule);
    }
    return null;
  }

  function isSkipped(el) {
    if (!el || el.nodeType !== 1) return false;
    if (el.hasAttribute && el.hasAttribute("data-no-i18n")) return true;
    var tag = (el.tagName || "").toUpperCase();
    return SKIP_TAGS[tag] === 1;
  }

  function applyText(node) {
    var raw = node.nodeValue;
    if (!raw) return;
    var trimmed = raw.trim();
    if (!trimmed) return;
    // Template output often carries indentation inside a single text node;
    // compare with runs of whitespace collapsed to one space.
    var norm = trimmed.replace(/\s+/g, " ");
    var mapped = lookup(trimmed) || (norm !== trimmed ? lookup(norm) : null);
    if (!mapped || mapped === trimmed) return;
    if (!nodeOrig.has(node)) nodeOrig.set(node, raw);
    var lead = raw.match(/^\s*/)[0];
    var trail = raw.match(/\s*$/)[0];
    node.nodeValue = lead + mapped + trail;
  }

  function applyAttrs(el) {
    for (var i = 0; i < ATTRS.length; i++) {
      var attr = ATTRS[i];
      if (!el.hasAttribute || !el.hasAttribute(attr)) continue;
      var value = el.getAttribute(attr);
      if (!value) continue;
      var mapped = lookup(value.trim());
      if (!mapped || mapped === value) continue;
      var store = attrOrig.get(el);
      if (!store) {
        store = {};
        attrOrig.set(el, store);
      }
      if (!(attr in store)) store[attr] = value;
      el.setAttribute(attr, mapped);
    }
  }

  function walk(root) {
    if (!root) return;
    if (root.nodeType === 3) {
      if (!isSkipped(root.parentNode)) applyText(root);
      return;
    }
    if (root.nodeType !== 1) return;
    if (isSkipped(root)) return;
    applyAttrs(root);
    for (var n = root.firstChild; n; n = n.nextSibling) walk(n);
  }

  function restoreText(node) {
    if (node.nodeType === 3) {
      if (nodeOrig.has(node)) node.nodeValue = nodeOrig.get(node);
      return;
    }
    if (node.nodeType !== 1 || isSkipped(node)) return;
    var store = attrOrig.get(node);
    if (store) {
      for (var attr in store) {
        if (Object.prototype.hasOwnProperty.call(store, attr)) {
          node.setAttribute(attr, store[attr]);
        }
      }
    }
    for (var n = node.firstChild; n; n = n.nextSibling) restoreText(n);
  }

  function applyAll() {
    if (lang !== "zh") return;
    busy = true;
    try {
      walk(document.body || document.documentElement);
      // Document title is part of the UI too.
      if (document.title && DICT[document.title]) document.title = DICT[document.title];
    } finally {
      busy = false;
    }
  }

  function restoreAll() {
    busy = true;
    try {
      restoreText(document.body || document.documentElement);
      if (document.title === DICT["Cap Standalone"]) document.title = "Cap Standalone";
    } finally {
      busy = false;
    }
  }

  // ---- observer -----------------------------------------------------------
  var pending = false;
  function schedule() {
    if (pending) return;
    pending = true;
    (window.requestAnimationFrame || setTimeout)(function () {
      pending = false;
      if (lang === "zh") applyAll();
    }, 16);
  }

  function observe() {
    var mo = new MutationObserver(function () {
      if (busy) return;
      schedule();
    });
    mo.observe(document.documentElement, {
      childList: true,
      subtree: true,
      characterData: true,
      attributes: true,
      attributeFilter: ATTRS,
    });
  }

  // ---- switcher -----------------------------------------------------------
  // Lives where it belongs: inside the sidebar footer next to Settings. On
  // chrome-less pages (login/share/tester) it renders inline under the content
  // instead — never as a floating element over the UI.
  function langLabel() {
    return lang === "zh" ? "中文" : "English";
  }

  function toggle() {
    setLang(lang === "zh" ? "en" : "zh");
    paintAll();
  }

  var switchers = [];

  function makeSwitcher() {
    if (document.getElementById("cap-lang-switcher")) return;
    var footer = document.querySelector("#appSidebar .sidebar-footer");
    var btn = document.createElement("button");
    btn.type = "button";
    btn.id = "cap-lang-switcher";
    btn.setAttribute("data-no-i18n", "");
    btn.setAttribute("title", "Switch language / 切换语言");
    btn.innerHTML =
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
      'stroke-linecap="round" stroke-linejoin="round" width="15" height="15">' +
      '<circle cx="12" cy="12" r="9"></circle><path d="M3 12h18"></path>' +
      '<path d="M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18"></path></svg>' +
      '<span class="cap-lang-label"></span>';

    if (footer) {
      btn.className = "settings-btn cap-lang-btn";
      var settingsBtn = footer.querySelector("#settingsBtn");
      if (settingsBtn && settingsBtn.parentNode === footer) footer.insertBefore(btn, settingsBtn);
      else footer.appendChild(btn);
    } else {
      // No sidebar (login / share / tester): inline, under the main content.
      var host =
        document.querySelector("form .bottom") ||
        document.querySelector("form") ||
        document.querySelector("main") ||
        document.body;
      btn.className = "cap-lang-inline";
      btn.style.cssText =
        "margin:16px auto 0;display:inline-flex;align-items:center;gap:6px;" +
        "background:none;border:1px solid currentColor;border-radius:999px;" +
        "padding:6px 12px;font:inherit;font-size:12px;color:inherit;opacity:.7;cursor:pointer";
      if (host.tagName === "P") host.appendChild(document.createTextNode(" "));
      host.appendChild(btn);
    }
    btn.addEventListener("click", toggle);
    switchers.push(btn);
    paintAll();
  }

  function paintAll() {
    for (var i = 0; i < switchers.length; i++) {
      var label = switchers[i].querySelector(".cap-lang-label");
      if (label) label.textContent = langLabel();
    }
  }

  function setLang(next) {
    lang = next === "zh" ? "zh" : "en";
    try {
      localStorage.setItem(STORE_KEY, lang);
    } catch (e) {}
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    if (lang === "zh") applyAll();
    else restoreAll();
    paintAll();
  }

  function init() {
    var stored = null;
    try {
      stored = localStorage.getItem(STORE_KEY);
    } catch (e) {}
    var nav = (navigator.language || "en").toLowerCase();
    lang = stored ? stored : nav.indexOf("zh") === 0 ? "zh" : "en";
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    observe();
    if (lang === "zh") applyAll();
    makeSwitcher();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
