(() => {
  const ASSET_BASE = (typeof window !== "undefined" && window.CAP_ASSET_BASE
    ? String(window.CAP_ASSET_BASE)
    : "https://cdn.jsdelivr.net"
  ).replace(/\/+$/, "");
  const WASM_VERSION = (typeof window !== "undefined" && window.CAP_WASM_VERSION) || "0.0.8";
  // Self-integrity: a random token embedded in a hidden sentinel inside our
  // shadow tree. If the component is replaced/tampered with, the sentinel is
  // gone or altered and widgetSelf=false is reported (cf closed-shadow check).
  const _selfToken = (typeof crypto !== "undefined" && crypto.randomUUID) ? crypto.randomUUID() : String(Math.random());
  const _selfArmedShadows = new WeakSet();
  const _browserHasHaptics =
    "vibrate" in navigator &&
    !window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  if (typeof window === "undefined") {
    return;
  }

  // Capture our own script URL while the parser is still on this <script>
  // (currentScript is null once execution is async). Used to self-fetch and
  // hash the widget for the optional integrity report.
  const _selfSrc = (() => {
    try {
      return (document.currentScript && document.currentScript.src) || null;
    } catch {
      return null;
    }
  })();

  const _ctp = ["#f5c2e7","#cba6f7","#f38ba8","#fab387","#f9e2af","#a6e3a1","#94e2d5","#89dceb","#b4befe"];
  const _bg = (s) => {
    if (s === "cap") return "#89b4fa";
    let h = 0;
    for (let i = 0; i < s.length; i++) h = s.charCodeAt(i) + ((h << 5) - h);
    return _ctp[Math.abs(h) % _ctp.length];
  };
  const _style = (t, i, n) => {
    const l = i === 0 ? "9999px" : "0";
    const r = i === n - 1 ? "9999px" : "0";
    return `color:#1e1e2e;background:${_bg(t)};margin-left:${i ? "-6px" : 0};padding:0 6px;border-radius:${l} ${r} ${r} ${l};font-weight:600`;
  };
  const log = {};
  for (const lvl of ["debug", "info", "warn", "error"]) {
    log[lvl] = (tags, ...args) => {
      if (window.CAP_SILENT || (lvl === "debug" && !window.CAP_DEBUG)) return;
      const fmt = tags.map((t) => `%c${t}`).join(" ");
      const styles = tags.map((t, i) => _style(t, i, tags.length));
      console[lvl === "debug" ? "log" : lvl](fmt, ...styles, ...args);
    };
  }
  const T = (sub) => (sub ? ["cap", sub] : ["cap"]);
  const since = (t) => `${Math.round(performance.now() - t)}ms`;
  const _err = (code, message) => Object.assign(new Error(message), { code });

  const capFetch = (u, conf = {}) => {
    if (window?.CAP_CUSTOM_FETCH) {
      return window.CAP_CUSTOM_FETCH(u, conf);
    }

    return fetch(u, conf);
  };

  const raceAbort = (promise, signal) => {
    if (!signal) return promise;
    if (signal.aborted) return Promise.reject(_err("aborted", "aborted"));
    return Promise.race([
      promise,
      new Promise((_, reject) =>
        signal.addEventListener(
          "abort",
          () => reject(_err("aborted", "aborted")),
          { once: true },
        ),
      ),
    ]);
  };

  const I18N_KEYS = "%%i18nKeys%%".split(",");
  const I18N_ROWS = %%i18nData%%;

  function _resolveI18nMap(forced) {
    const prefs = forced
      ? [forced]
      : navigator.languages || [navigator.language || ""];
    for (let pref of prefs) {
      if (!pref) continue;
      pref = pref.toLowerCase();
      if (pref === "en" || pref.startsWith("en-")) return null;
      const code = I18N_ROWS[pref]
        ? pref
        : I18N_ROWS[pref.split("-")[0]]
          ? pref.split("-")[0]
          : null;
      if (!code) continue;
      const parts = I18N_ROWS[code].split("/");
      const map = {};
      I18N_KEYS.forEach((k, i) => {
        map[k] = parts[i];
      });
      return map;
    }
    return null;
  }

  function prng(seed, length) {
    function fnv1a(str) {
      let hash = 2166136261;
      for (let i = 0; i < str.length; i++) {
        hash ^= str.charCodeAt(i);
        hash +=
          (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
      }
      return hash >>> 0;
    }

    let state = fnv1a(seed);
    let result = "";

    function next() {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      return state >>> 0;
    }

    while (result.length < length) {
      const rnd = next();
      result += rnd.toString(16).padStart(8, "0");
    }

    return result.substring(0, length);
  }

  // Hard ceiling on the decompressed instrumentation script (zip-bomb guard).
  const MAX_INFLATE_BYTES = 8 * 1024 * 1024;
  // The server caps challengeCount; clamp locally too so a hostile endpoint
  // cannot make the page allocate an enormous challenge array.
  const MAX_CHALLENGES = 1000;

  let _pakoPromise = null;
  async function _inflateRaw(compressed) {
    if (typeof DecompressionStream !== "undefined") {
      try {
        const ds = new DecompressionStream("deflate-raw");
        const writer = ds.writable.getWriter();
        const reader = ds.readable.getReader();
        writer
          .write(compressed)
          .then(() => writer.close())
          .catch(() => {});
        const chunks = [];
        let len = 0;
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          len += value ? value.length : 0;
          // Bound the decompressed size: the instrumentation blob is a few KB,
          // anything near this cap is a zip bomb aimed at the host page.
          if (len > MAX_INFLATE_BYTES) throw new Error("inflate too large");
          chunks.push(value);
        }
        const out = new Uint8Array(len);
        let off = 0;
        for (const c of chunks) {
          out.set(c, off);
          off += c.length;
        }
        return out;
      } catch {}
    }
    if (!_pakoPromise) {
      _pakoPromise = new Promise((resolve, reject) => {
        const url =
          window.CAP_PAKO_URL ||
          `${ASSET_BASE}/npm/pako@2.1.0/dist/pako_inflate.min.js`;
        log.debug(T("instr"), "DecompressionStream unavailable, loading pako from", url);
        const script = document.createElement("script");
        script.src = url;
        const pakoNonce = window.CAP_SCRIPT_NONCE || window.CAP_CSS_NONCE;
        if (pakoNonce) script.setAttribute("nonce", pakoNonce);
        script.onload = () => {
          if (window.pako?.inflateRaw) resolve(window.pako);
          else {
            _pakoPromise = null;
            reject(new Error("pako loaded but inflateRaw is missing"));
          }
        };
        script.onerror = () => {
          _pakoPromise = null;
          reject(new Error(`failed to load pako fallback from ${url}`));
        };
        document.head.appendChild(script);
      });
    }
    const pako = await _pakoPromise;
    const out = pako.inflateRaw(compressed);
    if (!out || out.length > MAX_INFLATE_BYTES) {
      throw new Error("inflate too large");
    }
    return out;
  }

  // Collect the consistency probes in the TOP-LEVEL document. The
  // instrumentation iframe is `sandbox="allow-scripts"` (no allow-same-origin),
  // which breaks canvas.toDataURL, WebGL, OfflineAudioContext and
  // navigator.storage in several real browsers — so those fields must be read
  // here, where full rendering/storage APIs are available, and merged into the
  // probe vector the iframe reports. Values are the true page context.
  async function collectTopLevelProbes() {
    const R = {};
    const probeCanvas = () => {
      try {
        const c = document.createElement("canvas");
        c.width = 120;
        c.height = 40;
        const x = c.getContext("2d");
        if (!x) return "";
        x.textBaseline = "top";
        x.font = "16px Arial";
        x.fillStyle = "#f60";
        x.fillRect(0, 0, 60, 20);
        x.fillStyle = "#069";
        x.fillText("capé 🐀", 2, 2);
        const d = c.toDataURL();
        let h = 0;
        for (let i = 0; i < d.length; i++) h = (h * 31 + d.charCodeAt(i)) >>> 0;
        return h.toString(16);
      } catch {
        return "";
      }
    };
    const probeWebgl = () => {
      try {
        const cv = document.createElement("canvas");
        cv.width = cv.height = 64;
        const g = cv.getContext("webgl") || cv.getContext("experimental-webgl");
        if (!g) return { ok: false };
        const ext = g.getExtension("WEBGL_debug_renderer_info");
        const v = ext ? g.getParameter(ext.UNMASKED_VENDOR_WEBGL) : g.getParameter(g.VENDOR);
        const r = ext ? g.getParameter(ext.UNMASKED_RENDERER_WEBGL) : g.getParameter(g.RENDERER);
        const g2 = !!cv.getContext("webgl2");
        let seed = (String(v) + "|" + String(r)).length;
        try {
          g.clearColor(0.2, 0.4, 0.6, 1);
          g.clear(g.COLOR_BUFFER_BIT);
          const px = new Uint8Array(4);
          g.readPixels(0, 0, 1, 1, g.RGBA, g.UNSIGNED_BYTE, px);
          for (let i = 0; i < px.length; i++) seed = (seed * 31 + px[i]) >>> 0;
        } catch {}
        return { ok: true, vendor: String(v), renderer: String(r), webgl2: g2, hash: seed.toString(16) };
      } catch {
        return { ok: false };
      }
    };
    const probeEmoji = () => {
      try {
        const sp = document.createElement("span");
        sp.style.cssText = "position:absolute;left:-9999px;top:-9999px;font-size:64px";
        sp.textContent = "😀❤";
        document.body.appendChild(sp);
        const w = sp.getBoundingClientRect().width;
        document.body.removeChild(sp);
        return { style: w >= 110 ? "apple-like" : "narrow", width: Math.round(w) };
      } catch {
        return null;
      }
    };
    const probeAudio = () =>
      new Promise((resolve) => {
        try {
          const AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
          if (!AC) return resolve(null);
          const ctx = new AC(1, 5000, 44100);
          const o = ctx.createOscillator();
          o.type = "triangle";
          o.frequency.value = 10000;
          const cp = ctx.createDynamicsCompressor();
          o.connect(cp);
          cp.connect(ctx.destination);
          o.start(0);
          ctx.oncomplete = (e) => {
            try {
              const d = e.renderedBuffer.getChannelData(0);
              let s = 0;
              for (let i = 4500; i < 5000; i++) s += Math.abs(d[i]);
              resolve(s);
            } catch {
              resolve(null);
            }
          };
          ctx.startRendering();
        } catch {
          resolve(null);
        }
      });
    const probeStorage = () =>
      (navigator.storage && navigator.storage.estimate
        ? navigator.storage.estimate().then((e) => (typeof e.quota === "number" ? e.quota : null)).catch(() => null)
        : Promise.resolve(null));

    // Automation-framework global detection. Runs in the MAIN document, not
    // the sandbox iframe — so it can see bindings that Playwright/Puppeteer
    // inject (the iframe can't). This is one of the most reliable signals
    // because these bindings are structural requirements of the tools.
    const probeAutomation = () => {
      const found = [];
      try {
        const names = Object.getOwnPropertyNames(window);
        const patterns = [
          "__playwright", "__pw", "__selenium", "__webdriver",
          "__driver", "_phantom", "__nightmare", "callPhantom",
          "domAutomation", "domAutomationController",
          "_WEBDRIVER_ELEM_CACHE", "cdc_", "$cdc_",
          "wdioElectron", "__crWeb",
        ];
        for (const n of names) {
          const lower = n.toLowerCase();
          for (const p of patterns) {
            if (lower.indexOf(p.toLowerCase()) !== -1) {
              found.push(n);
              break;
            }
          }
          // Puppeteer exposeFunction uses `puppeteer_` prefix (CDP_BINDING_PREFIX)
          if (n.indexOf("puppeteer_") === 0) found.push(n);
        }
        // Playwright BindingsController property
        if ("__playwright__binding__controller__" in window) found.push("__playwright__binding__controller__");
        // Puppeteer evaluation script reference
        if (typeof window.puppeteer_evaluation_script !== "undefined") found.push("puppeteer_evaluation_script");
        // navigator.webdriver from main context (--enable-automation flag)
        if (navigator.webdriver) found.push("webdriver");
        // Error().stack containing pptr: sourceURL (Puppeteer injects //# sourceURL=pptr:internal)
        try {
          var st = new Error().stack || "";
          if (st.indexOf("pptr:") !== -1) found.push("pptr_stack_trace");
        } catch {}
      } catch {}
      return found;
    };

    try {
      R.canvas = probeCanvas();
      R.webgl = probeWebgl();
      R.emoji = probeEmoji();
      R.platform = navigator.platform || "__undefined";
      R.hardwareConcurrency = navigator.hardwareConcurrency;
      R.audio = await probeAudio();
      R.storageQuota = await probeStorage();
      R.automationGlobals = probeAutomation();
    } catch {}
    return R;
  }

  async function runInstrumentationChallenge(instrBytes) {
    const b64ToUint8 = (b64) => {
      const bin = atob(b64);
      const arr = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      return arr;
    };

    const compressed = b64ToUint8(instrBytes);
    const scriptText = new TextDecoder().decode(await _inflateRaw(compressed));
    // Integrity: hash the exact script text we're about to execute in the
    // iframe. The server compares it against the hash of the script it minted.
    const scriptHash = await sha256HexBytes(
      new TextEncoder().encode(scriptText),
    );

    return new Promise((resolve) => {
      var timeout = setTimeout(() => {
        cleanup();
        resolve({ __timeout: true });
      }, 20000);

      var iframe = document.createElement("iframe");
      iframe.setAttribute("sandbox", "allow-scripts");
      iframe.setAttribute("aria-hidden", "true");
      iframe.style.cssText =
        "position:absolute;width:1px;height:1px;top:-9999px;left:-9999px;border:none;opacity:0;pointer-events:none;";

      var resolved = false;
      function cleanup() {
        if (resolved) return;
        resolved = true;
        clearTimeout(timeout);
        window.removeEventListener("message", handler);
        if (iframe.parentNode) iframe.parentNode.removeChild(iframe);
      }

      async function handler(ev) {
        if (!iframe.contentWindow || ev.source !== iframe.contentWindow) return;
        var d = ev.data;
        if (!d || typeof d !== "object") return;
        if (d.type === "cap:instr") {
          cleanup();
          if (d.blocked) {
            resolve({
              __blocked: true,
              blockReason: d.blockReason || "automated_browser",
            });
          } else if (d.result) {
            const base = {
              ...d.result,
              vp: [window.innerWidth, window.innerHeight],
              scriptHash,
            };
            // Merge top-level rendering/storage probes. Values measured here
            // are authoritative because the iframe sandbox breaks several of
            // these APIs; we only fill/overwrite when the iframe copy is
            // missing or the probe is one the iframe cannot read reliably.
            const top = await collectTopLevelProbes().catch(() => null);
            // Supplemental main-document probes go into a SEPARATE `top` field,
            // never into `p`: p is HMAC-signed inside the iframe, and mutating it
            // here would invalidate the signature. The server merges `top` as a
            // lower-priority, unsigned hint.
            if (top) {
              const topOut = {};
              if (base.p && typeof base.p === "object") {
                for (const k of ["canvas", "webgl", "emoji", "audio", "storageQuota"]) {
                  const iv = base.p[k];
                  const tv = top[k];
                  const missing = iv === null || iv === undefined || iv === 0 ||
                    (k === "emoji" && iv && iv.width === 0);
                  if (missing && tv !== undefined) topOut[k] = tv;
                }
              }
              if (top.automationGlobals) topOut.automationGlobals = top.automationGlobals;
              if (Object.keys(topOut).length) base.top = topOut;
            }
            resolve(base);
          } else {
            resolve({ __timeout: true });
          }
        } else if (d.type === "cap:error") {
          cleanup();
          resolve({ __timeout: true });
        }
      }

      window.addEventListener("message", handler);

      const scriptNonce = window.CAP_SCRIPT_NONCE || window.CAP_CSS_NONCE;
      const nonceAttr = scriptNonce
        ? ` nonce="${String(scriptNonce).replace(/"/g, "&quot;")}"`
        : "";
      iframe.srcdoc =
        '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body><script' +
        nonceAttr +
        ">" +
        scriptText +
        "\n</scr" +
        "ipt></body></html>";

      document.body.appendChild(iframe);
    });
  }

  let wasmModulePromise = null;

  // Integrity: sha256 of each WASM/module byte stream actually loaded. Reported
  // at redeem so the server can reject a swapped solver. Kept in a side map so
  // the module-returning API (and worker postMessage) stays unchanged.
  const wasmHashes = { capWasm: null, hashwxWasm: null };

  const sha256HexBytes = async (buf) => {
    try {
      const subtle = (globalThis.crypto && globalThis.crypto.subtle) || null;
      if (!subtle) return null;
      const digest = await subtle.digest("SHA-256", buf);
      const arr = new Uint8Array(digest);
      let s = "";
      for (let i = 0; i < arr.length; i++) s += arr[i].toString(16).padStart(2, "0");
      return s;
    } catch {
      return null;
    }
  };

  // Honeypot decoys: invisible to humans, but enumerable by scrapers and
  // auto-fillers that touch every input/link on the page. Names mimic real
  // optional form fields (company/fax) so bots don't skip them. Hidden with
  // aria-hidden + tabindex=-1 + off-screen + opacity, NOT type=hidden.
  const _honeypot = { filled: false, touched: false, added: false, fields: [] };
  const _installHoneypot = () => {
    if (_honeypot.added || typeof document === "undefined" || !document.body) return;
    _honeypot.added = true;
    const mk = (tag) => {
      const el = document.createElement(tag);
      el.setAttribute("aria-hidden", "true");
      el.setAttribute("tabindex", "-1");
      el.setAttribute("autocomplete", "off");
      el.style.cssText =
        "position:absolute;left:-9999px;top:-9999px;width:0;height:0;opacity:0;pointer-events:none;border:0;padding:0;margin:0;";
      return el;
    };
    try {
      const f1 = mk("input");
      f1.type = "text";
      f1.name = "company";
      const f2 = mk("input");
      f2.type = "email";
      f2.name = "fax";
      const link = mk("a");
      link.href = "#";
      link.textContent = "Verify account";
      document.body.appendChild(f1);
      document.body.appendChild(f2);
      document.body.appendChild(link);
      _honeypot.fields = [f1, f2, link];
      const onTouch = (e) => {
        if (e && _honeypot.fields.indexOf(e.target) !== -1) _honeypot.touched = true;
      };
      document.addEventListener("focusin", onTouch, true);
      document.addEventListener("click", onTouch, true);
    } catch {}
  };
  const _recheckHoneypot = () => {
    for (let i = 0; i < _honeypot.fields.length; i++) {
      const f = _honeypot.fields[i];
      if (f && f.tagName === "INPUT" && f.value && String(f.value).length > 0) {
        _honeypot.filled = true;
      }
    }
  };
  const _honeypotTriggered = () => {
    try { _installHoneypot(); _recheckHoneypot(); } catch {}
    return _honeypot.filled || _honeypot.touched;
  };
  const _honeypotSnapshot = () => ({ filled: _honeypot.filled, touched: _honeypot.touched });
  try { _installHoneypot(); } catch {}

  // Best-effort: hash the served widget bytes for asset-integrity reporting.
  let _widgetHashPromise = null;
  const getWidgetHash = () => {
    if (_widgetHashPromise) return _widgetHashPromise;
    if (!_selfSrc) return Promise.resolve(null);
    _widgetHashPromise = fetch(_selfSrc, { cache: "no-store" })
      .then((r) => (r.ok ? r.arrayBuffer() : null))
      .then((buf) => (buf ? sha256HexBytes(buf) : null))
      .catch(() => null);
    return _widgetHashPromise;
  };

  // Build the integrity object sent at redeem: loaded asset hashes plus a
  // session-binding proof over nonce + asset set + submitted solutions so a
  // captured redeem cannot be replayed against another challenge/asset set.
  const buildIntegrity = async (nonce, solutions, scriptHash, selfOk) => {
    const out = {};
    if (wasmHashes.capWasm) out.capWasm = wasmHashes.capWasm;
    if (wasmHashes.hashwxWasm) out.hashwxWasm = wasmHashes.hashwxWasm;
    const widgetHash = await getWidgetHash();
    if (widgetHash) out.widget = widgetHash;
    if (scriptHash) out.scriptHash = scriptHash;
    out.widgetSelf = selfOk === true;
    if (_honeypotTriggered()) out.honeypot = _honeypotSnapshot();
    try {
      if (nonce) {
        // Request signature (RFC 9421 spirit): canonical string binds the
        // challenge nonce, a timestamp (replay window), the digest of the
        // submitted solutions, and the reported asset hashes. The server
        // recomputes this exact string and compares with a timing-safe check.
        const solDigest = await sha256HexBytes(
          new TextEncoder().encode(JSON.stringify(solutions ?? null)),
        );
        const hashes = Object.keys(out)
          .filter((k) => k === "capWasm" || k === "hashwxWasm" || k === "widget" || k === "scriptHash")
          .sort()
          .map((k) => `${k}=${out[k]}`)
          .join(",");
        const ts = Date.now();
        const canon = [String(nonce), String(ts), solDigest || "", hashes].join("|");
        const proof = await sha256HexBytes(new TextEncoder().encode(canon));
        if (proof) {
          out.ts = ts;
          out.proof = proof;
        }
      }
    } catch {}
    return out;
  };

  const getWasmModule = () => {
    if (wasmModulePromise) return wasmModulePromise;

    const wasmUrl =
      window.CAP_CUSTOM_WASM_URL ||
      `${ASSET_BASE}/npm/@cap.js/wasm@${WASM_VERSION}/browser/cap_wasm_bg.wasm`;

    const t0 = performance.now();
    log.debug(T("wasm"), "fetching", wasmUrl);
    wasmModulePromise = fetch(wasmUrl)
      .then((r) => {
        if (!r.ok) throw new Error(`Failed to fetch wasm: ${r.status}`);
        return r.arrayBuffer();
      })
      .then(async (buf) => {
        wasmHashes.capWasm = await sha256HexBytes(buf);
        return WebAssembly.compile(buf);
      })
      .then((mod) => {
        log.debug(T("wasm"), `ready in ${since(t0)}`);
        return mod;
      })
      .catch((e) => {
        wasmModulePromise = null;
        log.warn(T("wasm"), `load failed (${since(t0)}):`, e.message || e);
        throw e;
      });

    return wasmModulePromise;
  };

  const firstFulfilled = (tasks) =>
    new Promise((resolve, reject) => {
      let pending = tasks.length;
      let firstError = null;
      for (const task of tasks) {
        task.then(resolve, (err) => {
          if (!firstError) firstError = err;
          pending--;
          if (pending === 0) reject(firstError);
        });
      }
    });

  const MAX_HASHWX_DIFFICULTY = 1_000_000_000;
  const MAX_HASHWX_NONCES_PER_HASH = 1_048_576;

  let hashwxModulePromise = null;

  const getHashwxModule = () => {
    if (hashwxModulePromise) return hashwxModulePromise;

    const wasmUrl =
      window.CAP_CUSTOM_HASHWX_URL ||
      `${ASSET_BASE}/npm/@cap.js/wasm@${WASM_VERSION}/browser/hashwx.wasm`;

    const t0 = performance.now();
    log.debug(T("wasm"), "fetching", wasmUrl);
    hashwxModulePromise = fetch(wasmUrl)
      .then((r) => {
        if (!r.ok) throw new Error(`Failed to fetch hashwx wasm: ${r.status}`);
        return r.arrayBuffer();
      })
      .then(async (buf) => {
        wasmHashes.hashwxWasm = await sha256HexBytes(buf);
        return WebAssembly.compile(buf);
      })
      .then((mod) => {
        log.debug(T("wasm"), `hashwx ready in ${since(t0)}`);
        return mod;
      })
      .catch((e) => {
        hashwxModulePromise = null;
        log.warn(T("wasm"), `hashwx load failed (${since(t0)}):`, e.message || e);
        throw e;
      });

    return hashwxModulePromise;
  };

  if (
    typeof WebAssembly === "object" &&
    typeof WebAssembly.compile === "function"
  ) {
    getWasmModule().catch(() => {});
  }

  const prefersReducedMotion = () =>
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;

  const SPECULATIVE_DELAY_MS = 2500;
  const SPECULATIVE_WORKERS = 1;
  const SPECULATIVE_YIELD_MS = 120;

  let _sharedWorkerUrl = null;

  function _getSharedWorkerUrl() {
    if (_sharedWorkerUrl) return _sharedWorkerUrl;

    _sharedWorkerUrl = URL.createObjectURL(
      new Blob([%%workerScript%%], { type: "application/javascript" }),
    );
    return _sharedWorkerUrl;
  }

  const WORKER_STOP_GRACE_MS = 250;
  const HASHWX_SETTLE_MS = 1000;

  class WorkerPool {
    constructor(size) {
      this._size = size;
      this._workers = [];
      this._idle = [];
      this._queue = [];
      this._wasmModule = null;
      this._spawnFailures = 0;
    }

    setWasm(wasmModule) {
      this._wasmModule = wasmModule;
    }

    _spawn() {
      const url = _getSharedWorkerUrl();
      const w = new Worker(url);
      w._busy = false;
      this._workers.push(w);
      this._idle.push(w);
      return w;
    }

    _replaceWorker(deadWorker) {
      const idx = this._workers.indexOf(deadWorker);
      if (idx !== -1) this._workers.splice(idx, 1);
      const idleIdx = this._idle.indexOf(deadWorker);
      if (idleIdx !== -1) this._idle.splice(idleIdx, 1);

      try {
        deadWorker.terminate();
      } catch {}

      this._spawnFailures++;
      log.warn(T("pool"), `worker died, replacing (attempt ${this._spawnFailures}/3)`);
      if (this._spawnFailures > 3) {
        log.error(T("pool"), "worker spawn failed repeatedly, giving up");
        return null;
      }

      return this._spawn();
    }

    _ensureSize(n) {
      while (this._workers.length < n) this._spawn();
    }

    run(salt, target) {
      return new Promise((resolve, reject) => {
        this._queue.push({ salt, target, resolve, reject });
        this._dispatch();
      });
    }

    runMsg(msg, onProgress) {
      return new Promise((resolve, reject) => {
        this._queue.push({ msg, onProgress, resolve, reject });
        this._dispatch();
      });
    }

    _dispatch() {
      while (this._idle.length > 0 && this._queue.length > 0) {
        const worker = this._idle.shift();
        const task = this._queue.shift();
        const { resolve, reject } = task;
        const isMsg = task.msg !== undefined;

        let settled = false;

        const onMessage = ({ data }) => {
          if (settled) return;

          if (data && typeof data.progress === "number" && !data.found) {
            if (task.onProgress) {
              try { task.onProgress(data.progress); } catch {}
            }
            return;
          }
          settled = true;
          worker.removeEventListener("message", onMessage);
          worker.removeEventListener("error", onError);
          this._spawnFailures = 0;
          this._idle.push(worker);
          if (!data.found) {
            reject(new Error(data.error || "worker failed"));
          } else {
            resolve(isMsg ? data : data.nonce);
          }
          this._dispatch();
        };

        const onError = (err) => {
          if (settled) return;
          settled = true;
          worker.removeEventListener("message", onMessage);
          worker.removeEventListener("error", onError);
          const replacement = this._replaceWorker(worker);
          reject(err);
          if (replacement) {
            this._dispatch();
          }
        };

        worker.addEventListener("message", onMessage);
        worker.addEventListener("error", onError);

        if (isMsg) {
          worker.postMessage(task.msg);
        } else if (this._wasmModule) {
          worker.postMessage(
            { salt: task.salt, target: task.target, wasmModule: this._wasmModule },
            [],
          );
        } else {
          worker.postMessage({ salt: task.salt, target: task.target });
        }
      }
    }

    stopAll() {
      for (const w of this._workers) {
        try {
          w.postMessage({ kind: "stop" });
        } catch {}
      }
    }

    terminate() {
      const workers = this._workers;
      this._workers = [];
      this._idle = [];
      this._queue = [];
      for (const w of workers) {
        try {
          w.postMessage({ kind: "stop" });
        } catch {}
      }
      setTimeout(() => {
        for (const w of workers) {
          try {
            w.terminate();
          } catch {}
        }
      }, WORKER_STOP_GRACE_MS);
    }
  }


  // Theme is declared by the page, never guessed from pixels or the OS:
  // an explicit data-cap-theme wins, then page attributes/classes, then a
  // single CSS color-scheme. With no
  // declaration the widget uses its dark palette.
  function _pageTheme() {
    const root = document.documentElement;
    const body = document.body;
    const attrs = [
      "data-cap-theme", "data-theme", "data-bs-theme",
      "data-color-mode", "data-mode", "data-color-scheme",
    ];
    for (const node of [root, body]) {
      if (!node) continue;
      for (const name of attrs) {
        const v = String(node.getAttribute(name) || "").toLowerCase();
        if (v === "dark" || v === "light") return v;
      }
    }
    const cls = `${root.className || ""} ${(body && body.className) || ""}`.toLowerCase().split(/\s+/);
    if (cls.includes("dark") || cls.includes("theme-dark")) return "dark";
    if (cls.includes("light") || cls.includes("theme-light")) return "light";
    for (const node of [root, body]) {
      if (!node) continue;
      try {
        const cs = String(getComputedStyle(node).colorScheme || "").trim().toLowerCase();
        const tokens = cs.split(/\s+/);
        const schemes = tokens.filter(t => t === "light" || t === "dark");
        if (schemes.length === 1 && tokens.length <= 2 && tokens.every(t => t === schemes[0] || t === "only")) return schemes[0];
      } catch (e) {}
    }
    return "dark";
  }

  class CapWidget extends HTMLElement {
    static formAssociated = true;
    #themeObserver = null;
    // Call after CSSOM/stylesheet changes that do not mutate html/body attributes.
    refreshTheme() { if (this.isConnected) this.#syncTheme(); }
    #syncTheme = () => {
      const explicit = (this.getAttribute("data-cap-theme") || "").toLowerCase();
      const theme = explicit === "light" || explicit === "dark" ? explicit : _pageTheme();
      // Derived state must never overwrite the integrator's explicit setting.
      if (this.getAttribute("data-cap-resolved-theme") !== theme) {
        this.setAttribute("data-cap-resolved-theme", theme);
      }
    };
    #resetTimer = null;
    #workersCount = navigator.hardwareConcurrency || 8;
    token = null;
    #shadow;
    #div;
    #trigger;
    #credits;
    #troubleshootLink;
    #host;
    #tokenInput;
    #solving = false;
    #eventHandlers;
    #internals;

    #speculative = null;
    #speculativeTimer = null;
    #speculativePool = null;
    #interactionHandler = null;
    #i18n = null;
    #abort = null;
    #business = null;
    #generation = 0;

    // Credentials stay in private memory. reset/disconnect consume this binding;
    // callers must explicitly provide a fresh credential before another round.
    setBusinessToken(credential) {
      const { businessToken, expires } = credential || {};
      if (typeof businessToken !== "string" || !businessToken.length || businessToken.length > 8192 ||
          !Number.isSafeInteger(expires) || expires <= Date.now()) {
        throw _err("invalid_business_token", "Invalid or expired business credential");
      }
      this.reset();
      this.#business = Object.freeze({ businessToken, expires });
    }

    #requireBusiness() {
      if (!this.#business || this.#business.expires <= Date.now()) {
        throw _err("missing_business_token", "A valid business credential is required");
      }
      return this.#business;
    }

    async #roundFetch(round, url, init = {}) {
      if (round.generation !== this.#generation || round.signal.aborted) {
        throw _err("aborted", "aborted");
      }
      if (round.credential.expires <= Date.now()) {
        throw _err("expired_business_token", "Business credential expired");
      }
      try {
        return await capFetch(url, {
          ...init,
          signal: round.signal,
          headers: { ...init.headers, "Content-Type": "application/json" },
          body: JSON.stringify({ ...JSON.parse(init.body || "{}"), businessToken: round.credential.businessToken }),
        });
      } catch (_) {
        // Fetch/provider errors may echo request bodies; never log credentials.
        throw _err("network_error", "CAP request failed");
      }
    }

    #round() {
      const credential = this.#requireBusiness();
      return { generation: this.#generation, signal: this.#abort.signal, credential };
    }

    get #hasHaptics() {
      return (
        _browserHasHaptics &&
        !window.CAP_DISABLE_HAPTICS &&
        !this.hasAttribute("data-cap-disable-haptics")
      );
    }

    #makeSpeculativeState() {
      return {
        state: "idle",
        challengeResp: null,
        challenges: null,
        results: [],
        completedCount: 0,
        solvePromise: null,
        promoteFn: null,
        _listeners: [],
        pendingPromotion: null,
        token: null,
        tokenExpires: null,

        notify() {
          for (const fn of this._listeners) fn();
          this._listeners = [];
        },

        onSettled(fn) {
          if (this.state === "done" || this.state === "error") {
            fn();
          } else {
            this._listeners.push(fn);
          }
        },
      };
    }

    #resetSpeculativeState() {
      this.#speculative = this.#makeSpeculativeState();
      this.#attachInteractionListeners();
    }

    #detachInteractionListeners() {
      if (this.#interactionHandler) {
        window.removeEventListener("mousemove", this.#interactionHandler);
        window.removeEventListener("touchstart", this.#interactionHandler);
        window.removeEventListener("keydown", this.#interactionHandler);
        this.#interactionHandler = null;
      }
    }

    #attachInteractionListeners() {
      this.#detachInteractionListeners();
      const handler = () => {
        this.#detachInteractionListeners();
        this.#onFirstInteraction();
      };
      this.#interactionHandler = handler;
      window.addEventListener("mousemove", handler, { passive: true });
      window.addEventListener("touchstart", handler, { passive: true });
      window.addEventListener("keydown", handler, { passive: true });
    }

    #isVisible() {
      if (typeof this.checkVisibility === "function") {
        return this.checkVisibility({
          checkOpacity: true,
          checkVisibilityCSS: true,
        });
      }
      return !!(this.offsetParent || this.getClientRects().length > 0);
    }

    #logInvisible() {
      if (!this.#isVisible()) log.info(T("challenges"), "solved invisible challenge");
    }

    #onFirstInteraction() {
      if (this.#speculative.state !== "idle") return;
      if (!this.#isVisible()) return;
      this.#speculative.state = "waiting";
      this.#speculativeTimer = setTimeout(() => {
        this.#beginSpeculativeSolve();
      }, SPECULATIVE_DELAY_MS);
    }

    async #beginSpeculativeSolve() {
      if (this.#speculative.state !== "waiting") return;
      let round;
      try { round = this.#round(); } catch (err) {
        this.#speculative.state = "error";
        this.#speculative.notify();
        this.error(err.message, err.code);
        return;
      }
      const speculative = this.#speculative;
      this.#speculative.state = "fetching";
      this.#speculative._t0 = performance.now();

      let apiEndpoint = this.getAttribute("data-cap-api-endpoint");
      if (!apiEndpoint && window?.CAP_CUSTOM_FETCH) {
        apiEndpoint = "/";
      }
      if (!apiEndpoint) {
        this.#speculative.state = "idle";
        return;
      }
      if (!apiEndpoint.endsWith("/")) apiEndpoint += "/";

      try {
        const raw = await this.#roundFetch(round, `${apiEndpoint}challenge`, {
          method: "POST",
          signal: this.#abort?.signal,
        });
        let resp;
        try {
          resp = await raw.json();
        } catch {
          throw new Error("Failed to parse speculative challenge response");
        }
        if (round.generation !== this.#generation) return;
        if (resp.error) throw new Error(resp.error);
        if (round.generation !== this.#generation || !this.#speculative) return;

        resp._apiEndpoint = apiEndpoint;
        this.#speculative.challengeResp = resp;

        if (resp.format === 2 && Array.isArray(resp.challenges)) {
          if (resp.challenges.some((ch) => ch?.protocol === "hashwx")) {
            getHashwxModule().catch(() => {});
          }
          this.#speculative.state = "idle";
          this.#speculative.notify();
          return;
        }

        const { challenge, token } = resp;
        let challenges = challenge;
        if (!Array.isArray(challenges)) {
          let i = 0;
          const count = Math.min(
            Math.max(1, Number(challenge?.c) || 0),
            MAX_CHALLENGES,
          );
          challenges = Array.from({ length: count }, () => {
            i++;
            return [
              prng(`${token}${i}`, challenge.s),
              prng(`${token}${i}d`, challenge.d),
            ];
          });
        }
        this.#speculative.challenges = challenges;
        this.#speculative.state = "solving";

        this.#speculative.solvePromise = this.#speculativeSolveAll(
          challenges, round, speculative,
        ).catch(() => {
          if (round.generation !== this.#generation) return;
          if (round.generation !== this.#generation || !this.#speculative) return;
          this.#speculative.state = "error";
          this.#speculative.notify();
        });
      } catch {
        if (round.generation !== this.#generation || !this.#speculative) return;
        this.#speculative.state = "error";
        this.#speculative.notify();
      }
    }

    async #speculativeSolveAll(challenges, round, speculative) {
      _getSharedWorkerUrl();

      let wasmModule = null;
      try {
        wasmModule = await getWasmModule();
      } catch {}

      if (round.generation !== this.#generation || !this.#speculative) return [];
      if (!this.#speculativePool) {
        this.#speculativePool = new WorkerPool(1);
        this.#speculativePool._spawn();
      }
      this.#speculativePool.setWasm(wasmModule);

      const total = challenges.length;
      const results = new Array(total);

      let concurrency = SPECULATIVE_WORKERS;
      let promoted = false;

      this.#speculative.promoteFn = (fullCount) => {
        if (promoted || !this.#speculativePool) return;
        promoted = true;
        concurrency = fullCount;
        this.#speculativePool._size = fullCount;
        this.#speculativePool._ensureSize(fullCount);
      };

      if (this.#speculative.pendingPromotion !== null) {
        this.#speculative.promoteFn(this.#speculative.pendingPromotion);
        this.#speculative.pendingPromotion = null;
      }

      let nextIndex = 0;

      while (nextIndex < total) {
        if (round.generation !== this.#generation || !this.#speculativePool) return results;
        const batchSize = concurrency;
        const batch = [];
        const batchIndices = [];

        for (let i = 0; i < batchSize && nextIndex < total; i++) {
          batchIndices.push(nextIndex);
          batch.push(challenges[nextIndex]);
          nextIndex++;
        }

        this.#speculativePool._ensureSize(Math.max(concurrency, batchSize));

        const batchResults = await Promise.all(
          batch.map((challenge) =>
            this.#speculativePool
              .run(challenge[0], challenge[1])
              .then((nonce) => {
                if (round.generation === this.#generation) speculative.completedCount++;
                return nonce;
              }),
          ),
        );

        for (let i = 0; i < batchIndices.length; i++) {
          results[batchIndices[i]] = batchResults[i];
        }

        if (!promoted && nextIndex < total) {
          await new Promise((resolve) =>
            setTimeout(resolve, SPECULATIVE_YIELD_MS),
          );
        }
      }

      if (round.generation !== this.#generation || !this.#speculative) return results;
      this.#speculative.results = results;
      this.#speculative.state = "redeeming";
      this.#speculativeRedeem(results, round);
      return results;
    }

    async #speculativeRedeem(solutions, round) {
      try {
        if (round.generation !== this.#generation || !this.#speculative) return;
        const challengeResp = this.#speculative.challengeResp;
        const apiEndpoint = challengeResp._apiEndpoint;
        if (!apiEndpoint)
          throw _err("missing_endpoint", "speculative redeem: missing apiEndpoint");

        let instrOut = null;
        if (challengeResp.instrumentation) {
          instrOut = await runInstrumentationChallenge(
            challengeResp.instrumentation,
          );
          if (round.generation !== this.#generation || !this.#speculative) return;
          if (instrOut?.__timeout || instrOut?.__blocked) {
            this.#speculative.state = "done";
            this.#speculative.notify();
            return;
          }
        }

        const iScriptHash =
          (instrOut && instrOut.scriptHash) ||
          (Array.isArray(solutions) &&
            solutions.map((s) => s && s.instr && s.instr.scriptHash).find(Boolean)) ||
          null;
        const integrity = await buildIntegrity(
          challengeResp.nonce,
          solutions,
          iScriptHash,
          this.#selfOkNow(),
        );

        const redeemRaw = await this.#roundFetch(round, `${apiEndpoint}redeem`, {
          method: "POST",
          body: JSON.stringify({
            token: challengeResp.token,
            solutions,
            ...(Object.keys(integrity).length && { integrity }),
            ...(instrOut && { instr: instrOut }),
          }),
          headers: { "Content-Type": "application/json" },
          signal: this.#abort?.signal,
        });

        let resp;
        try {
          resp = await redeemRaw.json();
        } catch {
          throw new Error("Failed to parse speculative redeem response");
        }

        if (round.generation !== this.#generation || !this.#speculative) return;
        if (round.credential.expires <= Date.now()) throw _err("expired_business_token", "Business credential expired");
        if (!resp.success)
          throw new Error(resp.error || "Speculative redeem failed");

        this.#speculative.token = resp.token;
        this.#speculative.tokenExpires = new Date(resp.expires).getTime();
        this.#speculative.state = "done";
        this.#speculative._invisibleElapsed = this.#speculative._t0 ? since(this.#speculative._t0) : "?";
        this.#speculative.notify();
      } catch {
        if (round.generation !== this.#generation || !this.#speculative) return;
        this.#speculative.state = "done";
        this.#speculative.notify();
      }
    }

    get #fieldName() {
      return this.getAttribute("data-cap-hidden-field-name") || "cap-token";
    }

    #setToken(value) {
      const input =
        this.#tokenInput ||
        this.querySelector(`input[name='${CSS.escape(this.#fieldName)}']`);
      if (input) input.value = value;
    }

    getI18nText(key, defaultValue) {
      return (
        this.getAttribute(`data-cap-i18n-${key}`) ||
        this.#i18n?.[key] ||
        defaultValue
      );
    }

    #commitSpeculativeToken() {
      const generation = this.#generation;
      log.debug(T("solve"), `served from speculative cache (saved ${this.#speculative._invisibleElapsed || "?"})`);
      this.dispatchEvent("progress", { progress: 100 });
      if (generation !== this.#generation) return;

      this.#setToken(this.#speculative.token);

      this.token = this.#speculative.token;
      this.#business = null;
      this.dispatchEvent("solve", { token: this.token });
      if (generation !== this.#generation) return;

      const expiresIn = this.#speculative.tokenExpires - Date.now();
      if (this.#resetTimer) clearTimeout(this.#resetTimer);
      this.#resetTimer = setTimeout(() => this.reset(), expiresIn);

      this.#trigger.setAttribute(
        "aria-label",
        this.getI18nText(
          "verified-aria-label",
          "We have verified you're a human, you may now continue",
        ),
      );
      if (this.#hasHaptics) navigator.vibrate([10, 50, 20, 30, 40]);

      this.#logInvisible();
      this.#resetSpeculativeState();
      this.#detachInteractionListeners();
      this.#solving = false;
      return { success: true, token: this.token };
    }

    #resolveI18n() {
      this.#i18n = _resolveI18nMap(
        window.CAP_LANG || this.getAttribute("data-cap-lang"),
      );
    }

    static get observedAttributes() {
      return [
        "onsolve",
        "onprogress",
        "onreset",
        "onerror",
        "data-cap-worker-count",
        "data-cap-theme",
        "data-cap-i18n-initial-state",
        "required",
      ];
    }

    constructor() {
      super();
      if (this.#eventHandlers) {
        this.#eventHandlers.forEach((handler, eventName) => {
          this.removeEventListener(eventName.slice(2), handler);
        });
      }

      this.#eventHandlers = new Map();
      this.boundHandleProgress = this.handleProgress.bind(this);
      this.boundHandleSolve = this.handleSolve.bind(this);
      this.boundHandleError = this.handleError.bind(this);
      this.boundHandleReset = this.handleReset.bind(this);

      try {
        this.#internals = this.attachInternals();
      } catch {}
    }

    #updateValidity() {
      if (!this.#internals?.setValidity) return;
      if (this.hasAttribute("required") && !this.token) {
        this.#internals.setValidity(
          { valueMissing: true },
          this.getI18nText("required-label", "Please verify you're human"),
          this.#div || this,
        );
      } else {
        this.#internals.setValidity({});
      }
    }

    initialize() {
      _getSharedWorkerUrl();
      this.#abort = new AbortController();
      if (!this.#speculative) {
        this.#speculative = this.#makeSpeculativeState();
      }
      if (!this.#speculativePool) {
        this.#speculativePool = new WorkerPool(1);
        this.#speculativePool._spawn();
      }
    }

    attributeChangedCallback(name, _, value) {
      if (name === "data-cap-theme" && this.isConnected) this.#syncTheme();
      if (name.startsWith("on")) {
        const eventName = name.slice(2);
        const oldHandler = this.#eventHandlers.get(name);
        if (oldHandler) {
          this.removeEventListener(eventName, oldHandler);
        }

        if (value) {
          const handler = (event) => {
            const callback = this.getAttribute(name);
            if (typeof window[callback] === "function") {
              window[callback].call(this, event);
            }
          };
          this.#eventHandlers.set(name, handler);
          this.addEventListener(eventName, handler);
        }
      }

      if (name === "data-cap-worker-count") {
        this.setWorkersCount(parseInt(value, 10));
      }

      if (
        name === "data-cap-i18n-initial-state" &&
        this.#div &&
        this.#div?.querySelector(".label.active")
      ) {
        this.animateLabel(
          this.getI18nText("initial-state", "Verify you're human"),
        );
      }

      if (name === "required") {
        this.#updateValidity();
      }
    }

    async connectedCallback() {
      this.#host = this;
      this.#syncTheme();
      this.#themeObserver?.disconnect();
      this.#themeObserver = new MutationObserver(this.#syncTheme);
      for (const node of [document.documentElement, document.body]) {
        if (node) this.#themeObserver.observe(node, {
          attributes: true,
          attributeFilter: ["class", "style", "data-cap-theme", "data-theme",
            "data-bs-theme", "data-color-mode", "data-mode", "data-color-scheme"],
        });
      }

      if (!this.shadowRoot) {
        this.#shadow = this.attachShadow({ mode: "open" });
      } else {
        this.#shadow = this.shadowRoot;
      }

      try {
        if (this.#shadow && !_selfArmedShadows.has(this.#shadow)) {
          Object.defineProperty(this.#shadow, "__capSelf", {
            value: _selfToken,
            configurable: false,
            enumerable: false,
            writable: false,
          });
          _selfArmedShadows.add(this.#shadow);
        }
      } catch {}
      if (!this.#div) this.#div = document.createElement("div");
      this.#resolveI18n();
      this.createUI();
      this.addEventListeners();
      this.initialize();
      this.#trigger.removeAttribute("disabled");

      const workers = this.getAttribute("data-cap-worker-count");
      const parsedWorkers = workers ? parseInt(workers, 10) : null;
      this.setWorkersCount(parsedWorkers || navigator.hardwareConcurrency || 8);
      // Build the hidden field via the DOM: the name comes from an attribute,
      // so string interpolation into innerHTML is an injection sink.
      this.#tokenInput = document.createElement("input");
      this.#tokenInput.type = "hidden";
      this.#tokenInput.name = this.#fieldName;
      this.#host.replaceChildren(this.#tokenInput);

      log.debug(T(), `widget ready (workers=${this.#workersCount}, haptics=${this.#hasHaptics})`);
      this.#attachInteractionListeners();
      this.#updateValidity();

      this.addEventListener("invalid", this.#handleInvalid);
    }

    #handleInvalid = () => {
      if (!this.#div) return;
      try {
        this.scrollIntoView({ behavior: "smooth", block: "center" });
      } catch {
        this.scrollIntoView();
      }
      this.#div.classList.remove("invalid");
      void this.#div.offsetWidth;
      this.#div.classList.add("invalid");
      setTimeout(() => this.#div?.classList.remove("invalid"), 1500);
    };

    #selfOkNow() {
      try {
        return !!(
          this.#shadow &&
          _selfArmedShadows.has(this.#shadow) &&
          this.#shadow.__capSelf === _selfToken &&
          this.shadowRoot === this.#shadow &&
          this.isConnected
        );
      } catch {
        return false;
      }
    }

    async solve() {
      // HTTPS-only: the probe result is HMAC-ed via WebCrypto, which requires a
      // secure context. Refuse to run on plain HTTP (loopback allowed for dev).
      if (
        typeof window !== "undefined" &&
        window.isSecureContext === false &&
        !/^(localhost|127\.0\.0\.1|\[::1\])$/.test(String(location.hostname || ""))
      ) {
        this.updateUI("", this.getI18nText("error-label", "Verification failed"), false);
        throw new Error("Cap requires a secure context (HTTPS)");
      }
      if (this.#solving) {
        return;
      }

      let round;
      try { round = this.#round(); } catch (err) {
        this.error(err.message, err.code);
        throw err;
      }
      this.#enforceCredits();
      const _solveT0 = performance.now();
      const signal = this.#abort?.signal;
      log.debug(T("solve"), "starting");

      try {
        this.#solving = true;
        this.updateUI(
          "verifying",
          this.getI18nText("verifying-label", "Verifying..."),
          true,
        );
        this.#trigger.setAttribute(
          "aria-label",
          this.getI18nText(
            "verifying-aria-label",
            "Verifying you're a human, please wait",
          ),
        );
        this.dispatchEvent("progress", { progress: 0 });
        if (signal.aborted) return;

        try {
          let apiEndpoint = this.getAttribute("data-cap-api-endpoint");
          if (!apiEndpoint && window?.CAP_CUSTOM_FETCH) {
            apiEndpoint = "/";
          } else if (!apiEndpoint) {
            throw _err(
              "missing_endpoint",
              "Missing API endpoint. Either custom fetch or an API endpoint must be provided.",
            );
          }
          if (!apiEndpoint.endsWith("/")) apiEndpoint += "/";

          let solutions;
          let challengeResp;

          if (
            this.#speculative.state === "done" &&
            this.#speculative.token &&
            this.#speculative.tokenExpires &&
            Date.now() < this.#speculative.tokenExpires
          ) {
            return this.#commitSpeculativeToken();
          }

          if (this.#speculative.state === "done") {
            solutions = this.#speculative.results;
            challengeResp = this.#speculative.challengeResp;
            this.dispatchEvent("progress", { progress: 100 });
          } else if (
            this.#speculative.state === "solving" ||
            this.#speculative.state === "redeeming" ||
            this.#speculative.state === "fetching" ||
            this.#speculative.state === "waiting"
          ) {
            if (this.#speculative.state === "waiting") {
              if (this.#speculativeTimer) {
                clearTimeout(this.#speculativeTimer);
                this.#speculativeTimer = null;
              }
              this.#speculative.state = "waiting";
              this.#beginSpeculativeSolve();
            }

            this.#speculative.pendingPromotion = this.#workersCount;
            if (this.#speculative.promoteFn) {
              this.#speculative.promoteFn(this.#workersCount);
            }

            const progressInterval = setInterval(() => {
              if (signal?.aborted || !this.#speculative) {
                clearInterval(progressInterval);
                return;
              }
              const st = this.#speculative.state;
              if (st === "done" || st === "error") {
                clearInterval(progressInterval);
                return;
              }
              const total = this.#speculative.challenges
                ? this.#speculative.challenges.length
                : 1;
              const done = this.#speculative.completedCount;
              const visual =
                st === "redeeming"
                  ? 99
                  : st === "fetching" || st === "waiting"
                    ? 0
                    : Math.min(98, Math.round((done / total) * 100));
              this.dispatchEvent("progress", { progress: visual });
            }, 150);

            await new Promise((resolve) =>
              this.#speculative.onSettled(resolve),
            );
            clearInterval(progressInterval);
            if (signal?.aborted || !this.#speculative) return;

            if (
              this.#speculative.state === "idle" &&
              this.#speculative.challengeResp?.format === 2 &&
              Array.isArray(this.#speculative.challengeResp.challenges)
            ) {
              challengeResp = this.#speculative.challengeResp;
              this.#speculative.challengeResp = null;
              solutions = await this.solveChallengesV2(
                challengeResp.challenges,
                signal,
              );
            } else {
              if (this.#speculative.state !== "done") {
                throw _err("solve_failed", "Unable to solve challenge, self-hosted instance likely down. This is not an issue with Cap.");
              }

            if (
              this.#speculative.token &&
              this.#speculative.tokenExpires &&
              Date.now() < this.#speculative.tokenExpires
            ) {
              return this.#commitSpeculativeToken();
            }

            solutions = this.#speculative.results;
            challengeResp = this.#speculative.challengeResp;
            this.dispatchEvent("progress", { progress: 100 });
            }
          } else {
            const cached = this.#speculative.challengeResp;
            if (cached?.format === 2 && Array.isArray(cached.challenges)) {
              challengeResp = cached;
              this.#speculative.challengeResp = null;
            } else {
              const challengeRaw = await this.#roundFetch(round, `${apiEndpoint}challenge`, {
                method: "POST",
                signal,
              });
              try {
                challengeResp = await challengeRaw.json();
                if (signal.aborted) return;
              } catch {
                throw _err("challenge_parse_error", "Failed to parse challenge response from server");
              }
              if (challengeResp.error) throw _err("network_error", "Challenge request failed");
            }

            if (
              challengeResp.format === 2 &&
              Array.isArray(challengeResp.challenges)
            ) {
              solutions = await this.solveChallengesV2(
                challengeResp.challenges,
                signal,
              );
            } else {
              const { challenge, token } = challengeResp;
              let challenges = challenge;
              if (!Array.isArray(challenges)) {
                let i = 0;
                const count = Math.min(
                  Math.max(1, Number(challenge?.c) || 0),
                  MAX_CHALLENGES,
                );
                challenges = Array.from({ length: count }, () => {
                  i++;
                  return [
                    prng(`${token}${i}`, challenge.s),
                    prng(`${token}${i}d`, challenge.d),
                  ];
                });
              }
              solutions = await this.solveChallenges(challenges, signal);
            }
          }

          if (signal.aborted) return;
          const instrPromise = challengeResp.instrumentation
            ? runInstrumentationChallenge(challengeResp.instrumentation)
            : Promise.resolve(null);

          const instrOut = await instrPromise;
          if (signal?.aborted || !this.#speculative) return;

          if (instrOut?.__timeout || instrOut?.__blocked) {
            this.#roundFetch(round, `${apiEndpoint}redeem`, {
              method: "POST",
              body: JSON.stringify({
                token: challengeResp.token,
                solutions,
                ...(instrOut.__blocked && { instr_blocked: true }),
                ...(instrOut.__timeout && { instr_timeout: true }),
              }),
              headers: { "Content-Type": "application/json" },
              signal,
            }).catch(() => {});

            this.updateUIBlocked(
              this.getI18nText("error-label", "Error"),
              instrOut?.__blocked,
            );
            this.#trigger.setAttribute(
              "aria-label",
              this.getI18nText(
                "error-aria-label",
                "An error occurred, please try again",
              ),
            );
            const instrCode = instrOut?.__blocked ? "instr_blocked" : "instr_timeout";
            const instrMsg = instrOut?.__blocked
              ? `Instrumentation blocked (${instrOut.blockReason || "automated_browser"})`
              : "Instrumentation timed out";
            this.removeEventListener("error", this.boundHandleError);
            const errEvent = new CustomEvent("error", {
              bubbles: true,
              composed: true,
              detail: { isCap: true, code: instrCode, message: instrMsg },
            });
            super.dispatchEvent(errEvent);
            this.addEventListener("error", this.boundHandleError);
            if (signal.aborted) return;
            this.executeAttributeCode("onerror", errEvent);
            if (signal.aborted) return;
            log.error(T("instr"), `[${instrCode}] ${instrMsg}`);
            this.#solving = false;
            return;
          }

          const { token } = challengeResp;

          const iScriptHash =
            (instrOut && instrOut.scriptHash) ||
            (Array.isArray(solutions) &&
              solutions.map((s) => s && s.instr && s.instr.scriptHash).find(Boolean)) ||
            null;
          const integrity = await buildIntegrity(
            challengeResp.nonce,
            solutions,
            iScriptHash,
            this.#selfOkNow(),
          );

          const redeemResponse = await this.#roundFetch(round, `${apiEndpoint}redeem`, {
            method: "POST",
            body: JSON.stringify({
              token,
              solutions,
              ...(Object.keys(integrity).length && { integrity }),
              ...(instrOut && { instr: instrOut }),
            }),
            headers: { "Content-Type": "application/json" },
            signal,
          });

          let resp;
          try {
            resp = await redeemResponse.json();
          } catch {
            throw _err("redeem_failed", "Failed to parse server response");
          }

          if (signal?.aborted || !this.#speculative) return;

          this.dispatchEvent("progress", { progress: 100 });
          if (signal.aborted) return;
          if (round.credential.expires <= Date.now()) throw _err("expired_business_token", "Business credential expired");
          if (!resp.success) throw _err("invalid_solution", "Invalid solution");

          this.#setToken(resp.token);

          this.token = resp.token;
          this.#business = null;
          this.dispatchEvent("solve", { token: resp.token });
          if (signal.aborted) return;

          this.#resetSpeculativeState();
          this.#detachInteractionListeners();

          if (this.#resetTimer) clearTimeout(this.#resetTimer);
          const expiresIn = new Date(resp.expires).getTime() - Date.now();
          if (expiresIn > 0 && expiresIn < 24 * 60 * 60 * 1000) {
            this.#resetTimer = setTimeout(() => this.reset(), expiresIn);
          } else {
            this.error("Invalid expiration time", "invalid_expires");
          }

          this.#trigger.setAttribute(
            "aria-label",
            this.getI18nText(
              "verified-aria-label",
              "We have verified you're a human, you may now continue",
            ),
          );
          if (this.#hasHaptics) navigator.vibrate([10, 50, 20, 30, 40]);

          log.debug(T("solve"), `verified in ${since(_solveT0)}`);
          this.#logInvisible();
          return { success: true, token: this.token };
        } catch (err) {
          if (signal?.aborted || !this.#speculative) return;
          this.#trigger.setAttribute(
            "aria-label",
            this.getI18nText(
              "error-aria-label",
              "An error occurred, please try again",
            ),
          );
          this.error(err.message, err.code || "solve_failed");
          throw err;
        }
      } finally {
        if (round.generation === this.#generation) this.#solving = false;
      }
    }

    async solveChallengesV2(challenges, signal) {
      const total = challenges.length;
      let completed = 0;

      const solutions = new Array(challenges.length);
      for (let i = 0; i < challenges.length; i++) {
        const ch = challenges[i];
        if (
          !ch ||
          typeof ch !== "object" ||
          !(
            ch.protocol === "sha256-pow" ||
            ch.protocol === "rsw" ||
            ch.protocol === "hashwx" ||
            ch.protocol === "instrumentation"
          )
        ) {
          throw _err("challenge_unsupported", `unsupported format-2 protocol '${ch?.protocol}'`);
        }
      }

      let needsCapWasm = false;
      let hashwxCount = 0;
      for (const ch of challenges) {
        if (ch.protocol === "sha256-pow") needsCapWasm = true;
        else if (ch.protocol === "hashwx") {
          hashwxCount++;
          const { c, d, n } = ch.payload ?? {};
          if (
            typeof c !== "string" ||
            !/^[0-9a-f]{64}$/i.test(c) ||
            !Number.isInteger(d) ||
            d < 1 ||
            d > MAX_HASHWX_DIFFICULTY ||
            !Number.isInteger(n) ||
            n < 1 ||
            n > MAX_HASHWX_NONCES_PER_HASH
          ) {
            throw _err("challenge_unsupported", "malformed hashwx challenge payload");
          }
        }
      }
      const needsHashwx = hashwxCount > 0;

      const wasmSupported =
        typeof WebAssembly === "object" &&
        typeof WebAssembly.instantiate === "function";

      let wasmModule = null;
      if (wasmSupported && needsCapWasm) {
        try { wasmModule = await getWasmModule(); }
        catch (e) { log.warn(T("wasm"), "unavailable, falling back to JS solver:", e.message || e); }
      }

      let hashwxModule = null;
      if (needsHashwx) {
        if (!wasmSupported) {
          throw _err("challenge_unsupported", "hashwx requires WebAssembly");
        }
        hashwxModule = await getHashwxModule();
      }

      const poolSize = Math.max(1, Math.min(this.#workersCount, challenges.length));
      if (signal?.aborted) throw _err("aborted", "aborted");
      const pool = new WorkerPool(poolSize);
      pool.setWasm(wasmModule);
      pool._ensureSize(poolSize);

      const hashwxWorkers = Math.max(1, this.#workersCount);
      const hashwxQueued = hashwxCount > hashwxWorkers;
      const hashwxStripes = hashwxQueued ? 1 : hashwxWorkers;
      let hashwxPool = needsHashwx ? new WorkerPool(hashwxWorkers) : null;
      if (hashwxPool) hashwxPool._ensureSize(hashwxWorkers);

      const reclaimStripes = async (stripes) => {
        hashwxPool.stopAll();
        let timer;
        const settled = await Promise.race([
          Promise.allSettled(stripes).then(() => true),
          new Promise((resolve) => {
            timer = setTimeout(() => resolve(false), HASHWX_SETTLE_MS);
          }),
        ]);
        clearTimeout(timer);
        if (settled) return;
        log.warn(T("solve"), "hashwx workers did not stop in time, replacing the pool");
        hashwxPool.terminate();
        hashwxPool = new WorkerPool(hashwxWorkers);
        hashwxPool._ensureSize(hashwxWorkers);
      };

      const TASK_TIMEOUT_MS = 60_000;
      const withTimeout = (promise, label) => {
        let timer;
        return Promise.race([
          promise,
          new Promise((_, rej) => {
            timer = setTimeout(
              () => rej(new Error(`[cap] ${label} timed out after ${TASK_TIMEOUT_MS}ms`)),
              TASK_TIMEOUT_MS,
            );
          }),
        ]).finally(() => clearTimeout(timer));
      };

      const inFlight = new Array(challenges.length).fill(0);
      const emit = () => {
        if (signal?.aborted) return;
        const sum = inFlight.reduce((a, b) => a + b, 0) + completed;
        const visual = Math.min(99, Math.round((sum / total) * 100));
        this.dispatchEvent("progress", { progress: visual });
      };

      const solveHashwx = async (ch, idx) => {
        const { c, d, n } = ch.payload;
        const expected = Math.max(1, d);
        const striped = new Array(hashwxStripes).fill(0);
        const stripes = [];
        try {
          for (let s = 0; s < hashwxStripes; s++) {
            const stripe = s;
            const task = hashwxPool.runMsg(
              {
                kind: "hashwx",
                hashwxModule,
                c,
                d,
                n,
                workerIndex: stripe,
                workerCount: hashwxStripes,
              },
              (hashes) => {
                striped[stripe] = hashes;
                let sum = 0;
                for (const v of striped) sum += v;
                inFlight[idx] = Math.min(0.99, sum / expected);
                emit();
              },
            );
            task.catch(() => {});
            stripes.push(task);
          }
          const data = await withTimeout(
            firstFulfilled(stripes).catch((err) => {
              throw _err(
                "solve_failed",
                err?.message || "every hashwx worker failed",
              );
            }),
            `hashwx worker #${idx}`,
          );
          solutions[idx] = { nonce: data.nonce };
          log.debug(
            T("solve"),
            `hashwx #${idx}: ${data.hashes} hashes in ${data.durationMs}ms`,
            `compiled=${data.compiled}`,
          );
          inFlight[idx] = 0;
          completed++;
          emit();
        } catch (err) {
          await reclaimStripes(stripes);
          throw err;
        }
        return stripes;
      };

      const hashwxJobs = [];
      challenges.forEach((ch, idx) => {
        if (ch.protocol === "hashwx") hashwxJobs.push({ ch, idx });
      });
      const hashwxSequence = hashwxJobs.length
        ? hashwxQueued
          ? Promise.all(hashwxJobs.map((job) => solveHashwx(job.ch, job.idx)))
          : (async () => {
              for (let i = 0; i < hashwxJobs.length; i++) {
                const stripes = await solveHashwx(
                  hashwxJobs[i].ch,
                  hashwxJobs[i].idx,
                );
                if (i < hashwxJobs.length - 1) await reclaimStripes(stripes);
              }
            })()
        : null;

      try {
        await raceAbort(Promise.all([
          hashwxSequence,
          ...challenges.map((ch, idx) => {
            if (ch.protocol === "sha256-pow") {
              return withTimeout(
                pool.run(ch.payload.salt, ch.payload.target),
                `sha256-pow worker #${idx}`,
              ).then((nonce) => {
                solutions[idx] = { nonce: Number(nonce) };
                inFlight[idx] = 0;
                completed++;
                emit();
              });
            }

            if (ch.protocol === "rsw") {
              return withTimeout(
                pool.runMsg(
                  { kind: "rsw", N: ch.payload.N, x: ch.payload.x, t: ch.payload.t | 0 },
                  (p) => { inFlight[idx] = p; emit(); },
                ),
                `rsw worker #${idx}`,
              ).then((data) => {
                solutions[idx] = { y: data.y };
                inFlight[idx] = 0;
                completed++;
                emit();
              });
            }

            if (ch.protocol === "hashwx") return null;

            return runInstrumentationChallenge(ch.payload.blob).then((out) => {
              if (out?.__timeout) solutions[idx] = { timeout: true };
              else if (out?.__blocked) solutions[idx] = { blocked: true };
              else solutions[idx] = { instr: out };
              inFlight[idx] = 0;
              completed++;
              emit();
            });
          }),
        ]), signal);
      } finally {
        pool.terminate();
        if (hashwxPool) hashwxPool.terminate();
      }

      return solutions;
    }

    async solveChallenges(challenges, signal) {
      const total = challenges.length;
      let completed = 0;

      const speculativeHead = 0;

      let wasmModule = null;
      const wasmSupported =
        typeof WebAssembly === "object" &&
        typeof WebAssembly.instantiate === "function";

      if (wasmSupported) {
        try {
          wasmModule = await getWasmModule();
        } catch (e) {
          log.warn(T("wasm"), "unavailable, falling back to JS solver:", e.message || e);
        }
      }

      if (signal?.aborted) throw _err("aborted", "aborted");
      if (!wasmSupported) {
        log.warn(T("wasm"), "WebAssembly disabled in this browser, solver will be ~10x slower");
        if (!this.#shadow.querySelector(".warning")) {
          const warningEl = document.createElement("div");
          warningEl.className = "warning";
          warningEl.style.cssText = `width:var(--cap-widget-width,230px);background:rgb(237,56,46);color:white;padding:4px 6px;padding-bottom:calc(var(--cap-border-radius,14px) + 5px);font-size:10px;box-sizing:border-box;font-family:system-ui;border-top-left-radius:8px;border-top-right-radius:8px;text-align:center;user-select:none;margin-bottom:-35.5px;opacity:0;transition:margin-bottom .3s,opacity .3s;`;
          warningEl.innerText = this.getI18nText(
            "wasm-disabled",
            "Enable WASM for significantly faster solving",
          );
          this.#shadow.insertBefore(warningEl, this.#shadow.firstChild);
          setTimeout(() => {
            warningEl.style.marginBottom = `calc(-1 * var(--cap-border-radius, 14px))`;
            warningEl.style.opacity = 1;
          }, 10);
        }
      }

      const pool = new WorkerPool(this.#workersCount);
      pool.setWasm(wasmModule);
      pool._ensureSize(this.#workersCount);

      const results = [];
      try {
        for (let i = 0; i < challenges.length; i += this.#workersCount) {
          const chunk = challenges.slice(
            i,
            Math.min(i + this.#workersCount, challenges.length),
          );
          const chunkResults = await raceAbort(Promise.all(
            chunk.map(([salt, target]) =>
              pool.run(salt, target).then((nonce) => {
                completed++;
                const visual = Math.min(
                  99,
                  Math.round(((speculativeHead + completed) / total) * 100),
                );
                if (!signal?.aborted) this.dispatchEvent("progress", { progress: visual });
                return nonce;
              }),
            ),
          ), signal);
          results.push(...chunkResults);
        }
      } finally {
        pool.terminate();
      }

      return results;
    }

    setWorkersCount(workers) {
      const parsedWorkers = parseInt(workers, 10);
      const maxWorkers = Math.min(navigator.hardwareConcurrency || 8, 16);
      this.#workersCount =
        !Number.isNaN(parsedWorkers) &&
        parsedWorkers > 0 &&
        parsedWorkers <= maxWorkers
          ? parsedWorkers
          : navigator.hardwareConcurrency || 8;
    }

    createUI() {
      this.#div.classList.add("captcha");
      this.#div.setAttribute("role", "group");
      this.#div.setAttribute(
        "aria-label",
        this.getI18nText("group-aria-label", "Cap verification"),
      );

      this.#trigger = document.createElement("div");
      this.#trigger.className = "captcha-trigger";
      this.#trigger.setAttribute("part", "trigger");
      this.#trigger.setAttribute("role", "button");
      this.#trigger.setAttribute("tabindex", "0");
      this.#trigger.setAttribute(
        "aria-label",
        this.getI18nText("verify-aria-label", "Click to verify you're a human"),
      );
      this.#trigger.setAttribute("aria-live", "polite");
      this.#trigger.setAttribute("disabled", "true");
      this.#trigger.innerHTML = `<div class="checkbox" part="checkbox" aria-hidden="true"><svg class="progress-ring" viewBox="0 0 32 32" aria-hidden="true"><circle class="progress-ring-bg" cx="16" cy="16" r="14"></circle><circle class="progress-ring-circle" cx="16" cy="16" r="14"></circle></svg></div><p part="label" class="label-wrapper"><span class="label active"></span></p>`;
      // Localized strings can come from `data-cap-i18n-*` attributes, which a
      // host page may fill from user data — never interpolate them as HTML.
      const initialLabel = this.#trigger.querySelector(".label.active");
      if (initialLabel) {
        initialLabel.textContent = this.getI18nText(
          "initial-state",
          "Verify you're human",
        );
      }
      // Clear any children left over from a previous render/reconnect BEFORE
      // appending the fresh UI (otherwise the new nodes get wiped).
      this.#div.replaceChildren();
      this.#div.appendChild(this.#trigger);

      this.#troubleshootLink = document.createElement("a");
      this.#troubleshootLink.className = "cap-troubleshoot-link";
      this.#troubleshootLink.setAttribute("part", "troubleshoot");
      this.#troubleshootLink.setAttribute("target", "_blank");
      this.#troubleshootLink.setAttribute("rel", "noopener");
      this.#troubleshootLink.hidden = true;
      this.#div.appendChild(this.#troubleshootLink);

      this.#credits = document.createElement("a");
      this.#credits.className = "credits";
      this.#credits.setAttribute("aria-label", "Secured by Cap");
      this.#credits.setAttribute("href", "https://trycap.dev");
      this.#credits.setAttribute("target", "_blank");
      this.#credits.setAttribute(
        "title",
        "Secured by Cap: The self-hosted CAPTCHA for the modern web.",
      );
      this.#credits.textContent = "Cap";
      this.#div.appendChild(this.#credits);

      this.#shadow.innerHTML = `<style${window.CAP_CSS_NONCE ? ` nonce="${String(window.CAP_CSS_NONCE).replace(/"/g, "&quot;")}"` : ""}>%%capCSS%%</style>`;

      this.#shadow.appendChild(this.#div);

      this.#enforceCredits();
      setTimeout(() => this.#enforceCredits(), 100);
    }

    addEventListeners() {
      if (!this.#trigger) return;

      this.#credits.addEventListener("click", (e) => {
        e.preventDefault();
        window.open(
          `https://trycap.dev/?${new URLSearchParams(
            // this attribution is only for our plausible analytics
            // instance. no personal data is collected.
            {
              utm_source: "cap_widget",
              utm_medium: "referral",
              utm_campaign: "widget",
              utm_content: window.CAP_DISABLE_WIDGET_REF
                ? ""
                : location.hostname,
              // Send only origin+path: query strings can contain tokens/PII.
              ref: window.CAP_DISABLE_WIDGET_REF
                ? ""
                : `${location.origin}${location.pathname}`,
              sub: window.CAP_DISABLE_WIDGET_REF ? "" : document.referrer || "",
            },
          ).toString()}`,
          "_blank",
          "noopener,noreferrer",
        );
      });

      this.#trigger.addEventListener("click", () => {
        if (!this.#trigger.hasAttribute("disabled")) this.solve();
      });
      this.#trigger.addEventListener("mousedown", () => {
        if (!this.#trigger.hasAttribute("disabled") && this.#hasHaptics) {
          navigator.vibrate(5);
        }
      });

      this.#trigger.addEventListener("keydown", (e) => {
        if (e.target !== this.#trigger) return;
        if (
          (e.key === "Enter" || e.key === " ") &&
          !this.#trigger.hasAttribute("disabled")
        ) {
          e.preventDefault();
          e.stopPropagation();
          this.solve();
        }
      });

      this.addEventListener("progress", this.boundHandleProgress);
      this.addEventListener("solve", this.boundHandleSolve);
      this.addEventListener("error", this.boundHandleError);
      this.addEventListener("reset", this.boundHandleReset);
    }

    #hostIsHidden() {
      if (!this.#host) return false;
      const rect = this.#host.getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) return true;
      const cs = window.getComputedStyle(this.#host);
      if (cs.display === "none" || cs.visibility === "hidden") return true;
      return false;
    }

    #enforceCredits() {
      if (!this.#credits || !this.#div || this.#hostIsHidden()) return;
      if (!this.#credits.isConnected || this.#credits.parentNode !== this.#div) {
        this.#div.appendChild(this.#credits);
      }
      if (!this.#credits.textContent || !this.#credits.textContent.trim()) {
        this.#credits.textContent = "Cap";
      }
      if (this.#credits.getAttribute("href") !== "https://trycap.dev") {
        this.#credits.setAttribute("href", "https://trycap.dev");
      }
      this.#credits.style.cssText = [
        "display: inline-flex !important",
        "visibility: visible !important",
        "opacity: 0.8 !important",
        "pointer-events: all !important",
        "font-size: 12px !important",
        "transform: none !important",
        "clip-path: none !important",
        "filter: none !important",
        "position: absolute !important",
      ].join("; ");
    }

    animateLabel(text) {
      if (!this.#trigger) return;
      const wrapper = this.#trigger.querySelector(".label-wrapper");
      if (!wrapper) return;

      if (prefersReducedMotion()) {
        const current = wrapper.querySelector(".label.active");
        if (current) {
          current.textContent = text;
        } else {
          const span = document.createElement("span");
          span.className = "label active";
          span.textContent = text;
          wrapper.appendChild(span);
        }
        return;
      }

      const current = wrapper.querySelector(".label.active");

      const next = document.createElement("span");
      next.className = "label";
      next.textContent = text;
      wrapper.appendChild(next);

      void next.offsetWidth;

      next.classList.add("active");
      if (current) {
        current.classList.remove("active");
        current.classList.add("exit");
        current.addEventListener("transitionend", () => current.remove(), {
          once: true,
        });
      }
    }

    updateUI(state, text, disabled = false) {
      if (!this.#div || !this.#trigger) return;

      this.#div.setAttribute("data-state", state);
      this.#div.classList.remove("has-troubleshoot");

      this.animateLabel(text);

      if (this.#troubleshootLink) this.#troubleshootLink.hidden = true;

      if (disabled) {
        this.#trigger.setAttribute("disabled", "true");
      } else {
        this.#trigger.removeAttribute("disabled");
      }
    }

    updateUIBlocked(label, showTroubleshooting = false) {
      if (!this.#div || !this.#trigger) return;

      this.#div.setAttribute("data-state", "error");
      this.#trigger.removeAttribute("disabled");

      this.animateLabel(label);

      if (this.#troubleshootLink) {
        if (showTroubleshooting) {
          const troubleshootingUrl =
            this.getAttribute("data-cap-troubleshooting-url") ||
            "https://trycap.dev/guide/troubleshooting/instrumentation.html";
          this.#troubleshootLink.setAttribute("href", troubleshootingUrl);
          this.#troubleshootLink.textContent = this.getI18nText(
            "troubleshooting-label",
            "Troubleshoot",
          );
          this.#troubleshootLink.hidden = false;
          this.#div.classList.add("has-troubleshoot");
        } else {
          this.#troubleshootLink.hidden = true;
          this.#div.classList.remove("has-troubleshoot");
        }
      }
    }

    handleProgress(event) {
      if (!this.#trigger) return;

      const progressCircle = this.#trigger.querySelector(
        ".progress-ring-circle",
      );

      if (progressCircle) {
        const circumference = 2 * Math.PI * 14;
        const offset =
          circumference - (event.detail.progress / 100) * circumference;
        progressCircle.style.strokeDashoffset = offset;
      }

      const wrapper = this.#trigger.querySelector(".label-wrapper");
      if (wrapper) {
        const activeLabel = wrapper.querySelector(".label.active");
        if (activeLabel) {
          activeLabel.textContent = `${this.getI18nText("verifying-label", "Verifying...")}`;
        }
      }

      this.executeAttributeCode("onprogress", event);
    }

    handleSolve(event) {
      this.updateUI(
        "done",
        this.getI18nText("solved-label", "You're a human"),
        true,
      );
      this.executeAttributeCode("onsolve", event);
      this.#internals?.setValidity?.({});
      this.#div?.classList.remove("invalid");
    }

    handleError(event) {
      this.updateUI(
        "error",
        this.getI18nText("error-label", "Error. Try again."),
      );
      this.executeAttributeCode("onerror", event);

      if (this.#hasHaptics) navigator.vibrate([10, 40, 10]);
    }

    handleReset(event) {
      this.updateUI("", this.getI18nText("initial-state", "I'm a human"));
      this.executeAttributeCode("onreset", event);
      this.#updateValidity();
    }

    executeAttributeCode(attributeName, event) {
      const code = this.getAttribute(attributeName);
      if (!code) {
        return;
      }

      log.warn(
        T(),
        "inline `onxxx='…'` handlers are deprecated. use `addEventListener` callbacks instead.",
      );

      new Function("event", code).call(this, event);
    }

    error(message = "Unknown error", code = "unknown") {
      log.error(T("solve"), `[${code}] ${message}`);
      this.dispatchEvent("error", { isCap: true, code, message });
    }

    dispatchEvent(eventName, detail = {}) {
      const event = new CustomEvent(eventName, {
        bubbles: true,
        composed: true,
        detail,
      });
      super.dispatchEvent(event);
    }

    reset() {
      this.#generation++;
      this.#business = null;
      this.#abort?.abort();
      this.#abort = new AbortController();
      this.#solving = false;
      if (this.#speculative) {
        this.#speculative.state = "error";
        this.#speculative.notify();
      }
      if (this.#speculativePool) {
        this.#speculativePool.terminate();
        this.#speculativePool = null;
      }
      if (this.#resetTimer) {
        clearTimeout(this.#resetTimer);
        this.#resetTimer = null;
      }
      if (this.#speculativeTimer) {
        clearTimeout(this.#speculativeTimer);
        this.#speculativeTimer = null;
      }
      if (this.#speculative) this.#resetSpeculativeState();
      this.token = null;
      this.#setToken("");
      this.dispatchEvent("reset");
    }

    get tokenValue() {
      return this.token;
    }

    disconnectedCallback() {
      this.#themeObserver?.disconnect();
      this.#themeObserver = null;
      this.removeEventListener("invalid", this.#handleInvalid);
      this.#abort?.abort();
      this.removeEventListener("progress", this.boundHandleProgress);
      this.removeEventListener("solve", this.boundHandleSolve);
      this.removeEventListener("error", this.boundHandleError);
      this.removeEventListener("reset", this.boundHandleReset);

      this.#eventHandlers.forEach((handler, eventName) => {
        this.removeEventListener(eventName.slice(2), handler);
      });
      this.#eventHandlers.clear();

      if (this.#shadow) {
        this.#shadow.innerHTML = "";
      }

      this.reset();
      this.cleanup();
    }

    cleanup() {
      if (this.#resetTimer) {
        clearTimeout(this.#resetTimer);
        this.#resetTimer = null;
      }

      this.#detachInteractionListeners();
      if (this.#speculativeTimer) {
        clearTimeout(this.#speculativeTimer);
        this.#speculativeTimer = null;
      }
      if (this.#speculativePool) {
        this.#speculativePool.terminate();
        this.#speculativePool = null;
      }
      if (this.#speculative) {
        this.#speculative.state = "error";
        this.#speculative.notify();
        this.#speculative = null;
      }
    }
  }

  class Cap {
    constructor(config = {}, el) {
      const widget = el || document.createElement("cap-widget");

      Object.entries(config).forEach(([a, b]) => {
        widget.setAttribute(a, b);
      });

      if (!config.apiEndpoint && !window?.CAP_CUSTOM_FETCH) {
        widget.remove();
        throw new Error(
          "Missing API endpoint. Either custom fetch or an API endpoint must be provided.",
        );
      }

      if (config.apiEndpoint) {
        widget.setAttribute("data-cap-api-endpoint", config.apiEndpoint);
      }

      if (!el && !widget.hasAttribute("data-cap-disable-haptics")) {
        widget.setAttribute("data-cap-disable-haptics", "");
      }

      this.widget = widget;
      this.solve = this.widget.solve.bind(this.widget);
      this.reset = this.widget.reset.bind(this.widget);
      this.addEventListener = this.widget.addEventListener.bind(this.widget);

      Object.defineProperty(this, "token", {
        get: () => widget.token,
        configurable: true,
        enumerable: true,
      });

      if (!el) {
        widget.style.display = "none";
        document.documentElement.appendChild(widget);
      }
    }
  }

  window.Cap = Cap;

  if (!customElements.get("cap-widget") && !window?.CAP_DONT_SKIP_REDEFINE) {
    customElements.define("cap-widget", CapWidget);
  } else if (customElements.get("cap-widget")) {
    log.warn(
      T(),
      "cap-widget custom element already defined, skipping re-define. set window.CAP_DONT_SKIP_REDEFINE = true to override",
    );
  }

  if (typeof exports === "object" && typeof module !== "undefined") {
    module.exports = Cap;
  } else if (typeof define === "function" && define.amd) {
    define([], () => Cap);
  }

  if (typeof exports !== "undefined") {
    exports.default = Cap;
  }
})();
