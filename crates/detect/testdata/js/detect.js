const MOBILE_UA =
  /Android|iPhone|iPad|iPod|IEMobile|BlackBerry|Mobile Safari|; Mobile|Silk|Kindle|Tizen|Opera Mini/i;

const MAX_FONT_WIDTHS = 64;
const MAX_TAMPER_KEYS = 8;
const MAX_TAMPER_KEY_LENGTH = 32;
const MAX_DETAIL_FIELDS = 6;
const OUTER_HEIGHT_SLACK = 16;

const isNum = (x) => typeof x === "number" && Number.isFinite(x);
const isPlainObject = (x) => !!x && typeof x === "object" && !Array.isArray(x);

// Fields that are always collected. Optional consistency fields (workerUA,
// webgl, canvas, audio, emoji, platform, hardwareConcurrency, storageQuota)
// are probed only when the challenge opts in, so older clients that do not
// run the extended probe still validate.
const PROBE_FIELD_TYPES = {
  ua: "string",
  productSub: "string",
  oscpu: "string",
  uaDataPresent: "boolean",
  uaData: "nullableObject",
  plugins: "object",
  engine: "object",
  screen: "object",
  outerWH: "array",
  isExtended: "nullableBoolean",
  fontWidths: "array",
  tamper: "nullableObject",
};

const OPTIONAL_FIELD_TYPES = {
  workerUA: "nullableString",
  webgl: "nullableObject",
  canvas: "nullableString",
  audio: "nullableNumber",
  emoji: "nullableObject",
  platform: "nullableString",
  hardwareConcurrency: "nullableNumber",
  storageQuota: "nullableNumber",
  cdp: "nullableObject",
  active: "nullableObject",
  evalShape: "nullableObject",
  nativeShape: "nullableObject",
  notifPerm: "nullableString",
  mimeCount: "nullableNumber",
  languages: "nullableObject",
  chromeShape: "nullableObject",
  workerInfo: "nullableObject",
  canvasStable: "nullableBoolean",
  webgpu: "nullableObject",
};

const typeOk = (value, kind) => {
  if (kind === "string") return typeof value === "string";
  if (kind === "boolean") return typeof value === "boolean";
  if (kind === "object") return isPlainObject(value);
  if (kind === "array") return Array.isArray(value);
  if (kind === "number") return isNum(value);
  if (kind === "nullableString")
    return value === null || typeof value === "string";
  if (kind === "nullableNumber") return value === null || isNum(value);
  if (kind === "nullableObject") return value === null || isPlainObject(value);
  if (kind === "nullableBoolean")
    return value === null || typeof value === "boolean";
  return false;
};

// OS declared either by the UA string or by the platform string. We use it to
// cross-check facts that are OS-specific (emoji glyph style, font metrics).
function declaredOS(S) {
  const ua = String(S?.ua || "");
  const plat = String(S?.platform || "");
  const hay = `${ua} ${plat}`;
  if (/Android/i.test(hay)) return "android";
  if (/iPhone|iPad|iPod/i.test(hay)) return "ios";
  if (/Macintosh|Mac OS X|MacIntel|macOS/i.test(hay)) return "macos";
  if (/Windows|Win32|Win64/i.test(hay)) return "windows";
  if (/CrOS/i.test(hay)) return "chromeos";
  if (/Linux|X11|Ubuntu|Fedora/i.test(hay)) return "linux";
  return null;
}

// Generic product names that identify a virtualized / software renderer. Real
// Software / virtualized rasterizers only. We deliberately do NOT match
// "Google Inc." or "ANGLE (Google, Vulkan…)" — those appear on real Android
// GPUs (Chrome on Android reports an ANGLE-over-Vulkan string with a Google
// vendor prefix), so matching them misfires on legitimate phones.
const SOFTWARE_GPU =
  /swiftshader|llvmpipe|softpipe|mesa offscreen|vmware|virtualbox|qemu|parallels|virgl|microsoft basic render|swangle|angle \(google, vulkan \(swiftshader/i;

export function isMobileVector(S) {
  if (S?.uaData?.mobile === true) return true;
  return MOBILE_UA.test(String(S?.ua || ""));
}

export function probeCompleteness(S, fontStackCount, optionalFields) {
  if (!isPlainObject(S)) return ["probe"];
  const bad = [];
  for (const field of Object.keys(PROBE_FIELD_TYPES)) {
    if (!typeOk(S[field], PROBE_FIELD_TYPES[field])) bad.push(field);
  }
  if (Array.isArray(optionalFields)) {
    for (const field of optionalFields) {
      const kind = OPTIONAL_FIELD_TYPES[field];
      if (kind && !typeOk(S[field], kind)) bad.push(field);
    }
  }
  if (
    Array.isArray(S.fontWidths) &&
    isNum(fontStackCount) &&
    S.fontWidths.length !== fontStackCount
  ) {
    bad.push("fontWidths.length");
  }
  return bad;
}

export function geometryStats(fontWidths) {
  const w = (Array.isArray(fontWidths) ? fontWidths : [])
    .slice(0, MAX_FONT_WIDTHS)
    .filter(isNum);
  if (w.length < 6) return null;
  let count = 0;
  const distinct = new Set();
  for (const x of w) {
    if (Math.trunc(x) === x) {
      count++;
      distinct.add(x);
    }
  }
  return { count, distinct: distinct.size, n: w.length };
}

export function detectAutomation(S, opts = {}) {
  if (!S || typeof S !== "object") {
    return {
      pass: false,
      checks: [],
      blockedBy: ["probe_missing"],
      riskFlags: [],
    };
  }
  // `top` carries main-document supplements sent OUTSIDE the signed probe (the
  // sandboxed iframe cannot read canvas/WebGL/automation globals). Merge them
  // as lower priority so the signed `p` values always win on conflicts.
  if (isPlainObject(S.top)) {
    // Only the fields the sandboxed iframe genuinely cannot read may come from
    // the unsigned  supplement. Never let it override identity/consistency
    // fields (webdriver/deviceMemory/engine/tamper/...).
    const ALLOW_TOP = new Set([
      "automationGlobals",
      "innerWH",
      "webgl",
      "canvas",
      "emoji",
      "audio",
      "storageQuota",
    ]);
    const mergedTop = {};
    for (const k of Object.keys(S.top))
      if (ALLOW_TOP.has(k)) mergedTop[k] = S.top[k];
    S = Object.assign(mergedTop, S);
  }

  const checks = [];
  const add = (id, passed, detail, gating = true) =>
    checks.push({ id, passed: passed !== false, detail, gating });

  const incomplete = probeCompleteness(
    S,
    opts.fontStackCount,
    opts.optionalFields,
  );
  add(
    "probe_incomplete",
    incomplete.length === 0,
    incomplete.length
      ? `missing or malformed: ${incomplete.slice(0, MAX_DETAIL_FIELDS).join(", ")}`
      : "all fields present",
  );

  const gecko =
    S.engine?.hasMozInnerScreenX === true ||
    (S.productSub === "20100101" && S.uaDataPresent === false) ||
    (typeof S.oscpu === "string" && S.oscpu !== "__undefined");
  const chromium = S.uaDataPresent === true || S.engine?.hasChrome === true;
  const mobile = isMobileVector(S);

  const geo = geometryStats(S.fontWidths);
  const quantized = !!geo && geo.count >= 5 && geo.distinct >= 3;
  add(
    "geometry_quantized",
    !quantized,
    geo
      ? `${geo.count}/${geo.n} whole-px, ${geo.distinct} distinct`
      : "not measured",
  );

  add(
    "webdriver_true",
    S.webdriver !== true,
    `webdriver=${String(S.webdriver)}`,
  );

  const stripped = chromium && S.webdriver === undefined;
  add(
    "webdriver_stripped",
    !stripped,
    chromium ? (stripped ? "removed" : "ok") : "not a chromium engine",
  );

  const contradiction =
    gecko && (isNum(S.deviceMemory) || S.uaDataPresent === true);
  add("gecko_contradiction", !contradiction, gecko ? "gecko engine" : "n/a");

  // --- Declared identity vs observed engine shape ----------------------
  // The UA claims an engine; native code shape must agree. These are the
  // cheapest contradictions to force a stealth tool to explain.
  const uaStr = String(S.ua || "");
  const chromiumUa = /Chrome\//i.test(uaStr) || /Chromium\//i.test(uaStr);
  const firefoxUa = /Firefox\//i.test(uaStr);
  const webkitUa = /Safari\//i.test(uaStr) && !chromiumUa && !firefoxUa;
  // Engine identity by native-format SHAPE, not length (length drifts by
  // version). V8 renders natives single-line; Gecko/WebKit multi-line.
  const wantShape =
    Array.isArray(opts.optionalFields) &&
    (opts.optionalFields.includes("evalShape") ||
      opts.optionalFields.includes("nativeShape"));
  if (
    wantShape &&
    (!isPlainObject(S.evalShape) || typeof S.evalShape.nl !== "boolean")
  ) {
    add("shape_probe_missing", false, "eval/native shape probe missing");
  }
  if (isPlainObject(S.evalShape) && typeof S.evalShape.nl === "boolean") {
    const v8 = S.evalShape.nl === false;
    // A V8 (single-line) engine behind a Firefox/WebKit UA is a spoof; a
    // multi-line engine behind a Chromium UA likewise.
    const bad = (chromiumUa && !v8) || ((firefoxUa || webkitUa) && v8);
    add(
      "engine_eval_mismatch",
      !bad,
      bad ? `eval newline=${S.evalShape.nl} len=${S.evalShape.len}` : "ok",
      false,
    );
  }
  // Self-consistency: eval's native format must match another known native
  // (Array.prototype.push). A mismatch means one was individually patched —
  // this holds regardless of the engine's formatting across versions.
  if (
    isPlainObject(S.evalShape) &&
    isPlainObject(S.nativeShape) &&
    typeof S.evalShape.nl === "boolean" &&
    typeof S.nativeShape.nl === "boolean"
  ) {
    const bad = S.evalShape.nl !== S.nativeShape.nl;
    add(
      "native_shape_inconsistent",
      !bad,
      bad ? "eval/native format differ" : "ok",
      false,
    );
  }
  if (typeof S.productSub === "string" && S.productSub) {
    const expect = firefoxUa
      ? "20100101"
      : chromiumUa || /Safari\//.test(uaStr) || /OPR\//.test(uaStr)
        ? "20030107"
        : null;
    if (expect) {
      add(
        "productsub_mismatch",
        S.productSub === expect,
        S.productSub === expect ? "ok" : `productSub=${S.productSub}`,
        false,
      );
    }
  }
  if (
    isPlainObject(S.plugins) &&
    isNum(S.plugins.length) &&
    isNum(S.mimeCount)
  ) {
    const bad = S.plugins.length > 0 && S.mimeCount === 0;
    add(
      "plugins_mime_mismatch",
      !bad,
      bad ? `plugins=${S.plugins.length}, mimeTypes=0` : "ok",
      false,
    );
  }
  if (isPlainObject(S.languages)) {
    const lang = S.languages.lang;
    const langs = Array.isArray(S.languages.langs) ? S.languages.langs : [];
    if (lang && langs.length) {
      const ok = langs.indexOf(lang) !== -1;
      add(
        "language_not_in_languages",
        ok,
        ok ? "ok" : `${lang} not in languages`,
        false,
      );
    }
    // Server-observed Accept-Language must include the client's language
    // (base tag compare, to tolerate region/quality differences).
    if (typeof opts.acceptLanguage === "string" && opts.acceptLanguage) {
      const header = opts.acceptLanguage
        .split(",")
        .map((x) => x.split(";")[0].trim().toLowerCase())
        .filter((x) => x && x !== "*");
      const client = []
        .concat(typeof lang === "string" ? [lang.toLowerCase()] : [])
        .concat(
          langs
            .filter((l) => typeof l === "string")
            .map((l) => l.toLowerCase()),
        );
      if (header.length && client.length) {
        const base = (t) => t.split("-")[0];
        const ok = client.some((c) =>
          header.some((h) => h === c || base(h) === base(c)),
        );
        add(
          "language_header_mismatch",
          ok,
          ok ? "ok" : `header=${header[0]} client=${client[0]}`,
          false,
        );
      }
    }
  }
  if (chromiumUa && isPlainObject(S.chromeShape)) {
    // A real Chrome exposes at least one of loadTimes/csi/app on window.chrome;
    // a fully hollow object is the tell (not `runtime`, which real pages lack).
    const cs = S.chromeShape;
    const any = cs.runtime || cs.loadTimes || cs.csi || cs.app;
    add(
      "chrome_shape_hollow",
      !!any,
      any ? "ok" : "window.chrome is hollow",
      false,
    );
  }
  // --- Cross-realm (worker) consistency --------------------------------
  // Worker creation can legitimately fail in hardened/opaque-origin contexts,
  // so a missing workerInfo is a (small) risk flag, not a gating failure.
  if (
    Array.isArray(opts.optionalFields) &&
    opts.optionalFields.includes("workerInfo") &&
    !isPlainObject(S.workerInfo)
  ) {
    add("worker_probe_missing", false, "worker probe missing", false);
  }
  if (isPlainObject(S.workerInfo)) {
    const wi = S.workerInfo;
    if (
      isNum(wi.hardwareConcurrency) &&
      isNum(S.hardwareConcurrency) &&
      wi.hardwareConcurrency !== S.hardwareConcurrency
    ) {
      add(
        "worker_hw_mismatch",
        false,
        `main=${S.hardwareConcurrency} worker=${wi.hardwareConcurrency}`,
        false,
      );
    }
    if (
      isNum(wi.deviceMemory) &&
      isNum(S.deviceMemory) &&
      wi.deviceMemory !== S.deviceMemory
    ) {
      add(
        "worker_mem_mismatch",
        false,
        `main=${S.deviceMemory} worker=${wi.deviceMemory}`,
        false,
      );
    }
    if (
      typeof wi.platform === "string" &&
      wi.platform &&
      typeof S.platform === "string" &&
      S.platform &&
      wi.platform !== S.platform
    ) {
      add("worker_platform_mismatch", false, "main≠worker platform", false);
    }
    // Cross-realm engine shape: the main thread and a worker run the same
    // engine, so their native-function formats must agree. A mismatch means one
    // realm was patched. Engine-agnostic (V8/Gecko/WebKit all self-consistent).
    if (
      isPlainObject(wi.evalShape) &&
      isPlainObject(S.evalShape) &&
      typeof wi.evalShape.nl === "boolean" &&
      typeof S.evalShape.nl === "boolean"
    ) {
      const bad = wi.evalShape.nl !== S.evalShape.nl;
      add(
        "worker_engine_mismatch",
        !bad,
        bad ? "main≠worker native format" : "ok",
        false,
      );
    }
  }
  if (S.canvasStable === false) {
    add("canvas_unstable", false, "canvas output drifts across renders", false);
  }

  // --- WebGPU ↔ WebGL ↔ platform cross-validation -----------------------
  // Both APIs must describe the same physical GPU. A VM/container that fakes
  // one but not the other, or a software stack, contradicts itself.
  const gpu = isPlainObject(S.webgpu) ? S.webgpu : null;
  if (gpu) {
    if (gpu.ok === false && chromiumUa) {
      add("webgpu_absent", false, "requestAdapter returned null", false);
    } else if (gpu.ok === true) {
      const vendorOf = (s) => {
        const v = String(s || "").toLowerCase();
        if (/swiftshader|llvmpipe|softpipe|software|basic render/.test(v))
          return "software";
        if (/nvidia|geforce|quadro|rtx/.test(v)) return "nvidia";
        if (/amd|radeon/.test(v)) return "amd";
        if (/intel|arc/.test(v)) return "intel";
        if (/apple|metal/.test(v)) return "apple";
        if (/qualcomm|adreno/.test(v)) return "qualcomm";
        if (/imagination|powervr/.test(v)) return "imagination";
        return null;
      };
      const wgpu = vendorOf(gpu.vendor || gpu.description || gpu.device || "");
      const wgl = isPlainObject(S.webgl)
        ? vendorOf(`${S.webgl.vendor || ""} ${S.webgl.renderer || ""}`)
        : null;
      if (wgpu && wgl) {
        const ok = wgpu === wgl;
        add(
          "webgpu_webgl_mismatch",
          ok,
          ok ? "ok" : `webgpu=${wgpu} webgl=${wgl}`,
          false,
        );
      }
    }
  }

  const sc = S.screen || {};
  const ow = Array.isArray(S.outerWH) ? S.outerWH : [];
  let iw = Array.isArray(S.innerWH) ? S.innerWH : [];
  // innerWH (vp) is a parent-page supplement and is NOT covered by the probe
  // MAC, so only trust it when it is internally consistent with the signed
  // outer/screen dimensions; otherwise ignore it.
  if (
    isNum(iw[0]) &&
    isNum(iw[1]) &&
    ((isNum(ow[0]) && iw[0] > ow[0] + OUTER_HEIGHT_SLACK) ||
      (isNum(ow[1]) && iw[1] > ow[1] + OUTER_HEIGHT_SLACK) ||
      (isNum(sc.width) && iw[0] > sc.width + OUTER_HEIGHT_SLACK) ||
      (isNum(sc.height) && iw[1] > sc.height + OUTER_HEIGHT_SLACK))
  ) {
    iw = [];
  }
  const singleMonitor = S.isExtended === false;
  const outerTaller =
    isNum(ow[1]) && isNum(sc.height) && ow[1] > sc.height + OUTER_HEIGHT_SLACK;
  const exceeds = outerTaller && singleMonitor;
  add(
    "window_exceeds_screen",
    !exceeds,
    singleMonitor
      ? exceeds
        ? `outerHeight ${ow[1]} > screen.height ${sc.height}`
        : "ok"
      : "monitor layout unknown",
  );

  const viewportIsScreen =
    !mobile &&
    isNum(iw[0]) &&
    isNum(iw[1]) &&
    iw[0] === sc.width &&
    iw[1] === sc.height &&
    isNum(ow[1]) &&
    ow[1] > iw[1];
  add(
    "viewport_override",
    !viewportIsScreen,
    viewportIsScreen
      ? `viewport ${iw[0]}x${iw[1]} == screen, window ${ow[1]} tall`
      : "ok",
    false,
  );

  const brands = Array.isArray(S.uaData?.brands)
    ? S.uaData.brands.join(" ")
    : "";
  const headless =
    /headlesschrome/i.test(brands) ||
    /headlesschrome/i.test(String(S.ua || ""));
  add(
    "headless_token",
    !headless,
    headless ? "HeadlessChrome present" : "absent",
  );

  // When the challenge asked for the tamper probe, a missing/malformed object
  // means the check could not run. It is pure JS introspection, so a real
  // browser cannot legitimately fail it — treat it as a failed gating check
  // instead of silently skipping tamper-evidence.
  const wantTamper =
    Array.isArray(opts.optionalFields) &&
    opts.optionalFields.includes("tamper");
  if (wantTamper && !isPlainObject(S.tamper)) {
    add("tamper_probe_missing", false, "tamper probe missing or malformed");
  }
  const t = isPlainObject(S.tamper) ? S.tamper : {};
  const tampered = Object.keys(t).filter((k) => t[k] === false);
  add(
    "native_tamper",
    tampered.length === 0,
    tampered.length
      ? `JS-overridden: ${tampered
          .slice(0, MAX_TAMPER_KEYS)
          .map((k) => String(k).slice(0, MAX_TAMPER_KEY_LENGTH))
          .join(", ")}`
      : "native",
    false,
  );

  // WebCrypto native-ness: if `crypto.subtle.sign/importKey/digest` were
  // replaced, the probe-result MAC cannot be trusted. A patched primitive is
  // decisive tampering, so this one gates.
  const cryptoKeys = ["cryptoSign", "cryptoImportKey", "cryptoDigest"];
  if (cryptoKeys.some((k) => typeof t[k] === "boolean")) {
    const patched = cryptoKeys.filter((k) => t[k] === false);
    add(
      "crypto_tampered",
      patched.length === 0,
      patched.length ? `WebCrypto overridden: ${patched.join(", ")}` : "native",
    );
  } else if (wantTamper) {
    // The probe is expected to return a verdict for every WebCrypto primitive
    // (HTTPS-only deployment). No verdict at all = the probe was stripped.
    add(
      "crypto_probe_missing",
      false,
      "no WebCrypto tamper verdict (probe stripped)",
    );
  }

  // --- CDP / DevTools attachment --------------------------------------
  // The console-accessor trap fires only when something OUTSIDE the page reads
  // console properties (CDP Runtime.enable does exactly this). Real browsers
  // never trip it. This is a GATING signal: a live DevTools/CDP attachment is
  // the signature of an automation driver, regardless of headless/headful.
  const wantCdp =
    Array.isArray(opts.optionalFields) && opts.optionalFields.includes("cdp");
  const cdp = isPlainObject(S.cdp) ? S.cdp : null;
  if (wantCdp && !cdp) {
    add("cdp_probe_missing", false, "cdp probe missing or malformed");
  }
  if (cdp) {
    const tapped = isNum(cdp.tap) && cdp.tap > 0;
    add(
      "cdp_console_trap",
      !tapped,
      tapped ? `console read externally (${cdp.tap}x)` : "no external read",
    );
    const paused = cdp.dbgPause === true;
    add(
      "cdp_debugger_pause",
      !paused,
      paused ? "debugger; caused a pause (>50ms)" : "no pause",
    );
    const prep = cdp.errPrep === true;
    add(
      "cdp_stack_tamper",
      !prep,
      prep ? "Error.prepareStackTrace overridden" : "clean",
      false,
    );
    const aut = cdp.aut === 1;
    add(
      "cdp_automation_globals",
      !aut,
      aut ? "automation global present" : "none",
      false,
    );
    // Legacy Runtime.enable serialization side-effects. Patched in current V8
    // but still present on older released Chrome builds — worth flagging.
    const objTap = isNum(cdp.objTap) && cdp.objTap > 0;
    add(
      "cdp_console_object_trap",
      !objTap,
      objTap
        ? `console object getter fired (${cdp.objTap}x)`
        : "no object read",
      false,
    );
    const stackTap = isNum(cdp.stackTap) && cdp.stackTap > 0;
    add(
      "cdp_stack_getter",
      !stackTap,
      stackTap
        ? `Error.stack getter fired (${cdp.stackTap}x)`
        : "no stack read",
      false,
    );
    const protoTap = isNum(cdp.protoTap) && cdp.protoTap > 0;
    add(
      "cdp_proto_getter",
      !protoTap,
      protoTap ? `prototype getter fired (${cdp.protoTap}x)` : "no proto read",
      false,
    );
  }

  // --- Active capability probes ---------------------------------------
  // These come from actually INVOKING APIs (enumerateDevices, permissions
  // .query, canPlayType, RTCPeerConnection, matchMedia). A capability that is
  // hooked or missing fails when called, not when merely read. All are weak
  // (non-gating) to avoid false positives on sparse devices.
  const act = isPlainObject(S.active) ? S.active : null;
  if (act) {
    // Device/codec/pointer expectations only hold for Chromium: Firefox and
    // privacy forks (Waterfox/LibreWolf) return an empty enumerateDevices()
    // until permission is granted, and their codec probes are OS-dependent.
    // Judging those engines by Chromium norms is a false positive.
    if (chromiumUa) {
      if (isPlainObject(act.devices)) {
        const total =
          (act.devices.audioin || 0) +
          (act.devices.videoin || 0) +
          (act.devices.audioout || 0);
        add(
          "active_no_media_devices",
          total > 0,
          total > 0 ? `devices=${total}` : "enumerateDevices returned 0",
          false,
        );
      }
      if (isPlainObject(act.codecs)) {
        const has = !!(act.codecs.mp4 || act.codecs.webm);
        add(
          "active_no_video_codecs",
          has,
          has ? "ok" : "no mp4/webm codec support",
          false,
        );
      }
      const desktopUa = !/Mobi|Android|iPhone|iPad/i.test(String(S.ua || ""));
      if (
        act.media &&
        act.media.pointerFine === false &&
        act.media.hoverHover === false &&
        desktopUa
      ) {
        add(
          "active_no_fine_pointer",
          false,
          "desktop UA but no fine pointer/hover",
          false,
        );
      }
    }
    // Engine-appropriate check for Firefox: device COUNT is not evidence there
    // (empty until permission), but a Firefox-claimed page whose mediaDevices
    // API is missing/stubbed is a tamper signal. So we still test Firefox.
    if (
      firefoxUa &&
      isPlainObject(act.mediaApi) &&
      act.mediaApi.md === "object"
    ) {
      const ok = act.mediaApi.ed === "function";
      add(
        "active_media_api_missing",
        ok,
        ok ? "ok" : "enumerateDevices missing",
        false,
      );
    }
    if (act.rtc === false) {
      add("active_no_rtc", false, "RTCPeerConnection unavailable", false);
    }
    // Safari/WebKit legitimately rejects some permission names, so only judge
    // a failed permissions.query on Chromium/Gecko.
    if (act.permError === true && (chromiumUa || firefoxUa)) {
      add("active_permissions_error", false, "permissions.query failed", false);
    }
    // Notification.permission vs permissions.query state must agree. The API
    // spells the unanswered state differently ("default" vs "prompt").
    if (typeof S.notifPerm === "string" && typeof act.permState === "string") {
      const norm = (p) => (p === "prompt" ? "default" : p);
      const bad = norm(act.permState) !== S.notifPerm;
      add(
        "notif_perm_mismatch",
        !bad,
        bad ? `Notification=${S.notifPerm} vs query=${act.permState}` : "ok",
        false,
      );
    }
  }

  // Automation globals detected in the MAIN document (not the iframe). This is
  // the most reliable Puppeteer/Playwright signal because it catches their
  // mandatory window bindings (__playwright__binding__, __pwInitScripts, cdc_*,
  // etc.) from the page where they are visible.
  if (Array.isArray(S.automationGlobals) && S.automationGlobals.length > 0) {
    add(
      "automation_globals_main",
      false,
      `found: ${S.automationGlobals.slice(0, 5).join(", ")}`,
    );
  }

  // --- Extended consistency checks -------------------------------------
  // These only fire when the client returned the optional probe fields. A
  // missing optional field means the check is "not run" (passed) rather than
  // failed, so enabling the probe stays backwards-compatible.

  const os = declaredOS(S);

  // Worker UA vs main-thread UA. Automation tools frequently override the
  // main-thread userAgent but leave the worker's navigator.userAgent intact.
  if (typeof S.workerUA === "string" && typeof S.ua === "string" && S.ua) {
    const mismatch = S.workerUA !== S.ua;
    add(
      "worker_ua_mismatch",
      !mismatch,
      mismatch
        ? `main≠worker (${MAX_DETAIL_FIELDS}:${String(S.workerUA).slice(0, 48)})`
        : "consistent",
    );
  }

  // WebGL renderer sanity. Software renderers (SwiftShader/Mesa/llvmpipe) and
  // the "no vendor" desktop case are the classic headless/VM signatures. On
  // Chromium, a missing WebGL2 context while WebGL1 works is also abnormal.
  const gl = isPlainObject(S.webgl) ? S.webgl : null;
  if (gl) {
    const renderer = String(gl.renderer || "");
    const vendor = String(gl.vendor || "");
    // No context at all: odd for a real display-backed desktop browser, but
    // possible with hardened privacy settings, so this is a risk flag only.
    if (gl.ok === false && !mobile) {
      add(
        "webgl_absent_desktop",
        false,
        "no webgl context on desktop UA",
        false,
      );
    }
    const generic = SOFTWARE_GPU.test(renderer) || SOFTWARE_GPU.test(vendor);
    // Gating only on desktop. On mobile a software renderer string is far less
    // conclusive (emulators aside, some browsers fall back), so it stays a
    // risk flag there to avoid blocking legitimate phones.
    add(
      "webgl_software_renderer",
      !generic,
      generic ? `renderer=${renderer.slice(0, 64)}` : renderer || "no webgl",
      false,
    );

    const hashOk =
      typeof gl.hash === "string" && gl.hash.length >= 8 && gl.hash !== "0";
    const noContext = gl.ok === false;
    add(
      "webgl_render_probe",
      hashOk || !noContext,
      noContext
        ? "no webgl context"
        : hashOk
          ? `hash=${gl.hash.slice(0, 12)}`
          : "empty render",
      false,
    );

    const webgl2Phantom = gl.webgl2 === false && chromium && !mobile;
    add(
      "webgl2_absent_on_chromium",
      !webgl2Phantom,
      webgl2Phantom ? "webgl2 missing on chromium desktop" : "ok",
      false,
    );

    // Platform vs GPU renderer cross-check. A UA that claims a mobile device
    // but reports a desktop GPU, or claims Windows while navigator.platform
    // and the GPU string scream Linux/Mac, is a strong spoofing signal that
    // survives because it lives in two different subsystems. Legitimate users
    // score high enough that a single flag here never blocks them.
    const combo = `${vendor} ${renderer}`;
    const gpuApple = /apple|metal|m1|m2|m3|m4/i.test(combo);
    const gpuLinux = /mesa|llvmpipe|amdgpu|nouveau/i.test(combo);
    const gpuWindows = /direct3d|d3d11|angle \(nvidia|geforce|quadro|rtx/i.test(
      combo,
    );
    const gpuAndroid = /adreno|mali|powervr|tegra/i.test(combo);
    let platformGpuMismatch = false;
    let pgDetail = "";
    if (os === "android" || os === "ios") {
      // Mobile should not expose a desktop-only GPU family.
      if (gpuApple && os === "android") {
        platformGpuMismatch = true;
        pgDetail = "android declared, Apple GPU";
      } else if (
        (gpuWindows || /geforce|quadro|rtx/i.test(combo)) &&
        !gpuAndroid
      ) {
        platformGpuMismatch = true;
        pgDetail = `${os} declared, desktop GPU`;
      }
    } else if (os === "windows" && gpuLinux && !/swiftshader/i.test(combo)) {
      platformGpuMismatch = true;
      pgDetail = "windows declared, Linux GL stack";
    } else if ((os === "macos" || os === "linux") && gpuWindows && !gpuApple) {
      // macOS should never report Direct3D/ANGLE-on-D3D.
      if (os === "macos") {
        platformGpuMismatch = true;
        pgDetail = "macos declared, D3D backend";
      }
    }
    if (combo.trim()) {
      add(
        "platform_gpu_mismatch",
        !platformGpuMismatch,
        platformGpuMismatch ? pgDetail : "consistent",
      );
    }
  }

  // Canvas read-back sanity. An all-zero / constant hash means the canvas was
  // never actually rasterized (common in stripped headless contexts).
  if (typeof S.canvas === "string") {
    const degenerate = S.canvas === "" || /^0+$/.test(S.canvas);
    add(
      "canvas_degenerate",
      !degenerate,
      degenerate ? "empty canvas hash" : `hash=${S.canvas.slice(0, 12)}`,
      false,
    );
  }

  // AudioContext fingerprint. A null result is expected on some locked-down
  // browsers, but a CPU-only / virtualized audio stack tends to produce the
  // exact constant stream. We flag only an explicitly repeated "silent" value.
  if (isNum(S.audio)) {
    const silent = S.audio === 0;
    add("audio_silent", !silent, silent ? "silent output" : "ok", false);
  }

  // Emoji rendering. Two things:
  //  1) emoji_no_render: no glyph metrics at all — an environment fact (stripped
  //     rasterizer), independent of any OS claim.
  //  2) emoji_os_mismatch: style vs declared OS. This is only meaningful on
  //     desktop, where Apple/Segoe/Noto stacks differ predictably. On Android/iOS
  //     emoji fonts vary wildly across devices and OEM ROMs (many Android ROMs
  //     ship Apple-style emoji), so we never flag mobile here — it misfires on
  //     legitimate phones.
  if (isPlainObject(S.emoji)) {
    const style = String(S.emoji.style || "");
    const width = isNum(S.emoji.width) ? S.emoji.width : null;
    add(
      "emoji_no_render",
      width !== 0 && width !== null,
      width === 0 || width === null ? "no glyph metrics" : `width=${width}`,
      false,
    );

    const mobileOs = os === "android" || os === "ios";
    if (os && !mobileOs) {
      // Apple color emoji is wider than Segoe/Noto stacks on desktop.
      const appleLike = width !== null ? width >= 110 : style === "apple-like";
      let mismatched = false;
      if (os === "macos") mismatched = !appleLike;
      else if (os === "windows" || os === "linux") mismatched = appleLike;
      add(
        "emoji_os_mismatch",
        !mismatched,
        mismatched ? `declared ${os}, width ${width}` : "match",
        false,
      );
    }
  }

  // Hardware shape: a lone core (desktop) or an implausibly high core count
  // (mobile) are typical of tiny VM instances and spoofed values. A mobile UA
  // claiming more cores than any shipping phone has is a strong tell.
  if (isNum(S.hardwareConcurrency)) {
    const hc = S.hardwareConcurrency;
    const odd = hc > 0 && hc % 2 === 1 && hc !== 1;
    const tooSmall = hc === 1 && !mobile;
    const tooManyForMobile = hc > 12 && mobile;
    add(
      "hardware_shape",
      !(odd || tooSmall || tooManyForMobile),
      odd || tooSmall || tooManyForMobile
        ? `hardwareConcurrency=${hc}${mobile ? " (mobile)" : ""}`
        : "ok",
      false,
    );
  }

  // Core count vs device memory mismatch: a device advertising many cores but
  // minimal RAM (or the reverse) is a classic container profile.
  const mem = isNum(S.deviceMemory) ? S.deviceMemory : null;
  if (isNum(S.hardwareConcurrency) && mem !== null) {
    const hc = S.hardwareConcurrency;
    const mismatched = (hc >= 8 && mem <= 1) || (hc <= 2 && mem >= 16);
    add(
      "hw_mem_mismatch",
      !mismatched,
      mismatched ? `cores=${hc}, deviceMemory=${mem}` : "ok",
      false,
    );
  }

  // Rendering pipeline availability. If the challenge asked for the render
  // probes (webgl/canvas/audio/emoji) but every one came back empty, the
  // environment has no working GPU / rasterizer / audio stack — the profile of
  // a headless or VM browser. Hardened real browsers can disable one of these,
  // but all at once is a strong "not a full desktop browser" signal.
  const renderProbes = (opts.optionalFields || []).filter((f) =>
    ["webgl", "canvas", "audio", "emoji"].includes(f),
  );
  if (renderProbes.length >= 2) {
    // Distinguish "probe did not run" (null/undefined — e.g. the sandboxed
    // iframe could not execute it, or it timed out) from "probe ran and the
    // pipeline failed" (WebGL object with ok:false, empty canvas string). Only
    // the latter is evidence. Require >=2 probes that actually ran, all failed,
    // and WebGL among them — otherwise it is noise.
    const ran = renderProbes.filter((f) => S[f] !== null && S[f] !== undefined);
    const failed = (f) => {
      const v = S[f];
      if (f === "webgl")
        return !!(v && typeof v === "object" && v.ok === false);
      if (f === "canvas") return v === "";
      if (f === "emoji") return !!(v && typeof v === "object" && v.width === 0);
      return false; // audio: null means "no output", too ambiguous to judge
    };
    const allRanFailed =
      ran.length >= 2 && // at least two probes actually executed
      ran.includes("webgl") &&
      ran.every(failed);
    add(
      "render_pipeline_absent",
      !allRanFailed,
      allRanFailed
        ? `all failed: ${renderProbes.join("/")}`
        : ran.length === 0
          ? "probes not executed"
          : `${ran.length}/${renderProbes.length} ran`,
      false,
    );
  }

  // Storage quota rounding. Browsers expose large, power-of-two-ish quotas;
  // a hard cap (0 or a tiny round number) indicates a sandboxed container.
  if (isNum(S.storageQuota)) {
    const tiny = S.storageQuota > 0 && S.storageQuota < 1024 * 1024;
    add(
      "storage_quota_tiny",
      !tiny,
      tiny ? `quota=${S.storageQuota}` : "ok",
      false,
    );
  }

  const failed = checks.filter((c) => c.gating && !c.passed);
  return {
    pass: failed.length === 0,
    checks,
    blockedBy: failed.map((c) => c.id),
    riskFlags: checks.filter((c) => !c.gating && !c.passed).map((c) => c.id),
  };
}
