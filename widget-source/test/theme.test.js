import { afterAll, beforeAll, expect, test, setDefaultTimeout } from "bun:test";
setDefaultTimeout(60000);
import { chromium } from "playwright";
import { readFile } from "node:fs/promises";

// Exercise the actual release widget and the Rust loader, not source markers.
const widget = await readFile(new URL("../../widget-dist/widget.js", import.meta.url), "utf8");
const generator = Bun.spawn(["cargo", "run", "--quiet", "--locked", "--manifest-path", new URL("../../Cargo.toml", import.meta.url).pathname, "-p", "cap-embed", "--example", "browser_fixture"], { stdout: "pipe", stderr: "inherit" });
const fixtureText = await new Response(generator.stdout).text();
if (await generator.exited !== 0) throw new Error("Rust iframe fixture generation failed");
const fixtures = JSON.parse(fixtureText);
const loader = fixtures.loader;
const wasm = await readFile(new URL("../../widget-dist/cap_wasm_bg.wasm", import.meta.url));
const hashwx = await readFile(new URL("../../widget-dist/hashwx.wasm", import.meta.url));
let browser;
beforeAll(async () => {
  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || "/bin/chromium", args: ["--no-sandbox"] });
});
afterAll(async () => { await browser?.close(); });

async function checkpoint(page) {
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}

async function setup(embed = false) {
  const page = await browser.newPage({ colorScheme: "light" });
  page.externalRequests = [];
  await page.route("**/*", route => { page.externalRequests.push(route.request().url()); return route.abort(); });
  await page.route("https://page.test/**", route => route.fulfill({ contentType: "text/html", body: "<!doctype html><html><head></head><body></body></html>" }));
  page.assetRequests = [];
  page.frameNavigations = 0;
  page.on("framenavigated", frame => { if (frame.url().startsWith("https://cap.test/embed/")) page.frameNavigations++; });
  await page.route("https://cap.test/**", async route => {
    const url = new URL(route.request().url());
    page.assetRequests.push(url.pathname);
    if (url.pathname.startsWith("/embed/")) return route.fulfill({ contentType: "text/html", body: fixtures[url.searchParams.get("theme") === "light" ? "light" : "dark"] });
    if (url.pathname === "/assets/widget.js") return route.fulfill({ contentType: "application/javascript", body: widget });
    if (url.pathname === "/assets/cap_wasm_bg.wasm") return route.fulfill({ contentType: "application/wasm", body: wasm });
    if (url.pathname === "/assets/hashwx.wasm") return route.fulfill({ contentType: "application/wasm", body: hashwx });
    if (url.pathname === "/site/challenge") return route.fulfill({ json: { format: 2, token: "fixture-challenge", challenges: [
      { protocol: "sha256-pow", payload: { salt: "theme-test", target: "0" } },
      { protocol: "hashwx", payload: { c: "a".repeat(64), d: 1, n: 1 } },
    ] } });
    if (url.pathname === "/site/redeem") return route.fulfill({ json: { success: true, token: "verified-fixture-token", expires: new Date(Date.now() + 60000).toISOString() } });
    if (url.pathname === "/loader.js") return route.fulfill({ contentType: "application/javascript", body: loader });
    return route.abort();
  });
  await page.goto("https://page.test/");
  if (embed) await page.evaluate(() => {
    window.messageListeners = new Set();
    const add = window.addEventListener, remove = window.removeEventListener;
    window.addEventListener = function(type, listener, options) {
      if (type === "message") messageListeners.add(listener);
      return add.call(this, type, listener, options);
    };
    window.removeEventListener = function(type, listener, options) {
      if (type === "message") messageListeners.delete(listener);
      return remove.call(this, type, listener, options);
    };
  });
  if (embed) await page.addScriptTag({ url: "https://cap.test/loader.js" });
  else await page.addScriptTag({ content: widget });
  await page.evaluate(embed => {
    for (const id of ["a", "b"]) {
      const el = document.createElement(embed ? "cap-embed" : "cap-widget");
      el.id = id;
      el.setAttribute("data-cap-worker-count", "1");
      el.setAttribute(embed ? "data-site-key" : "data-cap-api-endpoint", embed ? "site" : "/site/");
      document.body.append(el);
    }
  }, embed);
  return page;
}

test("real iframe: local WASM, receiver guards, solved state survives theme changes", async () => {
  const page = await setup(true);
  try {
    const frame = page.frameLocator("#a iframe");
    await frame.locator("cap-widget .captcha").waitFor();
    await page.frameLocator("#b iframe").locator("cap-widget .captcha").waitFor();
    await frame.locator("cap-widget").evaluate(el => el.setAttribute("data-cap-worker-count", "1"));
    const navigations = page.frameNavigations;
    await page.evaluate(() => { window.loads = 0; document.querySelectorAll("iframe").forEach(f => f.addEventListener("load", () => loads++)); });
    // Real worker/WASM solves; only the challenge/redeem HTTP backend is a fixture.
    const solved = await frame.locator("cap-widget").evaluate(el => el.solve());
    expect(solved.success).toBe(true);
    expect(page.assetRequests).toContain("/assets/cap_wasm_bg.wasm");
    expect(page.assetRequests).toContain("/assets/hashwx.wasm");
    await checkpoint(page);
    expect(await page.$eval("#a input", el => el.value)).toBe("verified-fixture-token");
    await frame.locator("cap-widget").evaluate(() => {
      for (const [origin, source] of [["https://evil.test", parent], ["https://page.test", window]]) {
        window.dispatchEvent(new MessageEvent("message", { origin, source, data: { type: "cap:theme", theme: "light" } }));
      }
    });
    expect(await frame.locator("html").getAttribute("data-theme")).toBe("dark");
    await page.evaluate(() => { document.body.dataset.theme = "light"; });
    await frame.locator('cap-widget[data-cap-resolved-theme="light"]').waitFor();
    expect(await frame.locator("cap-widget .captcha").evaluate(el => getComputedStyle(el).backgroundColor)).toBe("rgb(253, 253, 253)");
    expect(await frame.locator("cap-widget").evaluate(el => el.tokenValue)).toBe("verified-fixture-token");
    expect(await page.$eval("#a input", el => el.value)).toBe("verified-fixture-token");
    expect(await frame.locator("cap-widget .captcha").getAttribute("data-state")).toBe("done");
    expect(page.frameNavigations).toBe(navigations);
    expect(await page.evaluate(() => loads)).toBe(0);
    expect(page.externalRequests).toEqual([]);
  } finally { await page.close(); }
});

test("custom widget URL keeps deployment asset contract", async () => {
  const page = await browser.newPage();
  try {
    let customRequests = 0;
    await page.route("https://custom.test/widget.js", route => { customRequests++; return route.fulfill({ contentType: "application/javascript", body: "window.customLoaded = true" }); });
    await page.route("https://cap.test/custom", route => route.fulfill({ contentType: "text/html", body: fixtures.custom }));
    await page.goto("https://cap.test/custom");
    expect(customRequests).toBe(1);
    expect(await page.evaluate(() => [window.customLoaded, window.CAP_CUSTOM_WASM_URL, window.CAP_CUSTOM_HASHWX_URL])).toEqual([true, undefined, undefined]);
  } finally { await page.close(); }
});

for (const embed of [false, true]) {
  test(`${embed ? "embed" : "standalone"}: page precedence, dynamic theme, remount`, async () => {
    const page = await setup(embed);
    try {
      const theme = async () => {
        if (!embed) return page.$eval("#a", el => el.getAttribute("data-cap-resolved-theme"));
        const frame = page.frameLocator("#a iframe");
        await frame.locator("cap-widget .captcha").waitFor();
        // Wait for the actual postMessage receiver, not the iframe URL.
        await page.evaluate(() => CapEmbed.refreshTheme());
        await page.evaluate(() => new Promise(resolve => setTimeout(resolve, 25)));
        return frame.locator("cap-widget").getAttribute("data-cap-resolved-theme");
      };
      expect(await theme()).toBe("dark"); // system light is deliberately ignored
      await page.emulateMedia({ colorScheme: "dark" });
      await page.evaluate(() => { document.body.style.backgroundColor = "white"; });
      expect(await theme()).toBe("dark");
      await page.emulateMedia({ colorScheme: "light" });
      await page.evaluate(() => { document.body.style.backgroundColor = "black"; });
      expect(await theme()).toBe("dark");
      await page.evaluate(() => { document.documentElement.style.colorScheme = "normal"; document.body.style.colorScheme = "light"; });
      expect(await theme()).toBe("light");
      await page.evaluate(() => { document.documentElement.style.colorScheme = "light dark"; });
      expect(await theme()).toBe("light");
      await page.evaluate(() => { document.body.style.colorScheme = "only light"; });
      expect(await theme()).toBe("light");
      await page.evaluate(() => { document.body.style.colorScheme = "only dark"; });
      expect(await theme()).toBe("dark");
      await page.evaluate(() => { document.body.style.colorScheme = "only light"; document.documentElement.style.colorScheme = "only dark"; });
      expect(await theme()).toBe("dark");
      await page.evaluate(() => { document.documentElement.style.colorScheme = "light only"; document.body.style.colorScheme = "dark only"; });
      expect(await theme()).toBe("light");
      await page.evaluate(() => { document.body.className = "dark"; });
      expect(await theme()).toBe("dark");
      await page.evaluate(() => { document.body.dataset.theme = "light"; });
      expect(await theme()).toBe("light");
      await page.evaluate(() => { document.documentElement.dataset.theme = "dark"; });
      expect(await theme()).toBe("dark"); // root attribute wins body attribute
      await page.evaluate(() => { delete document.documentElement.dataset.theme; document.documentElement.className = "dark"; });
      expect(await theme()).toBe("light"); // body attribute wins root class
      await page.evaluate(() => { document.documentElement.className = ""; });
      await page.evaluate(() => { document.getElementById("a").dataset.capTheme = "dark"; });
      expect(await theme()).toBe("dark");
      await page.evaluate(() => { document.getElementById("a").removeAttribute("data-cap-theme"); });
      expect(await theme()).toBe("light");
      if (!embed) {
        expect(await page.$eval("#a", el => el.hasAttribute("data-cap-theme"))).toBe(false);
        expect(await page.$eval("#a", el => getComputedStyle(el.shadowRoot.querySelector(".captcha")).backgroundColor)).toBe("rgb(253, 253, 253)");
      }
      await page.evaluate(() => { window.saved = document.getElementById("a"); saved.remove(); });
      await page.evaluate(() => { document.body.dataset.theme = "dark"; document.body.append(saved); });
      expect(await theme()).toBe("dark");
      expect(await page.$eval("#a", el => el.querySelectorAll("input").length)).toBe(1);
      await page.evaluate(embed => {
        document.documentElement.removeAttribute("style");
        document.body.removeAttribute("style");
        document.body.removeAttribute("class");
        document.body.removeAttribute("data-theme");
        const style = document.createElement("style"); document.head.append(style);
        style.sheet.insertRule("html { color-scheme: only light; }");
        if (embed) CapEmbed.refreshTheme(); else document.getElementById("a").refreshTheme();
      }, embed);
      expect(await theme()).toBe("light");
    } finally { await page.close(); }
  });
}

test("embed: isolated messages, no reload on theme update, cleanup", async () => {
  const page = await setup(true);
  try {
    await page.frameLocator("#a iframe").locator("cap-widget .captcha").waitFor();
    await page.frameLocator("#b iframe").locator("cap-widget .captcha").waitFor();
    await page.evaluate(() => {
      window.framesBefore = [...document.querySelectorAll("iframe")];
      const a = document.getElementById("a"), b = document.getElementById("b");
      const send = (origin, source, siteKey, token) => window.dispatchEvent(new MessageEvent("message", { origin, source, data: { type: "cap:token", siteKey, token } }));
      send("https://evil.test", a.querySelector("iframe").contentWindow, "site", "bad");
      send("https://cap.test", window, "site", "bad");
      send("https://cap.test", a.querySelector("iframe").contentWindow, "other", "bad");
    });
    expect(await page.$$eval("input", els => els.map(el => el.value))).toEqual(["", ""]);
    await page.evaluate(() => {
      window.dispatchEvent(new MessageEvent("message", { origin: "https://cap.test", source: framesBefore[0].contentWindow, data: { type: "cap:token", siteKey: "site", token: "good" } }));
      document.body.dataset.theme = "light";
    });
    expect(await page.$$eval("input", els => els.map(el => el.value))).toEqual(["good", ""]);
    await page.frameLocator("#a iframe").locator('html[data-theme="light"]').waitFor();
    await page.frameLocator("#b iframe").locator('html[data-theme="light"]').waitFor();
    await page.evaluate(() => CapEmbed.setTheme(document.getElementById("b"), "dark"));
    await page.frameLocator("#b iframe").locator('html[data-theme="dark"]').waitFor();
    await page.frameLocator("#a iframe").locator('html[data-theme="light"]').waitFor();
    expect(await page.evaluate(() => framesBefore.every((frame, i) => frame === document.querySelectorAll("iframe")[i]))).toBe(true);
    await page.evaluate(() => { window.saved = document.getElementById("a"); window.observer = saved.__capThemeObserver; saved.remove(); });
    expect(await page.evaluate(() => !saved.__capEmbed && !saved.__capThemeObserver && saved.children.length === 0)).toBe(true);
    expect(await page.evaluate(() => messageListeners.size)).toBe(1);
    await page.evaluate(() => document.body.append(saved));
    expect(await page.$eval("#a", el => el.querySelectorAll("iframe").length)).toBe(1);
    expect(await page.evaluate(() => messageListeners.size)).toBe(2);
    await page.evaluate(() => {
      window.oldFrame = saved.querySelector("iframe").contentWindow;
      CapEmbed.destroy(saved);
      CapEmbed.destroy(saved);
    });
    // Multiple event-loop / mutation observer checkpoints with no explicit scan.
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    expect(await page.$eval("#a", el => el.children.length)).toBe(0);
    expect(await page.evaluate(() => messageListeners.size)).toBe(1);
    await page.evaluate(() => CapEmbed.mount(saved));
    await page.evaluate(() => window.dispatchEvent(new MessageEvent("message", {
      origin: "https://cap.test", source: oldFrame,
      data: { type: "cap:token", siteKey: "site", token: "stale" },
    })));
    expect(await page.$eval("#a input", el => el.value)).toBe("");
  } finally { await page.close(); }
});
