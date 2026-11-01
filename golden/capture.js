// Captures a real widget-generated instrumentation payload + challenge from the
// JS stack, so the Rust detect/instr ports can be diffed against ground truth.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const CHROME = process.env.CHROME_BIN || "chromium", PORT = 9281, TO = "http://localhost:4000/";
const OUT = fileURLToPath(new URL("./instr-sample.json", import.meta.url));
const profile = mkdtempSync(join(tmpdir(), "cap-gold-"));
process.on("exit", () => rmSync(profile, { recursive: true, force: true }));
const proc = Bun.spawn([CHROME, `--remote-debugging-port=${PORT}`, "--headless=new", "--no-sandbox", "--disable-dev-shm-usage", `--user-data-dir=${profile}`, "about:blank"], { stdout: "ignore", stderr: "ignore" });
const sleep = (ms) => Bun.sleep(ms);
for (let i = 0; i < 100; i++) { try { if ((await fetch(`http://127.0.0.1:${PORT}/json/version`)).ok) break; } catch {} await sleep(200); }
let page; for (let i = 0; i < 40 && !page; i++) { const t = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json(); page = t.find((x) => x.type === "page"); if (!page) await sleep(250); }
const ws = new WebSocket(page.webSocketDebuggerUrl); await new Promise((r) => ws.addEventListener("open", r));
let id = 0; const pend = new Map();
ws.addEventListener("message", (e) => { const m = JSON.parse(e.data); if (m.id && pend.has(m.id)) { pend.get(m.id)(m.result); pend.delete(m.id); } });
const send = (method, params = {}) => new Promise((res) => { const i = ++id; pend.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (x) => (await send("Runtime.evaluate", { expression: x, returnByValue: true, awaitPromise: true }))?.result?.value;
await send("Page.enable"); await send("Runtime.enable");
await send("Page.addScriptToEvaluateOnNewDocument", { source: `(function(){var of=window.fetch;window.fetch=function(u,o){var url=(typeof u==='string'?u:(u&&u.url)||'')+'';if(url.indexOf('/challenge')!==-1)of.call(this,u,o).then(r=>r.clone().json().then(j=>{window.__CH__=j}).catch(()=>{})).catch(()=>{});if(url.indexOf('/redeem')!==-1&&o&&typeof o.body==='string'){try{(window.__REQS__=window.__REQS__||[]).push(o.body)}catch(e){}}return of.apply(this,arguments);};})();` });
await send("Page.navigate", { url: TO }); await sleep(4000);
let x0 = 300, y0 = 300;
for (let i = 0; i < 40; i++) { const t = i / 40; x0 = 300 + Math.sin(t * 6.28) * 10; y0 = 300 + Math.cos(t * 4.7) * 6; await send("Input.dispatchMouseEvent", { type: "mouseMoved", x: x0, y: y0, button: "none" }); await sleep(16); }
await send("Input.dispatchMouseEvent", { type: "mousePressed", x: 300, y: 300, button: "left", clickCount: 1 }); await sleep(80);
await send("Input.dispatchMouseEvent", { type: "mouseReleased", x: 300, y: 300, button: "left", clickCount: 1 });
// Kick the widget programmatically (clicking alone is flaky in headless).
console.log("solve:", await ev("document.getElementById('cap').solve().then(()=> 'ok').catch(e=>'err:'+((e&&e.message)||e))"));
let reqs = null; for (let i = 0; i < 70; i++) { await sleep(1000); reqs = await ev("window.__REQS__||null"); if (reqs && reqs.length) break; }
const ch = await ev("window.__CH__||null");
const bodies = (reqs || []).map((b) => JSON.parse(b));
const instr = bodies.map((b) => (b.solutions || []).map((s) => s && s.instr).find(Boolean)).find(Boolean);
const out = { capturedAt: new Date().toISOString(), challenge: ch ? { format: ch.format, protocols: (ch.challenges || []).map((c) => c.protocol), nonce: !!ch.nonce } : null, instr: instr || null, solutions: bodies[0]?.solutions || null, integrity: bodies[0]?.integrity || null };
await Bun.write(OUT, JSON.stringify(out, null, 2));
console.log("captured:", OUT, "instr?", !!instr, "p keys:", instr ? Object.keys(instr.p || {}).length : 0);
ws.close(); proc.kill(); process.exit(0);
