import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const widgetMin = fs.readFileSync(
  path.join(__dirname, "..", "..", "widget-dist", "widget.js"),
  "utf-8",
);
export const wasmBytes = fs.readFileSync(
  path.join(
    __dirname,
    "..",
    "..",
    "widget-dist",
    "cap_wasm_bg.wasm",
  ),
);

export function makeBaseHandler({ onChallenge, onRedeem, html }) {
  return async (req) => {
    const url = new URL(req.url);
    if (req.method === "POST" && /\/(challenge|redeem)$/.test(url.pathname)) {
      const body = await req.clone().json();
      if (body.businessToken !== "e2e-business-fixture") return Response.json({ error: "invalid business fixture" }, { status: 403 });
    }
    if (url.pathname === "/widget.js") {
      return new Response(widgetMin, {
        headers: { "Content-Type": "application/javascript" },
      });
    }
    if (url.pathname === "/cap_wasm_bg.wasm") {
      return new Response(wasmBytes, {
        headers: { "Content-Type": "application/wasm" },
      });
    }
    if (url.pathname === "/" && html) {
      return new Response(html, { headers: { "Content-Type": "text/html" } });
    }
    if (url.pathname === "/cap/challenge" && req.method === "POST") {
      return Response.json(await onChallenge());
    }
    if (url.pathname === "/cap/redeem" && req.method === "POST") {
      const body = await req.json();
      return await onRedeem(body);
    }
    return new Response("not found", { status: 404 });
  };
}

export function setLocalWasmHtml(html) {
  return html.replace(
    "</head>",
    `<script>window.CAP_CUSTOM_WASM_URL = "/cap_wasm_bg.wasm";</script></head>`,
  );
}
