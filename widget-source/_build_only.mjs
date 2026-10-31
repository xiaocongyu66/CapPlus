import fs from "node:fs/promises";
import JavaScriptObfuscator from "javascript-obfuscator";
import { transform } from "lightningcss";
import { minify } from "terser";
import {
  keys,
  shipped,
  shippedKeys,
  translations,
} from "./src/src/i18n/translations.js";

const minifyCSS = (input) => {
  const { code } = transform({
    filename: "cap.css",
    code: Buffer.from(input),
    minify: true,
    targets: {
      chrome: 90 << 16,
      firefox: 90 << 16,
      safari: (14 << 16) | (1 << 8),
    },
  });
  return code.toString();
};

for (const [code, row] of Object.entries(translations)) {
  if (Array.isArray(row) && row.length !== keys.length) {
    throw new Error("i18n " + code + ": " + row.length + " strings, expected " + keys.length);
  }
}

const minifyJS = async (input) => {
  return (
    await minify(input, {
      compress: {
        drop_console: false,
        dead_code: true,
        reduce_vars: true,
      },
      output: {
        beautify: false,
        comments: false,
      },
      mangle: true,
    })
  ).code
    .split("\n")
    .map((e) => {
      return e.trimStart();
    })
    .join("\n");
};

console.time("build");

const rawMain = await fs.readFile("./src/src/cap.js", "utf-8");
const rawCSS = await fs.readFile("./src/src/cap.css", "utf-8");
const minifiedWorker = await minifyJS(
  await fs.readFile("./src/src/worker.js", "utf-8"),
);
const minifiedCSS = minifyCSS(rawCSS);

const keepIdx = shippedKeys.map((k) => {
  const i = keys.indexOf(k);
  if (i === -1) throw new Error(`shippedKey '${k}' not in keys`);
  return i;
});
const i18nRows = {};
for (const code of shipped) {
  if (!translations[code])
    throw new Error(`shipped lang '${code}' missing from translations`);
  const vals = keepIdx.map((i) => translations[code][i]);
  const bad = vals.find((v) => v.includes("/"));
  if (bad) throw new Error(`'${code}' string contains the "/" delimiter: ${bad}`);
  i18nRows[code] = vals.join("/");
}
const i18nJSON = JSON.stringify(i18nRows);
console.log(
  `i18n: ${shipped.length} langs x ${shippedKeys.length} keys, ${i18nJSON.length}B raw`,
);

const bundle = rawMain
  .replace("%%workerScript%%", () => JSON.stringify(minifiedWorker))
  .replace("%%capCSS%%", () => minifiedCSS)
  .replace("%%i18nKeys%%", () => shippedKeys.join(","))
  .replace("%%i18nData%%", () => i18nJSON);

// Obfuscate the shipped widget. Conservative config on purpose: we want to
// raise the reverse-engineering cost without breaking Web Components. We AVOID
// controlFlowFlattening/deadCodeInjection (they can break class fields, async
// iteration and shadow DOM logic) and keep a stable output so the integrity
// hash is reproducible per build. String array + identifier mangling only.
const obfuscateJS = (code) =>
  JavaScriptObfuscator.obfuscate(code, {
    // Deterministic output so the integrity hash is reproducible per build.
    seed: Number(process.env.OBF_SEED || 20260101),
    compact: true,
    identifierNamesGenerator: "mangled-shuffled",
    renameGlobals: false,
    stringArray: true,
    stringArrayThreshold: 0.75,
    stringArrayEncoding: ["base64"],
    stringArrayRotate: true,
    stringArrayShuffle: true,
    splitStrings: true,
    splitStringsChunkLength: 8,
    controlFlowFlattening: false,
    deadCodeInjection: false,
    selfDefending: false,
    debugProtection: false,
    disableConsoleOutput: false,
  }).getObfuscatedCode();

// Obfuscate first, then terser-minify, and write ONLY the final artifact so a
// mid-way failure can never publish an unobfuscated bundle.
const obfuscated = obfuscateJS(bundle);
await fs.writeFile("./src/cap.min.js", await minifyJS(obfuscated));

await fs.writeFile(
  "./src/cap-floating.min.js",
  await minifyJS(await fs.readFile("./src/src/cap-floating.js", "utf-8")),
);

console.timeEnd("build");
