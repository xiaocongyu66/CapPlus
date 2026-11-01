import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { referenceUrl } from "../../test/js-reference.js";
const reference = referenceUrl("prng.js");
const { prng } = reference ? await import(reference) : {};

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const widgetSource = fs.readFileSync(
  path.join(__dirname, "..", "src", "src", "cap.js"),
  "utf-8",
);

describe("widget source structure", () => {
  test("has prng function", () => {
    expect(widgetSource).toMatch(/function prng\(seed, length\)/);
  });

  test("has runInstrumentationChallenge function", () => {
    expect(widgetSource).toMatch(/runInstrumentationChallenge/);
  });

  test("instrumentation message handler validates ev.source against iframe.contentWindow", () => {
    expect(widgetSource).toMatch(
      /ev\.source !== iframe\.contentWindow/,
    );
  });

  test("speculative-solve trigger threshold matches expected value", () => {
    expect(widgetSource).toMatch(/SPECULATIVE_DELAY_MS = 2500/);
  });

  test("includes %%workerScript%% placeholder for build step", () => {
    expect(widgetSource).toContain("%%workerScript%%");
  });

  test("data-cap-hidden-field-name default is 'cap-token'", () => {
    expect(widgetSource).toMatch(
      /getAttribute\("data-cap-hidden-field-name"\) \|\| "cap-token"/,
    );
  });

  test("registers Cap as a custom element", () => {
    expect(widgetSource).toMatch(/customElements\.define\(["']cap-widget["']/);
  });
});

(prng ? describe : describe.skip)("widget prng matches capjs-core prng", () => {
  function widgetPrng(seed, length) {
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

  test("matches over many seed/length combos", () => {
    const seeds = [
      "abc",
      "deadbeef",
      "tokensampleX1",
      "tokensampleX1d",
      `${"f".repeat(50)}1`,
      "0",
    ];
    for (const seed of seeds) {
      for (const len of [1, 4, 8, 16, 32, 64, 128]) {
        expect(widgetPrng(seed, len)).toBe(prng(seed, len));
      }
    }
  });
});

describe("worker script structure", () => {
  const workerSource = fs.readFileSync(
    path.join(__dirname, "..", "src", "src", "worker.js"),
    "utf-8",
  );

  test("worker exports message handler", () => {
    expect(workerSource).toMatch(/onmessage|addEventListener\(["']message["']/);
  });

  test("worker has scalar SHA-256 fallback for environments without WASM SIMD", () => {
    expect(workerSource).toMatch(/sha256|SHA-256|S256|0x6a09e667/i);
  });
});

describe("regression: shadow root re-attach guard (#243-ish)", () => {
  test("connectedCallback checks if shadowRoot already exists", () => {
    expect(widgetSource).toMatch(
      /if \(!this\.shadowRoot\) \{[\s\S]*?attachShadow/,
    );
  });
});

describe("regression: token sometimes not returned (widget@0.1.40)", () => {
  // The field name comes from `data-cap-hidden-field-name`, so it is
  // host-page controlled. Interpolated raw it could close the attribute
  // selector (`x'][name='other`) and resolve to a different input, sending the
  // token to the wrong field. Behavioural coverage lives in e2e.test.js
  // ("hidden field") and e2e-regression.test.js ("custom name"); this asserts
  // the escaping invariant that those cannot express.
  test("field name is CSS-escaped in the hidden-input selector", () => {
    expect(widgetSource).not.toMatch(
      /querySelector\(\s*`input\[name='\$\{this\.#fieldName\}'\]`\s*\)/,
    );
    expect(widgetSource).toMatch(
      /querySelector\(\s*`input\[name='\$\{CSS\.escape\(this\.#fieldName\)\}'\]`\s*\)/,
    );
  });

  test("setToken writes the token into the resolved input", () => {
    expect(widgetSource).toMatch(
      /#setToken\(value\)\s*\{[\s\S]*?const input =[\s\S]*?this\.#tokenInput[\s\S]*?if \(input\) input\.value = value;/,
    );
  });

  test("hidden input is created with the configured field name", () => {
    expect(widgetSource).toMatch(/#tokenInput\.name = this\.#fieldName/);
  });

  test("hidden input is set before solve event is dispatched", () => {
    expect(widgetSource).toMatch(/#setToken\([\s\S]*?dispatchEvent\("solve"/);
  });
});

describe("regression: validity / required attribute (#227)", () => {
  test("uses ElementInternals.setValidity for form-associated invalid state", () => {
    expect(widgetSource).toMatch(/static formAssociated = true/);
    expect(widgetSource).toMatch(/setValidity/);
  });
});
