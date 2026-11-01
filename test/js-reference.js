import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

// The external reference implementation is not part of this repository.
export function referenceUrl(file) {
  const core = process.env.CAP_JS_CORE_DIR;
  if (!core || process.env.CAP_SKIP_JS_PARITY === "1") {
    if (process.env.CAP_SKIP_JS_PARITY !== "1" && process.env.CAP_REQUIRE_JS_PARITY === "1") {
      throw new Error("CAP_REQUIRE_JS_PARITY=1 requires CAP_JS_CORE_DIR pointing to the external JS core directory");
    }
    console.warn(`SKIP JS reference ${file}: set CAP_JS_CORE_DIR to enable`);
    return null;
  }
  const target = resolve(core, "src", file);
  if (!existsSync(target)) {
    throw new Error(`CAP_JS_CORE_DIR reference file not found: ${target}`);
  }
  return pathToFileURL(target).href;
}
