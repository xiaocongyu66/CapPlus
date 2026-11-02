"""Exercise generated Node and browser bindings, not a Rust test adapter."""
import functools
import hashlib
import http.server
import json
import os
import pathlib
import subprocess
import sys
import threading

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parents[2]
NODE = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "wasm-source/src/node"
WEB = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "widget-dist"
INVALID = ["aaaaaaaé", "aaaaaa€", "aaaaa\U0001f600", "é", "0123456789abcdeg",
           "+1", "-1", " 1", "1\u0000", "0" * 17, "a" * 4096]
# Hash of salt + zero: covers every legal prefix length without costly searches.
PREFIX = hashlib.sha256(b"salt0").hexdigest()[:16]
CASES = [["salt", ""], *[["salt", PREFIX[:n]] for n in range(1, 17)],
         *[["salt", PREFIX[:n].upper()] for n in range(1, 17)],
         ["simd-validation", "aBc"]]
RUN = """(solve, invalid, cases) => {
  for (const target of invalid) {
    let trapped = false;
    try { solve('salt', target); }
    catch (error) {
      if (!(error instanceof WebAssembly.RuntimeError)) throw error;
      trapped = true;
    }
    if (!trapped) throw new Error('invalid target returned a nonce: ' + target);
  }
  return cases.map(([salt, target]) => solve(salt, target).toString());
}"""


def verify(values):
    assert len(values) == len(CASES)
    for (salt, target), value in zip(CASES, values):
        nonce = int(value)
        assert hashlib.sha256(f"{salt}{nonce}".encode()).hexdigest().startswith(target.lower())
    assert all(value == "0" for value in values[:-1])
    nonce = int(values[-1])
    assert nonce >= 16
    assert all(not hashlib.sha256(f"simd-validation{n}".encode()).hexdigest().startswith("abc")
               for n in range(nonce))


node_program = f"""
const {{ solve_pow }} = require({json.dumps(str(NODE / 'cap_wasm.js'))});
console.log(JSON.stringify(({RUN})(solve_pow, {json.dumps(INVALID)}, {json.dumps(CASES)})));
"""
verify(json.loads(subprocess.check_output(["node", "-e", node_program], text=True, timeout=30)))
print("PASS generated Node bindings: invalid traps, empty, lengths 1..16, uppercase, SIMD SHA-256")


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=str(WEB)))
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH", "/bin/chromium"), args=["--no-sandbox"])
        page = browser.new_page()
        page.goto(f"http://127.0.0.1:{server.server_port}/")
        values = page.evaluate("""async ({invalid, cases, run}) => {
            const binary = await (await fetch('/cap_wasm_bg.wasm')).arrayBuffer();
            const compiled = await WebAssembly.compile(binary);
            const imports = WebAssembly.Module.imports(compiled);
            if (imports.some(i => i.module !== 'wbg' || i.name !== '__wbindgen_init_externref_table'))
                throw new Error('New imports incompatible with widget worker: ' + JSON.stringify(imports));
            const exports = WebAssembly.Module.exports(compiled).map(e => e.name);
            for (const name of ['memory', 'solve_pow', '__wbindgen_malloc', '__wbindgen_realloc', '__wbindgen_export_0'])
                if (!exports.includes(name)) throw new Error('Missing widget worker export: ' + name);
            const module = await import('/cap_wasm.js');
            await module.default();
            return eval('(' + run + ')')(module.solve_pow, invalid, cases);
        }""", {"invalid": INVALID, "cases": CASES, "run": RUN})
        verify(values)
        print(f"PASS generated web bindings in Chromium {browser.version}: same security and SHA-256 checks")
        browser.close()
finally:
    server.shutdown()
    server.server_close()
