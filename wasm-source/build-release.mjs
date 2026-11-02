// Non-interactive local build. No publishing or package installation.
// Requires Rust 1.99.1, wasm32-unknown-unknown, wasm-bindgen-cli 0.2.100,
// Node, Python with Playwright, and /bin/chromium for artifact verification.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

if (process.argv.length !== 2) throw new Error('This script accepts no arguments or publish options');
const root = path.dirname(fileURLToPath(import.meta.url));
const crate = path.join(root, 'src/rust');
const toolchain = process.env.RUST_TOOLCHAIN || 'stable';
const bindgen = process.env.WASM_BINDGEN || 'wasm-bindgen';
const rustVersion = execFileSync('rustc', [`+${toolchain}`, '--version'], { encoding: 'utf8' }).trim();
if (!rustVersion.startsWith('rustc 1.99.1 ')) throw new Error(`Expected Rust 1.99.1, got ${rustVersion}`);
const cliVersion = execFileSync(bindgen, ['--version'], { encoding: 'utf8' }).trim();
if (cliVersion !== 'wasm-bindgen 0.2.100') throw new Error(`Wrong CLI: ${cliVersion}`);
console.log(rustVersion, cliVersion);
const staging = fs.mkdtempSync(path.join(os.tmpdir(), 'cap-wasm-release-'));
try {
  const targetDir = path.join(staging, 'target');
  execFileSync('cargo', [`+${toolchain}`, 'build', '--manifest-path', path.join(crate, 'Cargo.toml'),
    '--target', 'wasm32-unknown-unknown', '--release', '--locked', '--offline', '--target-dir', targetDir], {
    stdio: 'inherit', env: { ...process.env, RUSTFLAGS: '-C target-feature=+simd128 -D warnings' },
  });
  for (const [folder, target] of [['browser', 'web'], ['node', 'nodejs']]) {
    const out = path.join(staging, folder);
    execFileSync(bindgen, [path.join(targetDir, 'wasm32-unknown-unknown/release/cap_wasm.wasm'),
      '--target', target, '--out-dir', out, '--out-name', 'cap_wasm'], { stdio: 'inherit' });
    const loader = path.join(out, 'cap_wasm.js');
    fs.writeFileSync(loader, fs.readFileSync(loader, 'utf8').trimEnd() + '\n');
    // Preserve the tracked package's ESM/CommonJS contract.
    fs.copyFileSync(path.join(root, 'src', folder, 'package.json'), path.join(out, 'package.json'));
  }
  execFileSync('python', [path.join(root, 'test/generated_security.py'),
    path.join(staging, 'node'), path.join(staging, 'browser')], { stdio: 'inherit', timeout: 120000 });
  // Do not touch tracked artifacts until both targets have built and passed tests.
  const names = ['cap_wasm.js', 'cap_wasm_bg.wasm', 'cap_wasm.d.ts', 'cap_wasm_bg.wasm.d.ts'];
  for (const folder of ['browser', 'node']) {
    for (const name of names) fs.copyFileSync(path.join(staging, folder, name), path.join(root, 'src', folder, name));
  }
  for (const name of names.slice(0, 2)) {
    const dest = path.join(root, '../widget-dist', name);
    fs.copyFileSync(path.join(staging, 'browser', name), dest);
    console.log(`${createHash('sha256').update(fs.readFileSync(dest)).digest('hex')}  ${dest}`);
  }
} finally {
  fs.rmSync(staging, { recursive: true, force: true });
}
