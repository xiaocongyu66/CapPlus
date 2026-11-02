#!/usr/bin/env python3
"""CI-owned Redis orchestration. Never uses inherited/default Redis or FLUSHDB."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
# tiagozip/cap core 0.1.6, Apache-2.0 (core/LICENSE), verified via GitHub API.
REFERENCE_REVISION = '278796641bc82972b272c5d16dc6f479aeadc753'
REFERENCE_FILES = ('package.json', 'bun.lock', 'LICENSE', 'src/hashwx.js',
                   'src/hashwx-load.js', 'src/hashwx-wasm.js', 'src/prng.js',
                   'src/index.js', 'src/instrumentation.js', 'src/detect.js')
# Exact package + libtest name allowlist. Discovery must equal this list, not a subset.
GROUPS = {
    'cap-admin': {
        'blocked::expiry_tests::blocked_admin_expiry_cas': 'shared',
        'keys::collision_tests::create_retries_collision_without_overwrite': 'shared',
        'rsw::tests::cancellation_keeps_singleflight_and_publication_does_not_overwrite': 'shared',
        'settings::security_settings_tests::security_settings_write_status_and_persistence': 'shared',
        'totp::tests::recovery_login_concurrency': 'shared',
        'totp::tests::totp_state_and_login': 'shared',
    },
    'cap-kv': {
        'business_tests::business_acl_preflight': 'shared',
        'atomic_tests::expired_blocks_cas_batches': 'shared',
        'atomic_tests::atomic_totp_claim': 'shared',
        'atomic_tests::atomic_recovery_and_indexed_creation': 'shared',
    },
    'cap-store': {'business::tests::isolated_business_state_machine': 'shared'},
    'cap-server': {
        'business::tests::isolated_http_business_binding': 'business',
        'cache::security_settings_tests::blocked_cas_concurrent_cache_misses': 'shared',
        'cache::security_settings_tests::security_settings_checked_storage_errors': 'shared',
        'training_routes::tests::isolated_management_http': 'training',
        'demo::tests::isolated_demo_authorization_and_binding': 'demo',
        'redeem::interleaving_tests::isolated_redeem_interleavings': 'redeem',
    },
}


def managed_child(argv, **kwargs):
    child = subprocess.Popen(argv, start_new_session=True, **kwargs)
    child.ci_pgid = child.pid  # Only this factory grants ownership to stop().
    return child


def run(argv, env=None, capture=False, cwd=ROOT, check=True, merge_stderr=False, timeout=None):
    print('+', ' '.join(map(str, argv)), flush=True)
    # File-backed capture cannot wait forever for EOF from an inherited pipe.
    # Cleanup runs even on normal leader exit, KeyboardInterrupt or SIGTERM/SystemExit.
    with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as output:
        child = managed_child(argv, cwd=cwd, env=env, text=True,
                              stdout=output if capture else None,
                              stderr=subprocess.STDOUT if merge_stderr else None)
        try:
            try:
                code = child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                code = 124
        finally:
            stop(child)
        output.seek(0)
        result = subprocess.CompletedProcess(argv, code, output.read() if capture else None)
        if check:
            result.check_returncode()
        return result


def base_env():
    return {k: v for k, v in os.environ.items()
            if k != 'REDISCLI_AUTH' and not k.startswith(('CAP_', 'REDIS_', 'CAPPRO_', 'SERVER_', 'ADMIN_', 'DEMO_'))}


def reference_env(reference, browser=False):
    """Explicit pinned checkout only; never trust inherited CAP_* configuration."""
    if reference is None:
        raise ValueError('--reference-core is required for strict JS parity')
    core = Path(reference).resolve(strict=True)
    for name in REFERENCE_FILES:
        if not (core / name).is_file():
            raise ValueError(f'reference missing required file: {core / name}')
    if core.name != 'core':
        raise ValueError('reference must be the pinned checkout core directory')
    env = base_env()
    revision = run(['git', '-C', str(core.parent), 'rev-parse', 'HEAD'], env, True).stdout.strip()
    if revision != REFERENCE_REVISION:
        raise ValueError(f'reference revision must be {REFERENCE_REVISION}, got {revision}')
    dirty = run(['git', '-C', str(core.parent), 'status', '--porcelain', '--untracked-files=no', '--', 'core'], env, True).stdout
    if dirty.strip():
        raise ValueError('reference core tracked files must be pristine')
    env['CAP_JS_CORE_DIR'] = str(core)
    if not browser:
        env['CAP_REQUIRE_JS_PARITY'] = '1'
    # Evaluate the genuine loader before compiling Rust; this requires no packages.
    script = '''const h = await import(process.env.CAP_JS_CORE_DIR + '/src/hashwx.js');
const state = await h.hashwxReady();
if (typeof h.hashwxHash(state,h.hashwxSeed(new Uint8Array(32).fill(7),3n),12345n) !== 'bigint') throw Error('hashwx API');
'''
    if browser:
        script += '''const c = await import(process.env.CAP_JS_CORE_DIR + '/src/index.js');
for (const key of ['generateChallenge','validateChallenge']) if(typeof c[key] !== 'function') throw Error('core API '+key);
await import(process.env.CAP_JS_CORE_DIR + '/src/prng.js');
await import(process.env.CAP_JS_CORE_DIR + '/src/instrumentation.js');
await import('esbuild'); await import('javascript-obfuscator');
'''
    run(['bun', '-e', script], env, cwd=core, timeout=60)
    print('PASS upstream reference', REFERENCE_REVISION, core, flush=True)
    return env


def port():
    while True:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            value = sock.getsockname()[1]
        if value > 1024 and value not in (6379, 8401):
            return value


def urls(env, url):
    return {**env, 'REDIS_URL': url, 'CAP_TEST_REDIS_URL': url}


def stop(child, grace=1.0):
    """Clean our session's original group, even after its leader exits.

    Descendants that deliberately setsid/setpgid escape this ownership boundary;
    we never scan/kill unrelated processes. Zombies are dead, reaped by their parent.
    """
    pgid = getattr(child, 'ci_pgid', None)
    if not isinstance(pgid, int) or pgid != child.pid or pgid == os.getpgrp():
        raise RuntimeError('refusing cleanup of an unowned process group')
    # A second cancellation must not interrupt TERM -> KILL cleanup. Pending
    # SIGTERM/SIGINT is delivered after cleanup; the original exception propagates.
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
    try:
        def send(sig):
            try:
                os.killpg(pgid, sig)
                return True
            except ProcessLookupError:
                return False
        if send(signal.SIGTERM):
            deadline = time.monotonic() + grace
            while time.monotonic() < deadline:
                child.poll()  # reap leader, but do NOT equate leader exit with group exit
                if not send(0):
                    break
                time.sleep(.02)
            send(signal.SIGKILL)
        child.wait(timeout=5)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


@contextmanager
def redis(env):
    with tempfile.TemporaryDirectory(prefix='cap-ci-redis-') as tmp:
        p = port()
        cli_env = env
        cli = ['redis-cli', '-h', '127.0.0.1', '-p', str(p), '-n', '15', '--raw']
        with open(Path(tmp) / 'redis.log', 'w+') as log:
            child = managed_child(['redis-server', '--bind', '127.0.0.1', '--port', str(p),
                '--save', '', '--appendonly', 'no', '--dir', tmp],
                stdout=log, stderr=log)
            try:
                def command(*args):
                    if child.poll() is not None:
                        raise RuntimeError('owned Redis exited')
                    return subprocess.check_output(cli + list(args), env=cli_env,
                        stderr=subprocess.DEVNULL, text=True, timeout=3).strip()
                deadline = time.monotonic() + 10
                while True:
                    try:
                        if command('PING') == 'PONG':
                            break
                    except subprocess.CalledProcessError:
                        pass
                    if time.monotonic() >= deadline:
                        raise RuntimeError('owned Redis PING timeout')
                    time.sleep(.05)
                version = next(x.split(':', 1)[1] for x in command('INFO', 'server').splitlines()
                               if x.startswith('redis_version:'))
                if int(version.split('.')[0]) < 7:
                    raise RuntimeError('Redis >=7 required')
                if command('ACL', 'SETUSER', 'cap-ci-preflight', 'off', 'reset') != 'OK':
                    raise RuntimeError('Redis ACL administration required')
                if command('ACL', 'DELUSER', 'cap-ci-preflight') != '1':
                    raise RuntimeError('Redis ACL cleanup failed')
                print('PASS owned Redis PING / Redis', version, '/ ACL preflight', flush=True)
                yield {**urls(env, f'redis://127.0.0.1:{p}/15'),
                       'CAPPRO_DIR': str(Path(tmp) / 'data')}
            finally:
                stop(child)


def listed(text):
    # Preserve multiplicity until discover has validated package-level uniqueness.
    return [line[:-6] for line in text.splitlines() if line.endswith(': test')]


def reconcile(discovered):
    expected = {(pkg, name) for pkg, tests in GROUPS.items() for name in tests}
    if discovered != expected:
        raise RuntimeError(f'ignored classification mismatch: unclassified={sorted(discovered-expected)}; missing={sorted(expected-discovered)}')
    return [(pkg, name, GROUPS[pkg][name]) for pkg, name in sorted(discovered)]


def cargo(*args):
    return ['cargo', *args, '--locked']


def discover(env):
    meta = json.loads(run(cargo('metadata', '--no-deps', '--format-version', '1'), env, True).stdout)
    members = set(meta['workspace_members'])
    found = set()
    for pkg in meta['packages']:
        if pkg['id'] in members:
            output = run(cargo('test', '-p', pkg['name']) + ['--', '--ignored', '--list'], env, True).stdout
            print(output, end='')
            for name in listed(output):
                identity = (pkg['name'], name)
                if identity in found:
                    raise RuntimeError(f'duplicate ignored test in package {pkg["name"]}: {name}; '
                                       'cross-target same-name tests require explicit target-aware classification')
                found.add(identity)
    plan = reconcile(found)
    print('IGNORED EXECUTION PLAN', json.dumps(plan, indent=2), flush=True)
    return plan


def rust(mode, reference):
    env = reference_env(reference)
    plan = discover(env)
    if mode == 'list':
        return
    completed = []
    with redis(env) as shared:
        run(cargo('test', '--workspace') + ['--', '--test-threads=1', '--nocapture'], shared)
        for pkg, name, group in plan:
            with tempfile.TemporaryDirectory(prefix='cap-business-http-') as tmp:
                test_env = {**shared, 'CAPPRO_DIR': tmp}
                if group == 'training':
                    test_env.update(CAP_TRAINING_TEST_ISOLATED='YES',
                                    CAP_TRAINING_TEST_REDIS_URL=shared['REDIS_URL'])
                elif group in ('demo', 'redeem'):
                    url = f'redis://127.0.0.1:{port()}/15'
                    test_env = urls(test_env, url)
                    test_env.pop('REDISCLI_AUTH', None)
                    test_env[f'CAP_{group.upper()}_TEST_ISOLATED'] = 'YES'
                    test_env[f'CAP_{group.upper()}_TEST_REDIS_URL'] = url
                run(cargo('test', '-p', pkg, name) + ['--', '--ignored', '--exact', '--test-threads=1', '--nocapture'], test_env)
                completed.append((pkg, name, group))
    if completed != plan:
        raise RuntimeError('ignored execution did not match discovery')
    print(f'PASS reconciled {len(completed)} isolated ignored test processes')


def browser(reference):
    env = reference_env(reference, browser=True)  # No global strict detector switch.
    widget = ROOT / 'widget-source'
    suites = ['unit', 'theme', 'e2e', 'e2e-instrumentation', 'e2e-regression', 'e2e-worker', 'e2e-hashwx']
    outputs = []
    for suite in suites:
        result = run(['bun', 'test', f'test/{suite}.test.js'], cwd=widget, env=env,
                     capture=True, check=False, merge_stderr=True, timeout=300)
        print(result.stdout, flush=True)
        outputs.append(result.stdout)
        result.check_returncode()
    skips = [line for output in outputs for line in output.splitlines()
             if 'skip' in line.lower() and not line.strip().startswith('0 skip')]
    summary_text = 'Actual Bun skip output:\n' + '\n'.join(skips) + '\n'
    print(summary_text)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
            summary.write('```text\n' + summary_text + '```\n')
    if skips:
        raise RuntimeError('Unexpected skipped JS tests with configured upstream reference: ' + '\n'.join(skips))
    note = ('Legacy five e2e suites and PRNG use the pinned genuine upstream reference. '
            'business_bench is excluded: its flow has no business-token binding; '
            'no performance or successful end-to-end solve coverage is claimed.')
    print(note)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
            summary.write(note + '\n')
    for script, args in [('training_ui_browser.py', []), ('dashboard_regression.py', ['--live'])]:
        run([sys.executable, str(ROOT / 'test' / script), *args], env, timeout=300)
    env = urls(env, f'redis://127.0.0.1:{port()}/15')
    env['CAP_DEMO_TEST_ISOLATED'] = 'YES'
    run([sys.executable, str(ROOT / 'test/demo_main_isolated.py')], env, timeout=300)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['rust', 'list', 'browser', 'preflight', 'reference-rust', 'reference-browser'])
    parser.add_argument('--reference-core', type=Path)
    args = parser.parse_args()
    # SIGTERM unwinds finally blocks on CI cancellation as well as ordinary failures.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    if args.mode in ('rust', 'list'):
        rust(args.mode, args.reference_core)
    elif args.mode == 'browser':
        browser(args.reference_core)
    elif args.mode.startswith('reference-'):
        reference_env(args.reference_core, browser=args.mode == 'reference-browser')
    else:
        with redis(base_env()):
            pass


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode if error.returncode > 0 else 1)
