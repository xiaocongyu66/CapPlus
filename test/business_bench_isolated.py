#!/usr/bin/env python3
"""Own isolated loopback processes; never connect to an existing Redis/server."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    if port in (8401, 6379):
        return free_port()
    return port


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', required=True, type=Path, help='Previously built server binary (never builds working tree)')
    p.add_argument('--label', required=True, help='Revision/build label recorded verbatim')
    p.add_argument('--playwright', type=Path, default=Path(__file__).resolve().parents[1] / 'widget-source/node_modules/playwright/index.mjs')
    p.add_argument('--chromium', default='/bin/chromium')
    p.add_argument('--output-parent', type=Path, help='Existing directory for isolated temporary evidence (default system temp)')
    p.add_argument('--seconds', type=int, default=15)
    p.add_argument('--rounds', type=int, default=3)
    p.add_argument('--concurrency', default='1,4,8')
    args = p.parse_args()
    concurrency = [int(x) for x in args.concurrency.split(',')]
    if not 1 <= args.seconds <= 30 or not 1 <= args.rounds <= 3 or not concurrency or len(concurrency) > 3 or any(x not in (1, 4, 8) for x in concurrency):
        p.error('bounded runs only: seconds 1..30, rounds 1..3, concurrency 1/4/8')
    binary = args.binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix='cap-business-bench-', dir=args.output_parent))
    os.chmod(root, 0o700)
    port, redis_port = free_port(), free_port()
    while redis_port == port:
        redis_port = free_port()
    origin = f'http://127.0.0.1:{port}'
    password, secret = secrets.token_hex(32), secrets.token_hex(32)
    config = dict(protocol='hashwx', hashwxDifficulty=1000000, rsw=False,
                  difficulty=4, challengeCount=80, saltSize=32,
                  instrumentation=True, obfuscationLevel=3,
                  blockAutomatedBrowsers=False, blockOnDeny=True,
                  requireSessionBind=True, blockNonBrowserUA=True,
                  ratelimitMax=1000, ratelimitDuration=60000,
                  corsOrigins=[origin])
    manifest = dict(label=args.label, binary=str(binary), binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                    protocol='official embedded widget/hashwx', site_config=config,
                    security=dict(CAP_REQUIRE_VSESS='true', CAP_TRUST_PROXY='false', CAP_RL_MODE='redis'),
                    seconds=args.seconds, rounds=args.rounds, concurrency=concurrency,
                    port=port, redis_port=redis_port, chromium=args.chromium,
                    browser_mode='automated headed Chromium on owned Xvfb; default automation flags retained; no JS probe spoofing',
                    protocol_compatibility='33fd36a fixture only; candidate comparison suspended pending mandatory domain and business-credential protocol adaptation',
                    interpretation='Strict automated-client measurement, not human traffic; refusal alone establishes neither bottleneck nor false positive',
                    cold_definition='first solve after fresh server/Redis/browser, page and assets already loaded',
                    warm_definition='one successful flow per worker before timed rounds; caches retained across rounds',
                    cpu_definition='server process user+system CPU; browser solve/probe wall time measured separately',
                    coverage='hashwx + instrumentation + signed embed session + SHA256 site secret; excludes RSW and legacy Argon secret')
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    redis_conf = root / 'redis.conf'
    redis_conf.write_text(f'bind 127.0.0.1\nport {redis_port}\nsave ""\nappendonly no\nrequirepass {password}\nmaxmemory 256mb\nmaxmemory-policy noeviction\ndir {root}\n')
    os.chmod(redis_conf, 0o600)
    processes = []
    logs = []
    print(str(root), flush=True)
    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        def start(cmd, name, env=None):
            log = (root / name).open('w')
            logs.append(log)
            proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env)
            processes.append(proc)
            return proc
        redis = start(['redis-server', str(redis_conf)], 'redis.log')
        renv = {**os.environ, 'REDISCLI_AUTH': password}
        def cli(*cmd):
            if redis.poll() is not None:
                raise RuntimeError('owned Redis exited; refusing to connect to another process')
            return subprocess.check_output(['redis-cli', '-h', '127.0.0.1', '-p', str(redis_port), '--raw', *cmd], env=renv, timeout=3).decode().strip()
        # Bounded startup readiness, not polling for candidate changes.
        for _ in range(100):
            try:
                if cli('PING') == 'PONG':
                    break
            except subprocess.SubprocessError:
                pass
            time.sleep(.05)
        else:
            raise RuntimeError('Redis startup timed out')
        cli('HSET', 'key:benchsite', 'name', 'isolated benchmark', 'jwtSecret', secrets.token_hex(32),
            'secretHash', 'sha256:' + hashlib.sha256(secret.encode()).hexdigest(), 'config', json.dumps(config))
        cli('SADD', 'keys', 'benchsite')
        # Do not inherit CAP_* production configuration, proxy secrets or Redis URLs.
        env = {k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'LANG', 'LC_ALL', 'LD_LIBRARY_PATH')}
        env.update(TMPDIR=str(root), CAPPRO_DIR=str(root / 'server-data'), SERVER_HOSTNAME='127.0.0.1', SERVER_PORT=str(port),
                   REDIS_URL=f'redis://:{password}@127.0.0.1:{redis_port}/0', ADMIN_KEY=secrets.token_hex(32),
                   CAP_REQUIRE_VSESS='true', CAP_TRUST_PROXY='false', CAP_RL_MODE='redis')
        server = start([str(binary)], 'server.log', env)
        for _ in range(200):
            if server.poll() is not None:
                raise RuntimeError('owned server exited')
            try:
                urllib.request.urlopen(origin + '/assets/widget.js', timeout=.3).close()
                break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError('server startup timed out')
        # Isolated display for an explicitly automated browser. Retain automation
        # flags and strict server policy; a trust rejection is not business success.
        display_read, display_write = os.pipe()
        xlog = (root / 'xvfb.log').open('w')
        logs.append(xlog)
        try:
            xvfb = subprocess.Popen(['Xvfb', '-displayfd', str(display_write), '-screen', '0', '1280x800x24', '-nolisten', 'tcp'],
                                    pass_fds=(display_write,), stdout=xlog, stderr=subprocess.STDOUT)
            processes.append(xvfb)
            os.close(display_write)
            display_write = None
            if not select.select([display_read], [], [], 10)[0]:
                raise RuntimeError('owned Xvfb startup timed out')
            display = os.read(display_read, 32).decode().strip()
            if not display.isdecimal():
                raise RuntimeError('owned Xvfb failed to allocate display')
        finally:
            os.close(display_read)
            if display_write is not None:
                os.close(display_write)
        nenv = {**env, 'DISPLAY': ':' + display, 'BENCH_URL': origin, 'BENCH_SECRET': secret, 'BENCH_SERVER_PID': str(server.pid),
                'BENCH_REDIS_PORT': str(redis_port), 'REDISCLI_AUTH': password,
                'BENCH_OUT': str(root), 'BENCH_PLAYWRIGHT': str(args.playwright.resolve()),
                'BENCH_CHROMIUM': args.chromium, 'BENCH_SECONDS': str(args.seconds),
                'BENCH_ROUNDS': str(args.rounds), 'BENCH_CONCURRENCY': args.concurrency}
        run = start(['node', str(Path(__file__).with_name('business_bench_browser.mjs'))], 'driver.log', nenv)
        rc = run.wait(timeout=900)
        if rc:
            raise RuntimeError(f'browser driver exited {rc}; inspect {root}/driver.log')
        print(f'Evidence: {root}/results.jsonl', flush=True)
    finally:
        for proc in reversed(processes):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
        for log in logs:
            log.close()
        (root / 'cleanup.json').write_text(json.dumps([dict(pid=x.pid, exitcode=x.returncode) for x in processes]))


if __name__ == '__main__':
    main()
