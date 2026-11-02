"""Chromium dashboard regressions. --live uses an owned Redis and debug server.
Run: python test/dashboard_regression.py [--live]
Never connects to shared Redis; no FLUSHDB; temporary processes/files cleaned.
"""
import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

from playwright.async_api import async_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
KEYS = [{'siteKey': 'A', 'name': 'Alpha'}]

async def fixtures(browser):
    for scenario in ('recover', 'persistent', 'longwait', 'http503array', 'settings', 'unauthorized', 'object', 'null', 'business'):
        label = scenario
        context = await browser.new_context()
        page = await context.new_page()
        errors, calls = [], []
        page.on('pageerror', lambda e: errors.append(str(e)))
        state = {'count': 0, 'fixed': False, 'active': 0, 'peak': 0}
        slow_reached = asyncio.Event()
        async def route(r):
            path = r.request.url.split('fixture.test')[-1]
            if path.startswith('/server/'):
                calls.append((r.request.method, path, time.monotonic()))
                state['active'] += 1
                state['peak'] = max(state['peak'], state['active'])
                status, data = 200, {
                    '/server/settings/headers': {'ipHeader': '', 'countryHeader': '', 'asnHeader': ''},
                    '/server/settings/ratelimit': {'max': 30, 'duration': 5000},
                    '/server/settings/cors': {'origins': None},
                    '/server/settings/filtering': {'blockNonBrowserUA': False, 'requiredHeaders': []},
                    '/server/settings/ipdb': {'mode': ''},
                    '/server/settings/sessions': [],
                    '/server/settings/apikeys': [],
                }.get(path, {})
                if path == '/server/keys':
                    state['count'] += 1
                    data = KEYS
                    if not state['fixed']:
                        if scenario == 'recover' and state['count'] == 1 or scenario == 'persistent':
                            status, data = 503, {'error': 'busy'}
                        elif scenario == 'longwait': status, data = 503, {'error': 'busy'}
                        elif scenario == 'http503array': status, data = 503, KEYS
                        elif scenario == 'unauthorized': status, data = 401, {'error': 'expired'}
                        elif scenario == 'object': data = {'unexpected': []}
                        elif scenario == 'null': data = None
                        elif scenario == 'business': data = {'success': False, 'message': 'denied'}
                elif path == '/server/settings/headers' and scenario == 'settings' and not state['fixed']:
                    status, data = 503, {'error': 'settings busy'}
                elif r.request.method in ('PUT', 'DELETE'):
                    status, data = 503, {'error': 'write busy'}
                elif '/keys/slow' in path:
                    slow_reached.set()
                    await asyncio.sleep(.3)
                    data = {'error': 'late site'}
                elif '/keys/retry' in path:
                    status, data = 503, {'error': 'busy'}
                await r.fulfill(status=status, content_type='application/json', body=json.dumps(data), headers={'Retry-After': '20' if scenario == 'longwait' else '0.1'})
                state['active'] -= 1
            elif path == '/login':
                await r.fulfill(body='<html>Login</html>', content_type='text/html')
            else:
                relative = path.split('?')[0].lstrip('/').replace('public/', '', 1)
                file = ROOT / 'frontend' / (relative or 'index.html')
                if file.is_file(): await r.fulfill(path=str(file))
                else: await r.fulfill(status=404, body='')
        await context.route('**/*', route)
        await page.add_init_script("if (location.pathname !== '/login') localStorage.setItem('cap_auth', JSON.stringify({token:'fixture',hash:'fixture'}))")
        start = time.monotonic()
        await page.goto('http://fixture.test/')
        if scenario == 'unauthorized':
            await page.wait_for_url('**/login')
            assert await page.evaluate("localStorage.getItem('cap_auth')") is None
            assert state['count'] == 1
        else:
            await page.wait_for_function('keysLoad === null && settingsLoad === null && (keysLoaded || keysError)')
            assert time.monotonic() - start < 10
            assert state['peak'] == 1, calls
            assert calls[1][1] == '/server/keys', calls
            await page.locator('#searchInput').fill('alpha')
            assert await page.evaluate('Array.isArray(keys)')
            if scenario in ('recover', 'settings'):
                await expect(page.locator('.key-item')).to_have_count(1)
                assert state['count'] == (2 if scenario == 'recover' else 1)
            else:
                await expect(page.get_by_role('button', name='Retry loading keys')).to_be_visible()
                assert state['count'] == (3 if scenario in ('persistent', 'http503array') else 1)
                count = state['count']
                await page.wait_for_timeout(400)
                assert state['count'] == count
                state['fixed'] = True
                await page.get_by_role('button', name='Retry loading keys').click()
                await expect(page.locator('.key-item')).to_have_count(1)
            if scenario == 'settings':
                assert await page.evaluate('headerSettings === null && keys.length === 1')
                await page.evaluate('openSettings()')
                await expect(page.locator('#retrySettings')).to_be_visible()
                assert not any(method == 'PUT' for method, _, _ in calls)
                state['fixed'] = True
                await page.locator('#retrySettings').click()
                await page.wait_for_function('!settingsError && headerSettings !== null && settingsLoad === null')
                assert not any(method == 'PUT' for method, _, _ in calls)
            if scenario == 'recover':
                # Previously good keys survive a failed refresh and search.
                state['fixed'] = False
                scenario = 'persistent'
                await page.evaluate('loadKeys()')
                await expect(page.locator('.key-item')).to_have_count(1)
                assert await page.evaluate('keysLoaded && keys.length === 1')
                for method in ('PUT', 'DELETE'):
                    await page.evaluate('(m) => api(m, "/keys/A", {})', method)
                    assert sum(m == method for m, _, _ in calls) == 1
                # Abort a real in-flight read on selection change; ignore its late body.
                await page.evaluate('void (window.slow = api("GET", "/keys/slow"))')
                await asyncio.wait_for(slow_reached.wait(), 3)
                await page.evaluate('siteRequests.abort(); siteRequests = new AbortController(); ++selectionEpoch')
                assert 'error' in await page.evaluate('window.slow')
                # Epoch change during Retry-After must not replay the old site.
                await page.evaluate('void (window.retry = api("GET", "/keys/retry"))')
                await page.wait_for_timeout(30)
                await page.evaluate('++selectionEpoch')
                await page.evaluate('window.retry')
                assert sum(path == '/server/keys/retry' for _, path, _ in calls) == 1
                await page.evaluate('void (window.retry = api("GET", "/keys/retry"))')
                await page.wait_for_timeout(30)
                await page.evaluate("localStorage.removeItem('cap_auth')")
                await page.evaluate('window.retry')
                assert sum(path == '/server/keys/retry' for _, path, _ in calls) == 2
        assert not errors, errors
        print('PASS fixture:', label, 'total keys attempts (including manual refresh):', state['count'])
        await context.close()


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


async def live(browser):
    redis_port, http_port = free_port(), free_port()
    assert redis_port != http_port and 8401 not in (redis_port, http_port)
    processes = []
    with tempfile.TemporaryDirectory(prefix='cap-dashboard-regression-') as tmp:
        env = {k: v for k, v in os.environ.items() if not k.startswith(('CAP_', 'REDIS_', 'SERVER_', 'ADMIN_', 'DEMO_'))}
        redis_url = f'redis://127.0.0.1:{redis_port}/13'
        env.update(CAPPRO_DIR=tmp, REDIS_URL=redis_url, CAP_TEST_REDIS_URL=redis_url,
                   SERVER_HOSTNAME='127.0.0.1', SERVER_PORT=str(http_port),
                   ADMIN_KEY='dashboard-regression-only-secret', ADMIN_LEGACY_DIR=str(ROOT / 'frontend'))
        with open(Path(tmp) / 'redis.log', 'w') as redis_log, open(Path(tmp) / 'server.log', 'w') as server_log:
            try:
                processes.append(subprocess.Popen(['redis-server', '--bind', '127.0.0.1', '--port', str(redis_port), '--save', '', '--appendonly', 'no', '--dir', tmp], stdout=redis_log, stderr=subprocess.STDOUT))
                deadline = time.monotonic() + 10
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1', redis_port), timeout=.2): break
                    except OSError:
                        if time.monotonic() > deadline: raise
                        await asyncio.sleep(.05)
                processes.append(subprocess.Popen([str(ROOT / 'target/debug/cap-server')], cwd=tmp, env=env, stdout=server_log, stderr=subprocess.STDOUT))
                base = f'http://127.0.0.1:{http_port}'
                deadline = time.monotonic() + 30
                while True:
                    try:
                        with urllib.request.urlopen(base + '/login', timeout=1): break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise AssertionError((Path(tmp) / 'server.log').read_text())
                        await asyncio.sleep(.1)
                page = await browser.new_page()
                responses, errors = [], []
                page.on('pageerror', lambda e: errors.append(str(e)))
                page.on('response', lambda r: responses.append((r.status, r.url)) if '/server/' in r.url else None)
                await page.goto(base)
                await page.locator('input[type=password]').fill(env['ADMIN_KEY'])
                await page.get_by_role('button', name='Continue to Cap').click()
                await page.get_by_role('button', name='New key', exact=True).wait_for()
                await page.wait_for_function('keysLoaded && settingsLoad === null && headerSettings !== null', timeout=60000)
                assert await page.evaluate('!keysError && !settingsError && Array.isArray(keys)')
                await page.locator('#searchInput').fill('search-safe')
                assert not errors, errors
                for code, url in responses: print('HTTP', code, url.replace(base, ''))
                print('PASS live debug default CPU; owned Redis DB13, ports', redis_port, http_port)
                await page.close()
            finally:
                for process in reversed(processes):
                    process.terminate()
                    try: process.wait(timeout=10)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()
                print('CLEANUP: owned process handles stopped; temporary directory removed on exit')


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path='/bin/chromium', args=['--no-sandbox'])
        try:
            await fixtures(browser)
            if '--live' in sys.argv: await live(browser)
        finally: await browser.close()

if __name__ == '__main__': asyncio.run(main())
