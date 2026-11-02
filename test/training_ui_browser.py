"""Real Chromium DOM + HTTP route fixtures; NOT a real-backend/Redis test.
Run: python test/training_ui_browser.py (requires Python Playwright + Chromium).
"""
import asyncio
import json
from pathlib import Path
from playwright.async_api import async_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'frontend/js/dashboard.js').read_text()
PANEL = SOURCE[SOURCE.index('<div class="config-card" id="trainingPanel">'):]
PANEL = PANEL[:PANEL.index('</div>') + len('</div>')]
GOOD = dict(config=dict(enabled=False, sample_rate_ppm=10000, retention_secs=86400,
                        cap_bytes=1048576), healthy=True, tombstoned=False, epoch=1)

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path='/bin/chromium', args=['--no-sandbox'])
        context = await browser.new_context(accept_downloads=True)
        page = await context.new_page()
        state = {'status': GOOD.copy(), 'fail': False, 'write_fail': False, 'delay': None}
        calls = []
        async def route(r):
            path = r.request.url.split('fixture.test')[-1]
            if path.startswith('/server/'):
                calls.append((r.request.method, path))
                if path.endswith('/status'):
                    snapshot = dict(state['status'])
                    if state['delay']:
                        gate = state['delay']; state['delay'] = None
                        await gate.wait()
                    data = {'error': 'status unavailable'} if state['fail'] else {'success': True, 'data': snapshot}
                elif r.request.method in ('PUT', 'DELETE'):
                    if state['write_fail']:
                        state['fail'] = True
                        data = {'error': '<img src=x onerror="window.pwned=1"> write timeout'}
                    else:
                        data = {'success': True}
                elif '/export?' in path:
                    data = {'error': 'stale cursor'} if state.get('export_fail') else {'success': True, 'data': {'rows': [], 'next_cursor': 'next-fixture'}}
                elif path == '/server/keys': data = []
                elif '/keys/' in path: data = {'key': {'siteKey': path.split('/')[-1]}}
                else: data = {}
                await r.fulfill(json=data)
            else:
                relative = path.split('?')[0].lstrip('/').replace('public/', '', 1)
                file = ROOT / 'frontend' / (relative or 'index.html')
                if file.is_file():
                    await r.fulfill(path=str(file))
                else: await r.fulfill(status=404, body='')
        await context.route('**/*', route)
        await page.add_init_script("localStorage.setItem('cap_auth', JSON.stringify({token:'fixture',hash:'fixture'}))")
        await page.goto('http://fixture.test/')
        async def mount(site='A'):
            await page.evaluate('''({html,site}) => {
                siteRequests.abort(); siteRequests = new AbortController();
                ++selectionEpoch; selectedKey = {siteKey:site};
                keyDetail.style.display='block'; keyDetail.innerHTML=html;
                bindTrainingPanel(site);
            }''', {'html': PANEL, 'site': site})
        def control(name): return page.locator(f'[data-training="{name}"]')
        async def ready(): await expect(control('refresh')).to_be_enabled()
        async def blocked():
            await ready()
            for n in ('save', 'delete', 'download', 'enabled'): await expect(control(n)).to_be_disabled()
        for patch in ({'healthy': False}, {'tombstoned': True}, {'healthy': None}):
            state['status'] = {**GOOD, **patch}
            await mount(); await blocked()
        state['status'] = GOOD.copy(); state['fail'] = True
        await mount(); await blocked()
        await expect(control('status')).to_contain_text('unknown')
        state['fail'] = False
        await control('refresh').click(); await ready()
        await expect(control('save')).to_be_enabled()
        state['write_fail'] = True
        await control('save').click(); await blocked()
        await expect(control('message')).to_contain_text('write timeout')
        await expect(control('message')).to_contain_text('status unavailable')
        assert await page.evaluate('window.pwned') is None
        assert await control('message').locator('img').count() == 0
        assert sum(method == 'PUT' for method, _ in calls) == 1
        state.update(fail=False, write_fail=False)
        gate = asyncio.Event(); state['delay'] = gate
        await mount('A')
        await page.wait_for_function("document.querySelector('#trainingPanel fieldset').disabled")
        # Wait until the delayed A request has reached the route before switching.
        while state['delay'] is not None: await asyncio.sleep(0)
        state['status'] = {**GOOD, 'healthy': False}
        await mount('B'); await blocked()
        gate.set()
        await page.wait_for_load_state('networkidle')
        await blocked(); await expect(control('status')).to_contain_text('unhealthy')
        state['status'] = GOOD.copy()
        await mount(); await ready()
        async with page.expect_download(): await control('download').click()
        await ready(); await expect(control('message')).to_contain_text('not confirmed saved')
        async with page.expect_download(): await control('download').click()
        exports = [path for _, path in calls if '/export?' in path]
        assert exports[-1] == exports[-2] and 'cursor=' not in exports[-1]
        await control('next').click()
        async with page.expect_download(): await control('download').click()
        assert 'cursor=next-fixture' in calls[-1][1]
        state['export_fail'] = True
        await control('download').click(); await ready()
        await expect(control('message')).to_contain_text('stale cursor')
        await expect(control('next')).to_be_disabled()
        state['export_fail'] = False
        async with page.expect_download(): await control('download').click()
        assert 'cursor=' not in calls[-1][1]
        state['status'] = {**GOOD, 'epoch': 2}
        await control('refresh').click(); await ready()
        await expect(control('next')).to_be_disabled()
        async with page.expect_download(): await control('download').click()
        assert 'cursor=' not in calls[-1][1]
        # Generic deletion preserves the original error and reconciles the panel.
        state['write_fail'] = True
        await page.evaluate('deleteKey()')
        await page.locator('#confirmBtn').click()
        await expect(page.locator('#deleteKeyError')).to_contain_text('write timeout')
        await expect(page.locator('#deleteKeyError')).to_contain_text('not complete')
        await blocked()
        assert await page.locator('#deleteKeyError img').count() == 0
        print('PASS: Chromium route fixtures (not real backend): health/tombstone/unknown, recovery, XSS, stale site, pagination, key deletion')
        await browser.close()

asyncio.run(main())
