#!/usr/bin/env python3
"""Real main regression; owns Redis, HTTP server, loopback TLS proxy and temp data.
CAP_DEMO_TEST_ISOLATED=YES REDIS_URL=redis://127.0.0.1:19388/15 \
CAP_TEST_REDIS_URL=redis://127.0.0.1:19388/15 python3 test/demo_main_isolated.py
Never connects to an existing Redis. No shared/default Redis or FLUSHDB.
"""
import base64
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
assert os.environ.get('CAP_DEMO_TEST_ISOLATED') == 'YES'
url = os.environ['REDIS_URL']
assert url == os.environ['CAP_TEST_REDIS_URL'], 'both explicit Redis URLs must match'
u = urllib.parse.urlsplit(url)
assert u.scheme == 'redis' and u.hostname == '127.0.0.1' and u.path == '/15'
assert u.port and u.port > 1024 and u.port not in (6379, 8401)
assert not u.username and not u.password and not u.query and not u.fragment

def unused(port=0):
    with socket.socket() as s:
        s.bind(('127.0.0.1', port))
        return s.getsockname()[1]

unused(u.port)  # reject any shared/occupied Redis before starting our child
port = unused()
password = secrets.token_hex(24)
private_url = f'redis://:{password}@127.0.0.1:{u.port}/15'
children = []

def stop(p):
    if p.poll() is None:
        p.terminate()
        try: p.wait(timeout=10)
        except subprocess.TimeoutExpired: p.kill(); p.wait()

def wait_for(check, process, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        assert process.poll() is None, f'child exited {process.returncode}'
        try:
            if check(): return
        except (OSError, http.client.HTTPException, subprocess.CalledProcessError): pass
        time.sleep(.05)
    raise AssertionError('child readiness timeout')

with tempfile.TemporaryDirectory(prefix='cap-demo-main-') as tmp:
    tmp = Path(tmp)
    log = (tmp/'process.log').open('wb')
    redis = subprocess.Popen(['redis-server', '--bind', '127.0.0.1', '--port', str(u.port),
        '--save', '', '--appendonly', 'no', '--requirepass', password, '--dir', str(tmp)], stdout=log, stderr=log)
    children.append(redis)
    cli = ['redis-cli', '-h', '127.0.0.1', '-p', str(u.port), '-n', '15', '--raw']
    cli_env = {**os.environ, 'REDISCLI_AUTH': password}
    def command(*args):
        return subprocess.check_output(cli+list(args), env=cli_env, stderr=subprocess.DEVNULL).decode().strip()
    try:
        wait_for(lambda: command('PING') == 'PONG', redis)
        admin_key = secrets.token_hex(32)
        env = {k:v for k,v in os.environ.items() if not k.startswith('CAP_')}
        env.update(CAPPRO_DIR=str(tmp/'data'), REDIS_URL=private_url, CAP_TEST_REDIS_URL=private_url,
            SERVER_HOSTNAME='127.0.0.1', SERVER_PORT=str(port), ADMIN_KEY=admin_key,
            ADMIN_LEGACY_DIR=str(ROOT/'frontend'), ENABLE_ASSETS_SERVER='false')
        def request(path, body=None, auth=None, host='example.test', tls=None):
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=10) if tls is None else \
                http.client.HTTPSConnection('127.0.0.1', tls, timeout=10, context=ssl._create_unverified_context())
            headers = {'Host': host, 'User-Agent': 'demo-main-regression'}
            if auth: headers['Authorization'] = auth
            if body is not None: headers['Content-Type'] = 'application/json'
            conn.request('POST' if body is not None else 'GET', path,
                json.dumps(body) if body is not None else None, headers)
            r = conn.getresponse(); data = r.read(); status = r.status; hs = dict(r.getheaders()); conn.close()
            return status, data, hs
        def start(demo, domains=None, invalid=False):
            e = {**env, 'DEMO_MODE': str(demo).lower()}
            if domains is not None: e['CAP_DEMO_ALLOWED_DOMAINS'] = domains
            p = subprocess.Popen([str(ROOT/'target/debug/cap-server')], env=e, stdout=log, stderr=log)
            children.append(p)
            if invalid:
                assert p.wait(timeout=30) != 0, 'invalid domain configuration must fail startup'
            else: wait_for(lambda: request('/demo')[0] in (200,404,503), p)
            return p
        # Non-demo missing domain config must start and issue a REAL session.
        server = start(False)
        status, raw, _ = request('/auth/login', {'admin_key':admin_key})
        assert status == 200, (status,raw)
        login = json.loads(raw)
        assert login['session_token'] and login['hashed_token']
        auth = 'Bearer '+base64.b64encode(json.dumps({'token':login['session_token'], 'hash':login['hashed_token']}).encode()).decode()
        stop(server)
        for bad in ('', '*', '*.example.test', '127.0.0.1', 'https://example.test', 'example.test,'):
            start(True, bad, invalid=True)
        server = start(True)
        status, raw, _ = request('/demo')
        assert status == 503 and b'demo_domains_missing' in raw, (status,raw)
        status, raw, _ = request('/demo/credential', {}, auth)
        assert status == 503 and b'demo_domains_missing' in raw, (status,raw)
        stop(server)
        # Restart with an IP listen address AND independent trusted domain.
        server = start(True, 'example.test')
        for host in ('example.test', 'attacker.test'):
            status, raw, _ = request('/demo/credential', {}, host=host)
            assert status == 401, (status,raw)
        status, raw, _ = request('/demo/credential', {}, auth, host='attacker.test')
        assert status == 200, (status,raw)  # Host is NOT authorization or configuration
        credential = json.loads(raw)
        site = credential['siteKey']
        config = json.loads(command('HGET', f'key:{site}', 'config'))
        assert config['corsOrigins'] == ['example.test'], config
        assert credential['businessToken'] and credential['handle']
        assert request('/demo/credential', {'action':'pay'}, auth)[0] == 400
        assert request('/demo/verify', {'response':'a:b:c'}, auth)[0] == 400
        assert request('/demo/verify', {'response':'a:b:c','handle':'0'*48}, auth)[0] == 400
        # Real TLS termination -> loopback HTTP main, with example.test Host.
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=example.test','-addext','subjectAltName=DNS:example.test',
            '-keyout',str(tmp/'key.pem'),'-out',str(tmp/'cert.pem')],check=True,stdout=log,stderr=log)
        class Proxy(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                c = http.client.HTTPConnection('127.0.0.1',port,timeout=10)
                c.request('GET',self.path,headers={'Host':self.headers.get('Host','example.test')})
                r=c.getresponse(); data=r.read(); self.send_response(r.status)
                for k,v in r.getheaders():
                    if k.lower() not in ('transfer-encoding','connection','content-length'): self.send_header(k,v)
                self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data); c.close()
            def log_message(self,*args): pass
        proxy=http.server.ThreadingHTTPServer(('127.0.0.1',0),Proxy)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(tmp/'cert.pem',tmp/'key.pem')
        proxy.socket=ctx.wrap_socket(proxy.socket,server_side=True)
        thread=threading.Thread(target=proxy.serve_forever,daemon=True); thread.start()
        try:
            tls=proxy.server_port
            parent=f'https://example.test:{tls}'
            path=f'/embed/{site}?parent='+urllib.parse.quote(parent,safe='')
            status,raw,headers=request(path,tls=tls,host=f'example.test:{tls}')
            assert status == 200, (status,raw)
            assert parent in headers.get('content-security-policy',''), headers
            assert b'cap-widget' in raw and b'widget.setBusinessToken(d.credential)' in raw, raw
            denied=f'/embed/{site}?parent='+urllib.parse.quote('https://attacker.test',safe='')
            status,raw,_=request(denied,tls=tls,host='attacker.test')
            assert status == 403, (status,raw)
            assert request('/demo',tls=tls)[0] == 200
        finally: proxy.shutdown(); proxy.server_close(); thread.join()
        # Valid old policy != newly configured domains: reject without rotation.
        pointer=command('GET','demo:widget-key')
        stop(server); server=start(True,'other.example.test')
        status,raw,_=request('/demo/credential',{},auth)
        assert status == 503 and b'corsOrigins' in raw, (status,raw)
        assert command('GET','demo:widget-key') == pointer
        assert json.loads(command('HGET',f'key:{site}','config')) == config
        print('PASS real main: login/restart, IP listen + trusted domains, missing/invalid config, authorization, binding body, TLS iframe, forged Host/parent, migration fail-closed')
        print('UI limit: HTTPS iframe response/CSP checked; no browser rendering or solve completion claimed.')
    except BaseException:
        log.flush()
        print((tmp/'process.log').read_text(errors='replace')[-10000:])
        raise
    finally:
        for child in reversed(children[1:]): stop(child)
        if redis.poll() is None:
            # Only enumerate this owned random-password child, then delete exact keys.
            for key in command('--scan').splitlines():
                if key: command('DEL',key)
        stop(redis); log.close()
