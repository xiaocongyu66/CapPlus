import json
import os
from pathlib import Path
import signal
import tempfile
import time
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

import ci_runner as ci


class RunnerTests(unittest.TestCase):
    def test_reference_missing_fails_before_commands(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(ci, 'run') as run:
            with self.assertRaises(ValueError): ci.reference_env(None)
            with self.assertRaises(FileNotFoundError): ci.reference_env(Path(tmp) / 'absent')
            with self.assertRaisesRegex(ValueError, 'missing required file'):
                ci.reference_env(tmp)
            run.assert_not_called()

    def test_reference_verified_explicit_path_overrides_untrusted_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            core = Path(tmp) / 'core'
            for name in ci.REFERENCE_FILES:
                file = core / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('fixture')
            def fake_run(argv, *args, **kwargs):
                out = ci.REFERENCE_REVISION + '\n' if 'rev-parse' in argv else ''
                return subprocess.CompletedProcess(argv, 0, out)
            with patch.dict(os.environ, {'CAP_JS_CORE_DIR': '/untrusted', 'CAP_SKIP_JS_PARITY': '1'}), patch.object(ci, 'run', side_effect=fake_run):
                env = ci.reference_env(core)
                self.assertEqual(env['CAP_JS_CORE_DIR'], str(core))
                self.assertEqual(env['CAP_REQUIRE_JS_PARITY'], '1')
                self.assertNotIn('CAP_SKIP_JS_PARITY', env)
                browser = ci.reference_env(core, browser=True)
                self.assertEqual(browser['CAP_JS_CORE_DIR'], str(core))
                self.assertNotIn('CAP_REQUIRE_JS_PARITY', browser)
            with patch.object(ci, 'run', return_value=subprocess.CompletedProcess([], 0, 'wrong')):
                with self.assertRaisesRegex(ValueError, 'revision must be'):
                    ci.reference_env(core)

    def test_exact_classification(self):
        found = {(pkg, name) for pkg, tests in ci.GROUPS.items() for name in tests}
        self.assertEqual(len(ci.reconcile(found)), 17)
        with self.assertRaisesRegex(RuntimeError, 'unclassified'):
            ci.reconcile(found | {('cap-new', 'new_ignored')})
        with self.assertRaisesRegex(RuntimeError, 'missing'):
            ci.reconcile(found - {next(iter(found))})
        self.assertEqual(ci.listed('a::b: test\n0 tests, 0 benchmarks\n'), ['a::b'])

    def test_discover_rejects_duplicate_cargo_output_before_deduplication(self):
        packages = [{'id': pkg, 'name': pkg} for pkg in ci.GROUPS]
        meta = {'workspace_members': list(ci.GROUPS), 'packages': packages}
        duplicate = next(iter(ci.GROUPS['cap-server']))

        def mock_cargo(argv, *args, **kwargs):
            if argv[1] == 'metadata':
                output = json.dumps(meta)
            else:
                pkg = argv[argv.index('-p') + 1]
                output = ''.join(f'{name}: test\n' for name in ci.GROUPS[pkg])
                if pkg == 'cap-server':
                    # Simulate another target reporting the same name (18 rows total).
                    output += f'\n1 test, 0 benchmarks\n{duplicate}: test\n'
            return subprocess.CompletedProcess(argv, 0, output)

        with patch.object(ci, 'run', side_effect=mock_cargo), patch.object(ci, 'reconcile') as reconcile:
            with self.assertRaisesRegex(RuntimeError, 'duplicate ignored test in package cap-server'):
                ci.discover({})
            reconcile.assert_not_called()

    def test_timeout_is_failed_command_not_skip(self):
        with self.assertRaises(subprocess.CalledProcessError) as error:
            ci.run([sys.executable, '-c', 'import time; time.sleep(20)'], timeout=.1)
        self.assertEqual(error.exception.returncode, 124)

    def test_failed_command_propagates(self):
        with self.assertRaises(subprocess.CalledProcessError) as error:
            ci.run([sys.executable, '-c', 'raise SystemExit(19)'])
        self.assertEqual(error.exception.returncode, 19)

    def test_refuses_unowned_process_group(self):
        child = Mock(pid=os.getpid(), ci_pgid=os.getpgrp())
        with self.assertRaisesRegex(RuntimeError, 'unowned'):
            ci.stop(child)

    def test_fork_descendants_cleaned_on_timeout_natural_exit_and_cancel(self):
        # Outer pipe is deliberately inherited by fork descendants in capture=False
        # mode. A leaked writer would make communicate(timeout=...) fail too.
        for mode in ('timeout', 'natural', 'SIGTERM', 'SIGINT'):
            for capture in (False, True):
                with self.subTest(mode=mode, capture=capture), tempfile.TemporaryDirectory() as tmp:
                    pidfile = Path(tmp) / 'grandchild.pid'
                    program = '''import os, signal, sys, time
from pathlib import Path
pid = os.fork()
if pid == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    Path(sys.argv[1]).write_text(str(os.getpid()))
    print('grandchild-ready', flush=True)
    while True: time.sleep(.1)
while not Path(sys.argv[1]).exists(): time.sleep(.01)
if sys.argv[2] == 'natural': sys.exit(0)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True: time.sleep(.1)
'''
                    wrapper = f'''import sys, signal
sys.path.insert(0, {str(ci.ROOT / 'test')!r})
import ci_runner as ci
signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
r = ci.run({[sys.executable, '-c', program, str(pidfile), mode]!r}, capture={capture!r}, timeout=1, check=False)
print('RESULT', r.returncode, flush=True)
'''
                    outer = subprocess.Popen([sys.executable, '-c', wrapper],
                                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    descendant = None
                    try:
                        deadline = time.monotonic() + 5
                        while not pidfile.exists():
                            if time.monotonic() > deadline:
                                self.fail('fork fixture did not start')
                            time.sleep(.01)
                        descendant = int(pidfile.read_text())
                        if mode in ('SIGTERM', 'SIGINT'):
                            outer.send_signal(getattr(signal, mode))
                        output, _ = outer.communicate(timeout=8)
                        if mode in ('timeout', 'natural'):
                            self.assertEqual(outer.returncode, 0, output)
                            self.assertIn('RESULT ' + ('124' if mode == 'timeout' else '0'), output)
                        else:
                            self.assertNotEqual(outer.returncode, 0, output)
                        # A zombie is no longer executing; S/R/etc are a real leak.
                        stat = Path(f'/proc/{descendant}/stat')
                        deadline = time.monotonic() + 2
                        while stat.exists() and stat.read_text().split(') ')[1].split()[0] != 'Z':
                            if time.monotonic() > deadline:
                                self.fail(f'live descendant leaked: {stat.read_text()}')
                            time.sleep(.02)
                    finally:
                        if outer.poll() is None:
                            outer.kill()
                            outer.wait(timeout=3)
                        if descendant is not None:
                            try: os.kill(descendant, signal.SIGKILL)
                            except ProcessLookupError: pass
                        outer.stdout.close()

    def test_redis_failure_still_cleans_up(self):
        child = Mock()
        child.poll.return_value = 1
        with patch.object(ci.subprocess, 'Popen', return_value=child), patch.object(ci, 'stop') as stop:
            with self.assertRaisesRegex(RuntimeError, 'owned Redis exited'):
                with ci.redis(ci.base_env()):
                    self.fail('must not yield unhealthy Redis')
            stop.assert_called_once_with(child)

    def test_no_inherited_redis_or_parity(self):
        with patch.dict(ci.os.environ, {'REDIS_URL': 'redis://shared', 'CAP_REQUIRE_JS_PARITY': '1'}):
            self.assertNotIn('REDIS_URL', ci.base_env())
            self.assertNotIn('CAP_REQUIRE_JS_PARITY', ci.base_env())
        env = ci.urls({}, 'redis://127.0.0.1:12345/15')
        self.assertEqual(env['REDIS_URL'], env['CAP_TEST_REDIS_URL'])


if __name__ == '__main__':
    unittest.main()
