"""Inert Windows startup checks. No PHP executable or Windows Job is launched."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile


HERE = Path(__file__).resolve().parent
if os.name != 'nt':
    raise SystemExit('These inert runner checks require Windows Python.')
SPEC = importlib.util.spec_from_file_location('cgi_runner', HERE / 'run-cgi-regressions.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class StartupChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='rpk-cgi-preflight-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'lab/windows'
        self.source = self.root / 'source'
        self.runtime = self.root.parent / 'php-patched-validation/runtime'
        self.runtime.mkdir(parents=True)
        self.source.mkdir(parents=True)
        self.archive = self.runtime.parent / 'php-8.5.12-nts-Win32-vs17-x64.zip'
        with zipfile.ZipFile(self.archive, 'w') as package:
            for name in ('php.exe', 'php-cgi.exe', 'dependency.dll'):
                data = ('inert fixture bytes for ' + name).encode()
                package.writestr(name, data)
                (self.runtime / name).write_bytes(data)
        manifest = []
        for name in ['run-tests.php', *runner.SELECTED, 'ext/session/tests/skipif.inc']:
            data = ('inert source fixture for ' + name).encode()
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            manifest.append({'path': name, 'gitBlobSha1': runner.blob_hash(data)})
        (self.root / 'source-manifest.json').write_text(json.dumps({'files': manifest}))
        self.trace = []
        self.target = self.root / 'runs/event-a'
        self.job_failure = None
        self.probe_failure = None
        self.fail_binary = 'php.exe'
        self.reservation_race = False
        self.change_runtime_after_preflight = False
        self.patchers = contextlib.ExitStack()
        self.addCleanup(self.patchers.close)
        for name, value in [('ROOT', self.root), ('SOURCES', self.source),
                            ('RUNTIME', self.runtime), ('PHP', self.runtime / 'php.exe')]:
            self.patchers.enter_context(patch.object(runner, name, value))
        real_hash = runner.file_sha256
        def fixture_hash(path):
            if Path(path) == self.archive:
                return '2ab242af38d76bdf417cde5ec048b1bcd76a5a40f39a3d15d5f046f38571c477'
            return real_hash(path)
        self.patchers.enter_context(patch.object(runner, 'file_sha256', side_effect=fixture_hash))
        self.patchers.enter_context(patch.dict(os.environ, {'SystemRoot': 'C:\\Windows'}, clear=True))
        self.patchers.enter_context(patch.object(runner.socket, 'getaddrinfo', return_value=[
            (None, None, None, None, ('127.0.0.1', 0))]))
        self.probe = self.patchers.enter_context(patch.object(runner.subprocess, 'run', side_effect=self.version_probe))
        self.create_job = self.patchers.enter_context(patch.object(runner, 'create_job', side_effect=self.job_create))
        self.patchers.enter_context(patch.object(runner, 'set_job', side_effect=self.job_set))
        self.patchers.enter_context(patch.object(runner, 'query_job', side_effect=self.job_query))
        self.patchers.enter_context(patch.object(runner, 'memory_status', side_effect=self.available_memory))
        self.create_process = self.patchers.enter_context(patch.object(runner, 'create_process', side_effect=self.process_create))
        self.patchers.enter_context(patch.object(runner, 'assign_job', return_value=True))
        self.patchers.enter_context(patch.object(runner, 'resume', return_value=0))
        self.patchers.enter_context(patch.object(runner, 'wait', return_value=0))
        self.patchers.enter_context(patch.object(runner, 'exit_code', side_effect=self.process_exit))
        self.patchers.enter_context(patch.object(runner, 'close', side_effect=lambda handle: self.trace.append(('close', handle))))
        self.patchers.enter_context(patch.object(runner, 'terminate_job', side_effect=AssertionError('Unexpected termination')))
        self.patchers.enter_context(patch.object(runner, 'terminate_process', side_effect=AssertionError('Unexpected termination')))
        self.patchers.enter_context(patch.object(runner.os, 'set_handle_inheritable'))
        self.patchers.enter_context(patch.object(runner.msvcrt, 'get_osfhandle', side_effect=lambda value: value))

    @staticmethod
    def ffi_failure():
        runner.c.set_last_error(5)
        return False

    def available_memory(self, pointer):
        runner.c.cast(pointer, runner.c.POINTER(runner.MemoryStatus)).contents.ullAvailPhys = 2 * 1024**3
        return True

    def version_probe(self, command, **kwargs):
        name = Path(command[0]).name
        self.trace.append(('probe', name))
        self.assertFalse(self.target.exists(), 'Version checks must precede event reservation')
        self.assertEqual(command[1:], ['-n', '-v'])
        self.assertEqual(kwargs['cwd'], self.runtime)
        self.assertEqual(kwargs['timeout'], 8)
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        self.assertEqual(kwargs['creationflags'], subprocess.CREATE_NO_WINDOW)
        self.assertEqual(set(kwargs['env']), {'SystemRoot', 'WINDIR', 'COMSPEC', 'PATH', 'PATHEXT'})
        sapi = 'cli' if name == 'php.exe' else 'cgi-fcgi'
        result = subprocess.CompletedProcess(command, 0, f'PHP 8.5.12 ({sapi}) (inert fixture)\n'.encode(), b'')
        if name == self.fail_binary:
            if isinstance(self.probe_failure, BaseException):
                raise self.probe_failure
            if self.probe_failure == 'missing-dll': result.returncode = -1073741515
            if self.probe_failure == 'wrong-version': result.stdout = result.stdout.replace(b'8.5.12', b'8.5.11')
            if self.probe_failure == 'wrong-sapi': result.stdout = b'PHP 8.5.12 (unrelated)\n'
            if self.probe_failure == 'prefixed-header': result.stdout = b'not ' + result.stdout
            if self.probe_failure == 'large-output': result.stdout = b'x' * 16385
        return result

    def job_create(self, *args):
        self.trace.append(('job-create', None))
        self.assertFalse(self.target.exists())
        return self.ffi_failure() if self.job_failure == 'create' else 101

    def job_set(self, handle, information, pointer, size):
        self.trace.append(('job-set', information))
        self.assertFalse(self.target.exists())
        return self.ffi_failure() if self.job_failure == 'set' else True

    def job_query(self, handle, information, pointer, size, returned):
        if information == 9:
            configured = runner.c.cast(pointer, runner.c.POINTER(runner.ExtendedLimit)).contents
            if not self.create_process.called:
                self.trace.append(('job-readback', information))
                self.assertFalse(self.target.exists())
                if self.job_failure == 'query': return self.ffi_failure()
            configured.JobMemoryLimit = 256 * 1024**2
            configured.BasicLimitInformation.ActiveProcessLimit = 16
            configured.BasicLimitInformation.LimitFlags = 0x2208
            if self.job_failure == 'memory': configured.JobMemoryLimit = 0
            if self.job_failure == 'processes': configured.BasicLimitInformation.ActiveProcessLimit = 0
            if self.job_failure == 'flags': configured.BasicLimitInformation.LimitFlags = 0
            if self.reservation_race:
                self.target.mkdir(parents=True)
                (self.target / 'concurrent-owner.txt').write_text('preserve this event')
            if self.change_runtime_after_preflight:
                (self.runtime / 'php.exe').write_bytes(b'changed after preflight')
        else:
            accounting = runner.c.cast(pointer, runner.c.POINTER(runner.Accounting)).contents
            accounting.ActiveProcesses = 0
            accounting.TotalProcesses = 2
        return True

    def process_create(self, application, command, pa, ta, inherit, flags, env, cwd, startup, process):
        self.trace.append(('phpt-create', None))
        self.assertTrue(self.target.is_dir())
        self.assertTrue((self.target / 'request.json').is_file())
        info = runner.c.cast(process, runner.c.POINTER(runner.ProcessInfo)).contents
        info.hProcess, info.hThread, info.dwProcessId = 202, 303, 404
        junit = '<testsuites><testsuite>' + ''.join(
            f'<testcase name="{name} (inert fixture)"/>' for name in runner.SELECTED)
        (self.target / 'junit.xml').write_text(junit + '</testsuite></testsuites>')
        return True

    def process_exit(self, handle, pointer):
        runner.c.cast(pointer, runner.c.POINTER(runner.w.DWORD)).contents.value = 0
        return True

    def invoke(self, run_id='event-a', extra=()):
        self.target = self.root / 'runs' / run_id
        with patch.object(sys, 'argv', ['run-cgi-regressions.py', run_id, *extra]), \
             contextlib.redirect_stdout(io.StringIO()):
            runner.main()

    def assert_no_reservation(self):
        self.assertFalse(self.target.exists())
        self.create_process.assert_not_called()

    def test_help_is_inert(self):
        with self.assertRaises(SystemExit) as ended:
            self.invoke('--help')
        self.assertEqual(ended.exception.code, 0)
        self.probe.assert_not_called()
        self.create_job.assert_not_called()
        self.assertFalse((self.root / 'runs').exists())

    def test_missing_system_root_and_reference_opt_in_are_inert(self):
        with patch.dict(os.environ, {}, clear=True), \
             self.assertRaisesRegex(RuntimeError, 'SystemRoot is unavailable'):
            self.invoke()
        self.assert_no_reservation()
        with self.assertRaisesRegex(RuntimeError, 'Unpatched reference requires'):
            self.invoke(extra=('--runtime-version', '8.5.11'))
        self.probe.assert_not_called()
        self.create_job.assert_not_called()

    def test_loader_timeout_and_version_failures_do_not_reserve_event(self):
        for binary in ('php.exe', 'php-cgi.exe'):
            for failure in ('missing-dll', 'wrong-version', 'wrong-sapi', 'prefixed-header',
                            'large-output', OSError('inert loader failure'),
                            subprocess.TimeoutExpired('inert version probe', 8)):
                with self.subTest(binary=binary, failure=str(failure)):
                    self.fail_binary, self.probe_failure = binary, failure
                    with self.assertRaisesRegex(RuntimeError, 'no run ID was reserved'):
                        self.invoke()
                    self.assert_no_reservation()
                    self.create_job.assert_not_called()
        # Correcting an unreserved prerequisite failure keeps this ID eligible.
        self.probe_failure = None
        with self.assertRaises(SystemExit) as ended:
            self.invoke()
        self.assertEqual(ended.exception.code, 0)

    def test_job_setup_failures_close_handles_before_reservation(self):
        for failure in ('create', 'set', 'query', 'memory', 'processes', 'flags'):
            with self.subTest(failure=failure):
                self.trace.clear()
                self.job_failure = failure
                with self.assertRaises((OSError, RuntimeError)):
                    self.invoke()
                self.assert_no_reservation()
                closed = [item for item in self.trace if item[0] == 'close']
                self.assertEqual(closed, [] if failure == 'create' else [('close', 101)])

    def test_fresh_events_run_after_preflight_and_completed_ids_only_replay(self):
        for run_id in ('event-a', 'event-b'):
            self.trace.clear()
            self.create_process.reset_mock()
            with self.assertRaises(SystemExit) as ended:
                self.invoke(run_id)
            self.assertEqual(ended.exception.code, 0)
            self.assertEqual(self.trace[:5], [('probe', 'php.exe'), ('probe', 'php-cgi.exe'),
                ('job-create', None), ('job-set', 9), ('job-readback', 9)])
            receipt = json.loads((self.target / 'receipt.json').read_text())
            self.assertTrue(receipt['selectedTestsPassed'])
            self.assertTrue(receipt['jobLimitsReadbackVerified'])
            exporter = (HERE / 'Write-HostedPacket.ps1').read_text()
            allowed = re.search(r'\$allowedReceiptFields = @\((.*?)\n\)', exporter, re.S)
            self.assertIsNotNone(allowed)
            self.assertEqual(set(receipt), set(re.findall(r"'([^']+)'", allowed.group(1))))
            before = (self.target / 'receipt.json').read_bytes()
            self.probe.reset_mock()
            self.create_job.reset_mock()
            self.create_process.reset_mock()
            with self.assertRaises(SystemExit) as replay:
                self.invoke(run_id)
            self.assertEqual(replay.exception.code, 2)
            self.assertEqual((self.target / 'receipt.json').read_bytes(), before)
            self.probe.assert_not_called()
            self.create_job.assert_not_called()
            self.create_process.assert_not_called()

    def test_saved_failed_result_also_replays_without_php(self):
        self.target.mkdir(parents=True)
        receipt = {'runId': 'event-a', 'runtimeVersion': '8.5.12', 'selectedTestsPassed': False}
        path = self.target / 'receipt.json'
        path.write_text(json.dumps(receipt))
        before = path.read_bytes()
        with self.assertRaises(SystemExit) as replay:
            self.invoke()
        self.assertEqual(replay.exception.code, 2)
        self.assertEqual(path.read_bytes(), before)
        self.probe.assert_not_called()
        self.create_job.assert_not_called()
        self.create_process.assert_not_called()

    def test_conflicting_and_unfinished_events_remain_untouched(self):
        self.target.mkdir(parents=True)
        receipt = self.target / 'receipt.json'
        for data in ({'runId': 'other', 'runtimeVersion': '8.5.12'},
                     {'runId': 'event-a', 'runtimeVersion': '8.5.11'}):
            receipt.write_text(json.dumps(data))
            with self.assertRaisesRegex(RuntimeError, 'conflicts'):
                self.invoke()
            self.assertEqual(json.loads(receipt.read_text()), data)
        receipt.unlink()
        with self.assertRaisesRegex(RuntimeError, 'Unfinished run'):
            self.invoke()
        self.probe.assert_not_called()
        self.create_job.assert_not_called()
        self.create_process.assert_not_called()

    def test_runtime_file_set_check_still_precedes_startup(self):
        extra = self.runtime / 'unreviewed.ini'
        extra.write_text('inert extra file')
        with self.assertRaisesRegex(RuntimeError, 'missing, extra or linked files'):
            self.invoke()
        self.assert_no_reservation()
        self.probe.assert_not_called()
        self.create_job.assert_not_called()

    def test_concurrent_reservation_is_preserved_and_job_is_closed(self):
        self.reservation_race = True
        with self.assertRaises(FileExistsError):
            self.invoke()
        self.assertEqual((self.target / 'concurrent-owner.txt').read_text(), 'preserve this event')
        self.assertEqual(sorted(path.name for path in self.target.iterdir()), ['concurrent-owner.txt'])
        self.create_process.assert_not_called()
        self.assertIn(('close', 101), self.trace)

    def test_runtime_change_after_preflight_still_prevents_phpt_launch(self):
        self.change_runtime_after_preflight = True
        with self.assertRaisesRegex(RuntimeError, 'PHP runtime changed before process launch'):
            self.invoke()
        self.create_process.assert_not_called()
        receipt = json.loads((self.target / 'receipt.json').read_text())
        self.assertFalse(receipt['selectedTestsPassed'])
        self.assertIn('PHP runtime changed', receipt['harnessError'])
        self.assertIn(('close', 101), self.trace)


if __name__ == '__main__':
    unittest.main()
