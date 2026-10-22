"""Run selected upstream PHP CGI session regressions in a bounded Windows job.

No service, PATH, firewall or system configuration changes. Each run ID names a
fresh directory; completed IDs return their saved receipt without another run.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile
import msvcrt

ROOT = Path(__file__).resolve().parent
SOURCES = ROOT / 'source'
RUNTIME = ROOT.parent / 'php-patched-validation' / 'runtime'
PHP = RUNTIME / 'php.exe'
SELECTED = [
    'ext/session/tests/rfc1867_no_user_code.phpt',
    'ext/session/tests/rfc1867_incomplete_class_reserved_props.phpt',
    'ext/session/tests/rfc1867_sid_invalid.phpt',
]

class BasicLimit(c.Structure):
    _fields_ = [('PerProcessUserTimeLimit', c.c_longlong), ('PerJobUserTimeLimit', c.c_longlong),
                ('LimitFlags', w.DWORD), ('MinimumWorkingSetSize', c.c_size_t),
                ('MaximumWorkingSetSize', c.c_size_t), ('ActiveProcessLimit', w.DWORD),
                ('Affinity', c.c_size_t), ('PriorityClass', w.DWORD), ('SchedulingClass', w.DWORD)]
class IoCounters(c.Structure):
    _fields_ = [(name, c.c_ulonglong) for name in ('ReadOperationCount','WriteOperationCount',
                'OtherOperationCount','ReadTransferCount','WriteTransferCount','OtherTransferCount')]
class ExtendedLimit(c.Structure):
    _fields_ = [('BasicLimitInformation', BasicLimit), ('IoInfo', IoCounters),
                ('ProcessMemoryLimit', c.c_size_t), ('JobMemoryLimit', c.c_size_t),
                ('PeakProcessMemoryUsed', c.c_size_t), ('PeakJobMemoryUsed', c.c_size_t)]
class Accounting(c.Structure):
    _fields_ = [(name, c.c_longlong) for name in ('TotalUserTime','TotalKernelTime',
                'ThisPeriodTotalUserTime','ThisPeriodTotalKernelTime')] + [
                (name, w.DWORD) for name in ('TotalPageFaultCount','TotalProcesses',
                'ActiveProcesses','TotalTerminatedProcesses')]
class Startup(c.Structure):
    _fields_ = [('cb', w.DWORD), ('lpReserved', w.LPWSTR), ('lpDesktop', w.LPWSTR),
                ('lpTitle', w.LPWSTR)] + [(name, w.DWORD) for name in
                ('dwX','dwY','dwXSize','dwYSize','dwXCountChars','dwYCountChars','dwFillAttribute','dwFlags')] + [
                ('wShowWindow', w.WORD), ('cbReserved2', w.WORD), ('lpReserved2', c.POINTER(c.c_byte)),
                ('hStdInput', w.HANDLE), ('hStdOutput', w.HANDLE), ('hStdError', w.HANDLE)]
class ProcessInfo(c.Structure):
    _fields_ = [('hProcess', w.HANDLE), ('hThread', w.HANDLE), ('dwProcessId', w.DWORD), ('dwThreadId', w.DWORD)]
class MemoryStatus(c.Structure):
    _fields_ = [('dwLength', w.DWORD), ('dwMemoryLoad', w.DWORD)] + [
        (name, c.c_ulonglong) for name in ('ullTotalPhys', 'ullAvailPhys', 'ullTotalPageFile',
        'ullAvailPageFile', 'ullTotalVirtual', 'ullAvailVirtual', 'ullAvailExtendedVirtual')]

K = c.WinDLL('kernel32', use_last_error=True)
def bind(name, args, result):
    fn = getattr(K, name); fn.argtypes = args; fn.restype = result; return fn
create_job = bind('CreateJobObjectW', [c.c_void_p, w.LPCWSTR], w.HANDLE)
set_job = bind('SetInformationJobObject', [w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL)
query_job = bind('QueryInformationJobObject', [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p], w.BOOL)
assign_job = bind('AssignProcessToJobObject', [w.HANDLE, w.HANDLE], w.BOOL)
create_process = bind('CreateProcessW', [w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL,
    w.DWORD, c.c_void_p, w.LPCWSTR, c.POINTER(Startup), c.POINTER(ProcessInfo)], w.BOOL)
resume = bind('ResumeThread', [w.HANDLE], w.DWORD)
wait = bind('WaitForSingleObject', [w.HANDLE, w.DWORD], w.DWORD)
exit_code = bind('GetExitCodeProcess', [w.HANDLE, c.POINTER(w.DWORD)], w.BOOL)
terminate_process = bind('TerminateProcess', [w.HANDLE, w.UINT], w.BOOL)
terminate_job = bind('TerminateJobObject', [w.HANDLE, w.UINT], w.BOOL)
close = bind('CloseHandle', [w.HANDLE], w.BOOL)
memory_status = bind('GlobalMemoryStatusEx', [c.POINTER(MemoryStatus)], w.BOOL)
def checked(ok):
    if not ok: raise c.WinError(c.get_last_error())

def blob_hash(data):
    return hashlib.sha1(f'blob {len(data)}\0'.encode() + data).hexdigest()

def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def runtime_launch_preflight(runtime, version):
    """Check the verified executables without reserving an observation directory."""
    system = os.environ.get('SystemRoot')
    if not system:
        raise RuntimeError('SystemRoot is unavailable; no run ID was reserved')
    environment = {'SystemRoot': system, 'WINDIR': system,
        'COMSPEC': str(Path(system)/'System32/cmd.exe'),
        'PATH': str(runtime)+';'+str(Path(system)/'System32'),
        'PATHEXT': '.COM;.EXE;.BAT;.CMD'}
    for name, sapi in (('php.exe', 'cli'), ('php-cgi.exe', 'cgi-fcgi')):
        try:
            result = subprocess.run([str(runtime/name), '-n', '-v'],
                cwd=runtime, env=environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8,
                creationflags=subprocess.CREATE_NO_WINDOW, check=False)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f'{name} version preflight timed out; no run ID was reserved') from error
        except OSError as error:
            raise RuntimeError(f'{name} could not start (Windows error {getattr(error, "winerror", None)}); '
                'check the required Visual C++ runtime and DLLs; no run ID was reserved') from error
        if result.returncode != 0:
            code = result.returncode & 0xffffffff
            hint = ('Missing DLL; check the required Visual C++ runtime and DLLs'
                    if code == 0xc0000135 else 'Check the runtime and its dependencies')
            raise RuntimeError(f'{name} version preflight exited 0x{code:08x}. '
                f'{hint}; no run ID was reserved')
        if len(result.stdout) > 16384 or len(result.stderr) > 16384:
            raise RuntimeError(f'{name} version preflight output exceeds its limit; no run ID was reserved')
        first_line = result.stdout.decode('utf-8', errors='replace').splitlines()[:1]
        expected = rf'PHP {re.escape(version)} \({re.escape(sapi)}\)(?: .*)?'
        if not first_line or re.fullmatch(expected, first_line[0]) is None:
            raise RuntimeError(f'{name} did not report PHP {version} ({sapi}); no run ID was reserved')


def create_verified_job():
    """Configure and read back process limits before an observation is reserved."""
    job = create_job(None, None)
    checked(job)
    try:
        limits = ExtendedLimit()
        limits.BasicLimitInformation.LimitFlags = 0x2000 | 0x200 | 0x8
        limits.JobMemoryLimit = 256 * 1024 * 1024
        limits.BasicLimitInformation.ActiveProcessLimit = 16
        checked(set_job(job, 9, c.byref(limits), c.sizeof(limits)))
        configured = ExtendedLimit()
        checked(query_job(job, 9, c.byref(configured), c.sizeof(configured), None))
        if (configured.JobMemoryLimit != 256 * 1024 * 1024
                or configured.BasicLimitInformation.ActiveProcessLimit != 16
                or configured.BasicLimitInformation.LimitFlags & 0x2208 != 0x2208):
            raise RuntimeError('Owned job limits did not match the requested memory/process/cleanup settings; no run ID was reserved')
    except BaseException:
        close(job)
        raise
    return job


def main():
    global RUNTIME, PHP
    parser = argparse.ArgumentParser(
        description='Run selected PHP CGI session-upload regressions on this Windows computer.',
        epilog='First-time users: double-click Start-Lab.cmd at the repository root. '
               'Advanced example: python run-cgi-regressions.py local-patched-1 --runtime-version 8.5.12')
    parser.add_argument('run_id', help='fresh lowercase ID for this observation; repeats never rerun PHP')
    parser.add_argument('--runtime-version', choices=['8.5.12','8.5.11'], default='8.5.12',
                        help='PHP version to test; the older release is reference-only')
    parser.add_argument('--allow-unpatched-reference', action='store_true',
                        help='explicitly allow the older, unpatched reference in this local lab')
    args = parser.parse_args()
    if args.runtime_version == '8.5.11' and not args.allow_unpatched_reference:
        raise RuntimeError('Unpatched reference requires explicit local comparison option')
    if args.runtime_version == '8.5.11': RUNTIME=ROOT.parent/'php-patched-validation'/'runtime-reference-8.5.11'; PHP=RUNTIME/'php.exe'
    if not args.run_id or any(x not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for x in args.run_id):
        raise ValueError('Use a lowercase, event-scoped run ID')
    target = ROOT / 'runs' / args.run_id
    receipt_path = target / 'receipt.json'
    if receipt_path.exists():
        previous=json.loads(receipt_path.read_text(encoding='utf-8'))
        if previous.get('runId') != args.run_id or previous.get('runtimeVersion','8.5.12') != args.runtime_version:
            raise RuntimeError('Run ID conflicts with its saved receipt; inspect that event before proceeding')
        print(json.dumps({'replayed':True,'evidenceStatus':'historical receipt; current inputs were not executed',
                          'receipt':previous},indent=2))
        raise SystemExit(2)
    if target.exists(): raise RuntimeError('Unfinished run exists; reconcile it before another effect')
    manifest = json.loads((ROOT/'source-manifest.json').read_text(encoding='utf-8-sig'))
    entries = {item['path']: item for item in manifest['files']}
    needed = ['run-tests.php'] + SELECTED + ['ext/session/tests/skipif.inc']
    source_bytes = {}
    for relative in needed:
        source = SOURCES / relative
        data = source.read_bytes()
        if blob_hash(data) != entries[relative]['gitBlobSha1']:
            raise RuntimeError(f'Source identity mismatch: {relative}')
        source_bytes[relative] = data
    archive = ROOT.parent/'php-patched-validation'/f'php-{args.runtime_version}-nts-Win32-vs17-x64.zip'
    expected_archive={'8.5.12':'2ab242af38d76bdf417cde5ec048b1bcd76a5a40f39a3d15d5f046f38571c477',
        '8.5.11':'0ea96e0d2b9b737a6036f05cf4e95c49313faa6d0f27bd97edb2742503f0c043'}[args.runtime_version]
    if not archive.is_file():
        raise RuntimeError(f'Missing PHP {args.runtime_version} archive. Run Start-Lab.cmd for guided setup, or follow lab/windows/README.md.')
    if file_sha256(archive) != expected_archive:
        raise RuntimeError('Runtime archive identity mismatch')
    runtime_hashes = {}
    with zipfile.ZipFile(archive) as package:
        entries = [item for item in package.infolist() if not item.is_dir()]
        names = [item.filename for item in entries]
        if len(names) != len(set(name.casefold() for name in names)) or any(
                name.startswith(('/', '\\')) or '\\' in name or ':' in name or
                any(part in ('', '.', '..') for part in name.split('/'))
                for name in names):
            raise RuntimeError('Runtime archive contains unsafe or duplicate paths')
        if not RUNTIME.is_dir():
            raise RuntimeError(f'Missing extracted PHP {args.runtime_version} runtime. Run Start-Lab.cmd for guided setup.')
        actual_files = {path.relative_to(RUNTIME).as_posix().casefold() for path in RUNTIME.rglob('*') if path.is_file()}
        if actual_files != {name.casefold() for name in names} or any(
                path.is_symlink() or getattr(path, 'is_junction', lambda: False)()
                for path in RUNTIME.rglob('*')):
            raise RuntimeError('Extracted PHP runtime contains missing, extra or linked files; no test started')
        for item in package.infolist():
            if item.is_dir(): continue
            expected = hashlib.sha256(package.read(item)).hexdigest()
            actual = file_sha256(RUNTIME/item.filename)
            if actual != expected: raise RuntimeError(f'Extracted runtime changed: {item.filename}')
            runtime_hashes[item.filename] = actual
    addresses = sorted({x[4][0] for x in socket.getaddrinfo('localhost', None)})
    if not addresses or not all(ipaddress.ip_address(x).is_loopback for x in addresses):
        raise RuntimeError('localhost does not resolve exclusively to loopback')
    memory = MemoryStatus(); memory.dwLength = c.sizeof(memory); checked(memory_status(c.byref(memory)))
    if memory.ullAvailPhys < 1024 * 1024 * 1024:
        raise RuntimeError('Available physical memory is below the 1024 MiB execution guard; no PHP test started')
    runtime_launch_preflight(RUNTIME, args.runtime_version)
    job = create_verified_job()
    try:
        target.mkdir(parents=True)
        temporary = target/'tmp'; temporary.mkdir()
        for relative, data in source_bytes.items():
            destination = target/relative; destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            if destination.read_bytes() != data:
                raise RuntimeError(f'Run-local source differs from verified bytes: {relative}')
        system = os.environ['SystemRoot']
        environment = {'SystemRoot':system, 'WINDIR':system, 'COMSPEC':str(Path(system)/'System32/cmd.exe'),
            'PATH':str(RUNTIME)+';'+str(Path(system)/'System32'), 'PATHEXT':'.COM;.EXE;.BAT;.CMD',
            'TEMP':str(temporary), 'TMP':str(temporary), 'USE_ZEND_ALLOC':'1',
            'TEST_PHP_EXECUTABLE':str(PHP), 'TEST_PHP_CGI_EXECUTABLE':str(RUNTIME/'php-cgi.exe'), 'TEST_PHP_SRCDIR':str(target),
            'TEST_PHP_JUNIT':str(target/'junit.xml'), 'REPORT_EXIT_STATUS':'1'}
        command = [str(PHP), '-n', '-d', 'memory_limit=64M', str(target/'run-tests.php'),
            '-n', '-q', '--offline', '--set-timeout', '20', '-p', str(PHP), '-d', 'memory_limit=64M']
        command.extend(str(target/x) for x in SELECTED)
        record = {'runId':args.run_id, 'runtimeVersion':args.runtime_version, 'selectedTests':SELECTED, 'command':command,
            'startedAtUtc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
            'localhostAddresses':addresses, 'environment':environment, 'deadlineSeconds':90,
            'runtimeSha256':file_sha256(PHP),
            'runtimeFileHashes':runtime_hashes,
            'harnessSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'sourceHashes':{name:hashlib.sha256((target/name).read_bytes()).hexdigest() for name in source_bytes},
            'networkIsolation':False, 'serverBinding':'none requested; selected CGI fixtures use pipes and synthetic local files',
            'availablePhysicalMiBBeforeStart':round(memory.ullAvailPhys/(1024*1024),2),
            'jobCommittedMemoryLimitBytes':256*1024*1024, 'jobActiveProcessLimit':16,
            'jobLimitsReadbackVerified':True,
            'limitScope':'These are execution bounds on this owned process tree, not PHP configuration mitigations or proof of memory-safety coverage.',
            'proofScope':'selected CGI session-upload behavior; fresh CGI processes, not persistent-worker or deployed-service proof'}
        (target/'request.json').write_text(json.dumps(record,indent=2),encoding='utf-8')
    except BaseException:
        close(job)
        raise
    pi = ProcessInfo(); assigned = False; begun = time.monotonic()
    try:
        with open(target/'stdout.txt','wb') as output, open(target/'stderr.txt','wb') as errors, open(os.devnull,'rb') as null:
            for file in (output,errors,null): os.set_handle_inheritable(msvcrt.get_osfhandle(file.fileno()),True)
            si = Startup(); si.cb = c.sizeof(si); si.dwFlags = 0x100
            si.hStdInput=msvcrt.get_osfhandle(null.fileno()); si.hStdOutput=msvcrt.get_osfhandle(output.fileno()); si.hStdError=msvcrt.get_osfhandle(errors.fileno())
            block = c.create_unicode_buffer('\0'.join(f'{k}={v}' for k,v in sorted(environment.items()))+'\0\0')
            cmdline = c.create_unicode_buffer(subprocess.list2cmdline(command))
            for relative, data in source_bytes.items():
                if (target/relative).read_bytes() != data:
                    raise RuntimeError(f'Run-local source changed before process launch: {relative}')
            for executable in ('php.exe', 'php-cgi.exe'):
                if file_sha256(RUNTIME/executable) != runtime_hashes[executable]:
                    raise RuntimeError(f'PHP runtime changed before process launch: {executable}')
            checked(create_process(str(PHP),cmdline,None,None,True,0x4|0x400|0x08000000,block,str(target),c.byref(si),c.byref(pi)))
            checked(assign_job(job,pi.hProcess)); assigned=True
            record['runnerProcessId']=pi.dwProcessId
            if resume(pi.hThread) == 0xffffffff: raise c.WinError(c.get_last_error())
            state = wait(pi.hProcess,90000)
            record['deadlineExceeded'] = state == 0x102
            if state == 0xffffffff: raise c.WinError(c.get_last_error())
            if record['deadlineExceeded']: checked(terminate_job(job,124)); wait(pi.hProcess,5000)
            code=w.DWORD(); checked(exit_code(pi.hProcess,c.byref(code))); record['exitCode']=code.value
            accounting=Accounting(); checked(query_job(job,1,c.byref(accounting),c.sizeof(accounting),None))
            record['activeProcessesAfterRunner']=accounting.ActiveProcesses
            record['totalProcesses']=accounting.TotalProcesses
            for unused in range(40):
                if accounting.ActiveProcesses == 0: break
                time.sleep(0.05)
                checked(query_job(job,1,c.byref(accounting),c.sizeof(accounting),None))
            record['activeProcessesAfterGrace']=accounting.ActiveProcesses
            record['forcedDescendantCleanup']=accounting.ActiveProcesses != 0
            if accounting.ActiveProcesses: checked(terminate_job(job,125))
            for unused in range(40):
                checked(query_job(job,1,c.byref(accounting),c.sizeof(accounting),None))
                if accounting.ActiveProcesses == 0: break
                time.sleep(0.05)
            record['activeProcessesAfterCleanup']=accounting.ActiveProcesses
            limits = ExtendedLimit()
            checked(query_job(job,9,c.byref(limits),c.sizeof(limits),None))
            record['peakJobCommittedBytes']=limits.PeakJobMemoryUsed
    except Exception as error:
        record['harnessError']=str(error)
        if pi.hProcess and not assigned: terminate_process(pi.hProcess,126)
        raise
    finally:
        close(job)
        if pi.hThread: close(pi.hThread)
        if pi.hProcess: close(pi.hProcess)
        record['elapsedSeconds']=round(time.monotonic()-begun,3)
        junit=target/'junit.xml'
        if junit.exists():
            try:
                tree=ET.parse(junit); record['testCases']=[{'name':x.attrib.get('name'),
                    'failures':len(x.findall('failure')), 'errors':len(x.findall('error')),
                    'skips':len(x.findall('skipped')), 'warnings':len(x.findall('warning'))} for x in tree.findall('.//testcase')]
            except Exception as error: record['junitParseError']=str(error)
        cases=record.get('testCases',[])
        for case in cases:
            path = (case.get('name') or '').split(' (',1)[0].replace('\\','/')
            prefix = target.as_posix()+'/'
            if path.lower().startswith(prefix.lower()): path=path[len(prefix):]
            case['relativePath']=path
        record['selectedIdentityMatch']=sorted(x['relativePath'] for x in cases)==sorted(SELECTED)
        record['selectedTestsPassed']=(record.get('exitCode') == 0 and not record.get('deadlineExceeded',True)
            and not record.get('harnessError') and not record.get('junitParseError')
            and record.get('activeProcessesAfterCleanup') == 0 and len(cases) == len(SELECTED)
            and record['selectedIdentityMatch']
            and all(x['failures'] == x['errors'] == x['skips'] == x['warnings'] == 0 for x in cases))
        record['finishedAtUtc']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
        receipt_path.write_text(json.dumps(record,indent=2),encoding='utf-8')
    print(json.dumps(record,indent=2))
    raise SystemExit(0 if record['selectedTestsPassed'] else 1)

if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
        print(f'RPK Lab stopped: {error}', file=sys.stderr)
        if isinstance(error, OSError):
            print('If Windows reports a missing Visual C++ runtime DLL, use the official x64 redistributable linked in lab/windows/README.md.', file=sys.stderr)
        raise SystemExit(2)
