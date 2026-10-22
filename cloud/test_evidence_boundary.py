"""Synthetic checks for misleading cloud success labels and log reconstruction."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile


HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def summarize_case(summarize, root, label, version, changes=None, failures=False,
                   bad_fixture_hash=False):
    host = root / label / 'host'
    guest = root / label / 'guest'
    host.mkdir(parents=True)
    guest.mkdir()
    inspect = {
        'networkMode': 'none', 'readOnlyRootfs': True,
        'memoryBytes': 536870912, 'pidsLimit': 64,
        'capDrop': ['ALL'], 'capAdd': [],
        'securityOpt': ['no-new-privileges'], 'privileged': False,
        'pidMode': '', 'ipcMode': 'private', 'utsMode': '',
        'user': '10001:10001', 'tmpfs': {'/work': 'rw', '/tmp': 'rw'},
        'mounts': [{'Type': 'bind', 'Source': str(guest.resolve()),
                    'Destination': '/results', 'RW': True}],
        'requestedMounts': [{'Type': 'bind', 'Source': str(guest.resolve()),
                             'Target': '/results'}],
        'binds': [], 'volumesFrom': [], 'devices': [],
        'running': False, 'oomKilled': False,
        'exitCode': 1 if failures else 0,
    }
    if changes:
        inspect.update(changes)
    (host / 'inspect.json').write_text(json.dumps(inspect), encoding='utf-8')
    (host / 'docker-wait-exit.txt').write_text(str(inspect['exitCode']), encoding='utf-8')
    names = sorted(summarize.SELECTED)
    xml = '<testsuites><testsuite>' + ''.join(
        f'<testcase name="/work/{name}">' +
        ('<failure>regression</failure>' if failures else '') +
        '</testcase>' for name in names) + '</testsuite></testsuites>'
    (guest / 'junit.xml').write_text(xml, encoding='utf-8')
    source_manifest = json.loads((HERE.parent / 'lab' / 'windows' / 'source-manifest.json')
                                 .read_text(encoding='utf-8'))
    identity_lines = [f'PHP {version} (synthetic)',
                      'a' * 64 + '  /src/sapi/cli/php',
                      'b' * 64 + '  /src/sapi/cgi/php-cgi']
    for index, entry in enumerate(source_manifest['files']):
        digest = '0' * 64 if bad_fixture_hash and index == 0 else entry['sha256']
        identity_lines.append(f"{digest}  /work/{entry['path']}")
    (guest / 'identity.txt').write_text('\n'.join(identity_lines) + '\n', encoding='utf-8')
    saved_argv = sys.argv
    try:
        sys.argv = ['summarize.py', '--version', version, '--event', label,
                    '--host', str(host), '--guest', str(guest)]
        with contextlib.redirect_stdout(io.StringIO()):
            exit_code = summarize.main()
    finally:
        sys.argv = saved_argv
    return exit_code, json.loads((host / 'summary.json').read_text(encoding='utf-8'))


def main():
    # Windows has no O_NOFOLLOW; local checks exercise the acceptance predicate.
    # The Linux workflow performs the actual no-follow read.
    if not hasattr(os, 'O_NOFOLLOW'):
        os.O_NOFOLLOW = 0
    if not hasattr(os, 'O_NONBLOCK'):
        os.O_NONBLOCK = 0
    summarize = load('summarize')
    emitter = load('emit_log_evidence')
    verifier = load('verify_log_evidence')
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        good, good_result = summarize_case(summarize, root, 'patched', '8.5.12')
        extra, extra_result = summarize_case(
            summarize, root, 'extra-mount', '8.5.12',
            {'mounts': [{'Type': 'bind', 'Destination': '/results', 'RW': True,
                         'Source': str((root / 'extra-mount' / 'guest').resolve())},
                        {'Type': 'bind', 'Destination': '/host', 'RW': True,
                         'Source': '/host'}],
             'privileged': True, 'capAdd': ['SYS_ADMIN']})
        timeout, timeout_result = summarize_case(
            summarize, root, 'timeout', '8.5.12', {'exitCode': 124})
        reference, reference_result = summarize_case(
            summarize, root, 'reference', '8.5.11', failures=True)
        bad_hash, bad_hash_result = summarize_case(
            summarize, root, 'bad-hash', '8.5.12', bad_fixture_hash=True)
        assert good == 0 and good_result['boundaryVerified'] and good_result['selectedOutcomeVerified']
        assert good_result['fixtureHashesVerified']
        assert extra == 1 and not extra_result['boundaryVerified']
        assert timeout == 1 and not timeout_result['exitVerified']
        assert reference == 0 and reference_result['failed'] == 3
        assert bad_hash == 1 and not bad_hash_result['fixtureHashesVerified']

        host = root / 'patched' / 'host'
        saved_argv = sys.argv
        saved_repo = os.environ.get('GITHUB_REPOSITORY')
        saved_sha = os.environ.get('GITHUB_SHA')
        try:
            os.environ['GITHUB_REPOSITORY'] = 'Basilisk-bat/RPK-PHP-CGI-Lab'
            os.environ['GITHUB_SHA'] = 'a' * 40
            sys.argv = ['emit_log_evidence.py', '--host', str(host),
                        '--event', 'github-1-1-8.5.12']
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                emitter.main()
        finally:
            sys.argv = saved_argv
            if saved_repo is None:
                os.environ.pop('GITHUB_REPOSITORY', None)
            else:
                os.environ['GITHUB_REPOSITORY'] = saved_repo
            if saved_sha is None:
                os.environ.pop('GITHUB_SHA', None)
            else:
                os.environ['GITHUB_SHA'] = saved_sha
        records = [json.loads(line.split(' ', 1)[1]) for line in output.getvalue().splitlines()]
        assert records[0]['kind'] == 'begin' and records[-1]['kind'] == 'end'
        for manifest in (record for record in records if record['kind'] == 'file'
                         and record['status'] == 'present'):
            encoded = ''.join(record['data'] for record in records
                              if record['kind'] == 'chunk' and record['name'] == manifest['name'])
            import base64
            data = base64.b64decode(encoded)
            assert len(data) == manifest['size']
            assert hashlib.sha256(data).hexdigest() == manifest['sha256']
        log = root / 'synthetic-job.log'
        log.write_text(''.join('step\t' + line + '\n' for line in output.getvalue().splitlines()),
                       encoding='utf-8')
        try:
            sys.argv = ['verify_log_evidence.py', '--log', str(log), '--run-id', '1',
                        '--attempt', '1', '--job-id', '2',
                        '--repository', 'Basilisk-bat/RPK-PHP-CGI-Lab',
                        '--version', '8.5.12',
                        '--commit', 'a' * 40, '--output', str(root / 'verified')]
            with contextlib.redirect_stdout(io.StringIO()):
                verifier.main()
        finally:
            sys.argv = saved_argv
        saved = (root / 'verified' / 'summary.json').read_bytes()
        original = (host / 'summary.json').read_bytes()
        assert saved == original, (len(saved), len(original),
                                   hashlib.sha256(saved).hexdigest(),
                                   hashlib.sha256(original).hexdigest())
    print('synthetic boundary and log reconstruction checks passed')


if __name__ == '__main__':
    main()
