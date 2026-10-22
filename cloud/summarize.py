"""Verify a cloud container boundary and selected PHP CGI observations."""
import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import re
import stat
import sys
import xml.etree.ElementTree as ET

SELECTED = {
    'rfc1867_no_user_code.phpt',
    'rfc1867_incomplete_class_reserved_props.phpt',
    'rfc1867_sid_invalid.phpt',
}
SOURCE_MANIFEST = Path(__file__).resolve().parent.parent / 'lab' / 'windows' / 'source-manifest.json'
PHP_BINARY_PATHS = {'/src/sapi/cli/php', '/src/sapi/cgi/php-cgi'}
HASH_LINE = re.compile(r'^([0-9a-f]{64})  (/[^\r\n]+)$')
VERSION_LINE = re.compile(r'^PHP ([0-9]+\.[0-9]+\.[0-9]+) \((cli|cgi-fcgi)\)(?: .*)?$')


def runtime_headers_match(identity: bytes, version: str) -> bool:
    try:
        headers = [line for line in identity.decode('utf-8').splitlines() if line.startswith('PHP ')]
    except UnicodeDecodeError:
        return False
    if len(headers) != 2:
        return False
    parsed = [VERSION_LINE.fullmatch(line) for line in headers]
    return all(parsed) and {(match.group(1), match.group(2)) for match in parsed} == {
        (version, 'cli'), (version, 'cgi-fcgi')
    }


def fixture_hashes_match(identity: bytes) -> bool:
    manifest = json.loads(SOURCE_MANIFEST.read_text(encoding='utf-8-sig'))
    expected = {'/work/' + entry['path']: entry['sha256'] for entry in manifest['files']}
    if len(expected) != len(manifest['files']):
        return False
    try:
        lines = identity.decode('utf-8').splitlines()
    except UnicodeDecodeError:
        return False
    observed = {}
    for line in lines:
        match = HASH_LINE.fullmatch(line)
        if match:
            digest, path = match.groups()
            if path in observed:
                return False
            observed[path] = digest
    if set(observed) != set(expected) | PHP_BINARY_PATHS:
        return False
    return all(observed[path] == digest for path, digest in expected.items())

def read_guest_regular(path: Path, maximum: int) -> bytes:
    """Read a stopped container's output without following links or accepting bulk data."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                 | getattr(os, 'O_BINARY', 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError(f'Guest output is not a bounded regular file: {path.name}')
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise ValueError(f'Guest output exceeds size limit: {path.name}')
        return b''.join(chunks)
    finally:
        os.close(fd)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', required=True, choices=['8.5.11', '8.5.12'])
    parser.add_argument('--event', required=True)
    parser.add_argument('--host', type=Path, required=True)
    parser.add_argument('--guest', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9.-]{1,100}', args.event):
        raise ValueError('Unsafe event identifier')
    host, guest = args.host, args.guest
    inspect = json.loads((host / 'inspect.json').read_text(encoding='utf-8'))
    wait_exit = int((host / 'docker-wait-exit.txt').read_text(encoding='utf-8').strip())
    junit = read_guest_regular(guest / 'junit.xml', 1_048_576)
    identity = read_guest_regular(guest / 'identity.txt', 65_536)
    fixture_hashes_verified = fixture_hashes_match(identity)
    runtime_version_verified = runtime_headers_match(identity, args.version)
    (host / 'junit.xml').write_bytes(junit)
    (host / 'identity.txt').write_bytes(identity)

    cases = []
    for case in ET.fromstring(junit).findall('.//testcase'):
        name = case.attrib.get('name', '')
        path = name.split(' (', 1)[0].replace('\\', '/')
        cases.append({
            'test': path.rsplit('/', 1)[-1],
            'failures': len(case.findall('failure')),
            'errors': len(case.findall('error')),
            'skips': len(case.findall('skipped')),
            'warnings': len(case.findall('warning')),
        })

    mounts = inspect.get('mounts') or []
    requested_mounts = inspect.get('requestedMounts') or []
    bind_mounts = [mount for mount in mounts if mount.get('Type') == 'bind']
    tmpfs_mounts = [mount for mount in mounts if mount.get('Type') == 'tmpfs']
    expected_mount = (
        len(requested_mounts) == 1 and len(bind_mounts) == 1
        and len(mounts) == len(bind_mounts) + len(tmpfs_mounts)
        and requested_mounts[0].get('Type') == 'bind'
        and requested_mounts[0].get('Target') == '/results'
        and Path(requested_mounts[0].get('Source', '')).resolve() == guest.resolve()
        and bind_mounts[0].get('Destination') == '/results'
        and Path(bind_mounts[0].get('Source', '')).resolve() == guest.resolve()
        and bind_mounts[0].get('RW') is True
        and {mount.get('Destination') for mount in tmpfs_mounts}.issubset({'/work', '/tmp'})
    )
    security_options = inspect.get('securityOpt') or []
    tmpfs = inspect.get('tmpfs') or {}
    tmpfs_flags_verified = (
        set(tmpfs) == {'/work', '/tmp'}
        and all({'rw', 'noexec', 'nosuid', 'nodev'}.issubset(set(options.split(',')))
                for options in tmpfs.values())
    )
    expected_security_options = {'no-new-privileges', 'no-new-privileges:true'}
    boundary_verified = (
        inspect.get('networkMode') == 'none'
        and inspect.get('readOnlyRootfs') is True
        and inspect.get('memoryBytes') == 536870912
        and inspect.get('pidsLimit') == 64
        and inspect.get('privileged') is False
        and not inspect.get('capAdd') and 'ALL' in (inspect.get('capDrop') or [])
        and bool(security_options)
        and set(security_options).issubset(expected_security_options)
        and inspect.get('pidMode') in ('', 'private')
        and inspect.get('ipcMode') in ('', 'private')
        and inspect.get('utsMode') in ('', 'private')
        and inspect.get('user') == '10001:10001'
        and tmpfs_flags_verified
        and expected_mount
        and not inspect.get('binds') and not inspect.get('volumesFrom')
        and not inspect.get('devices')
        and inspect.get('running') is False and inspect.get('oomKilled') is False
    )
    selected_match = len(cases) == len(SELECTED) and {case['test'] for case in cases} == SELECTED
    clean_cases = all(case['errors'] == case['skips'] == case['warnings'] == 0 for case in cases)
    passed = sum(case['failures'] == case['errors'] == case['skips'] == case['warnings'] == 0 for case in cases)
    failed = sum(case['failures'] > 0 or case['errors'] > 0 for case in cases)
    expected_exit = 0 if args.version == '8.5.12' else 1
    exit_verified = wait_exit == inspect.get('exitCode') == expected_exit
    outcome_verified = (selected_match and clean_cases and exit_verified
                        and fixture_hashes_verified and runtime_version_verified) and (
        (args.version == '8.5.12' and passed == 3) or
        (args.version == '8.5.11' and failed == 3)
    )
    result = {
        'schema': 'rpk.php.cloud-cgi-result.v2',
        'event': args.event,
        'version': args.version,
        'boundaryVerified': boundary_verified,
        'selectedIdentityMatch': selected_match,
        'fixtureHashesVerified': fixture_hashes_verified,
        'runtimeVersionVerified': runtime_version_verified,
        'exitVerified': exit_verified,
        'selectedOutcomeVerified': outcome_verified,
        'passed': passed,
        'failed': failed,
        'dockerWaitExit': wait_exit,
        'containerExitCode': inspect.get('exitCode'),
        'junitSha256': hashlib.sha256(junit).hexdigest(),
        'identitySha256': hashlib.sha256(identity).hexdigest(),
        'cases': cases,
        'interpretation': 'Selected result and container boundary verified' if boundary_verified and outcome_verified
                          else 'Cloud result needs review; no verified comparison claim',
    }
    (host / 'summary.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    if boundary_verified and outcome_verified:
        if args.version == '8.5.12':
            heading = 'Selected patched checks passed'
            explanation = 'All three selected fresh-process CGI cases passed in PHP 8.5.12.'
        else:
            heading = 'Older reference showed the selected difference'
            explanation = 'All three selected cases failed in PHP 8.5.11. That is comparison evidence, not a successful defensive result.'
    else:
        heading = 'No verified comparison from this job'
        explanation = 'A test, identity, exit-status or container-boundary check needs review.'
    (host / 'report.md').write_text(
        f'### PHP {args.version}: {heading}\n\n{explanation}\n\n'
        f'Event: `{args.event}`. Selected cases: {passed} passed, {failed} failed. '
        f'Boundary verified: `{str(boundary_verified).lower()}`. '
        f'Selected outcome verified: `{str(outcome_verified).lower()}`.\n\n'
        'This does not test a persistent server, cover every security path, or verify a deployed PHP service. '
        'Download the job artifact for the receipt and test details; artifact upload can fail independently.\n',
        encoding='utf-8')
    escape = html.escape
    (host / 'report.html').write_text(f'''<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RPK PHP CGI Lab result</title>
<style>:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#08090b;color:#f3eae8;font:16px/1.55 Consolas,'Cascadia Mono',monospace}}main{{max-width:58rem;margin:auto;padding:clamp(1.5rem,6vw,5rem)}}.kicker{{color:#ff715f;letter-spacing:.13em;text-transform:uppercase}}h1{{font-size:clamp(2rem,5vw,3.5rem);line-height:1.12;font-weight:600}}p{{max-width:70ch}}section{{border-top:1px solid #8b4b46;padding-top:1.4rem;margin-top:2rem}}a{{color:#ff998c}}a:focus-visible{{outline:3px solid #ff715f;outline-offset:3px}}.signal{{border:1px solid #ff715f;padding:1.2rem;background:#180e0e}}small{{color:#cbb9b6}}@media(forced-colors:active){{.signal{{border:1px solid CanvasText}}}}</style>
<main><p class="kicker">RPK / cloud experiment</p><h1>{escape(heading)}</h1>
<div class="signal"><p>{escape(explanation)}</p><p><strong>PHP:</strong> {escape(args.version)}<br><strong>Event:</strong> {escape(args.event)}</p></div>
<section><h2>Evidence</h2><p>Selected cases: {passed} passed, {failed} failed. Container boundary verified: {boundary_verified}. Selected outcome verified: {outcome_verified}.</p><p>See <a href="summary.json">summary</a>, <a href="junit.xml">test details</a> and <a href="identity.txt">runtime identity</a> for the recorded checks.</p></section>
<section><h2>Limit</h2><p>This result does not prove an exploit, cover every PHP security path, test a persistent server, or verify a deployed service.</p></section>
<small>Generated in GitHub Actions from the recorded job result. Confirm the run, attempt and commit in GitHub before citing it.</small></main></html>\n''', encoding='utf-8')
    print(json.dumps(result, indent=2))
    return 0 if boundary_verified and outcome_verified else 1

if __name__ == '__main__':
    sys.exit(main())
