"""Reconstruct bounded CGI evidence from a specific GitHub Actions job log."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

from emit_log_evidence import LIMITS, TOTAL_LIMIT


MARKER = 'RPK_CGI_EVIDENCE_V1 '
MAX_LOG_BYTES = 50_000_000


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--attempt', required=True)
    parser.add_argument('--job-id', required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--version', choices=['8.5.11', '8.5.12'], required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.log.stat().st_size > MAX_LOG_BYTES:
        raise ValueError('Job log exceeds review limit')
    context = {
        'event': f'github-{args.run_id}-{args.attempt}-{args.version}',
        'repository': args.repository,
        'commit': args.commit,
    }
    records = []
    with args.log.open('r', encoding='utf-8', errors='replace') as stream:
        for raw_line in stream:
            marker_at = raw_line.find(MARKER)
            if marker_at < 0:
                continue
            record = json.loads(raw_line[marker_at + len(MARKER):])
            if any(record.get(key) != value for key, value in context.items()):
                raise ValueError('Record belongs to a different run, commit or repository')
            records.append(record)
            if len(records) > 1_000:
                raise ValueError('Too many evidence records')

    begins = [record for record in records if record.get('kind') == 'begin']
    ends = [record for record in records if record.get('kind') == 'end']
    if len(begins) != 1 or len(ends) != 1:
        raise ValueError('Incomplete or duplicate evidence envelope')
    if records[0] is not begins[0] or records[-1] is not ends[0]:
        raise ValueError('Evidence envelope is out of order')
    if begins[0].get('fileCount') != len(LIMITS) or begins[0].get('totalLimit') != TOTAL_LIMIT:
        raise ValueError('Evidence limits do not match the expected format')

    manifests = [record for record in records if record.get('kind') == 'file']
    if len(manifests) != len(LIMITS) or {item.get('name') for item in manifests} != set(LIMITS):
        raise ValueError('Missing, extra or repeated file manifest')
    if any(record.get('kind') not in {'begin', 'end', 'file', 'chunk'} for record in records):
        raise ValueError('Unknown record kind')
    decoded = {}
    statuses = {}
    for manifest in manifests:
        name = manifest['name']
        status = manifest.get('status')
        statuses[name] = status
        chunks = [record for record in records if record.get('kind') == 'chunk'
                  and record.get('name') == name]
        if status != 'present':
            if chunks:
                raise ValueError(f'Chunks for rejected file: {name}')
            continue
        count = manifest.get('chunks')
        if not isinstance(count, int) or count != len(chunks):
            raise ValueError(f'Chunk count mismatch: {name}')
        indices = [record.get('index') for record in chunks]
        if indices != list(range(count)):
            raise ValueError(f'Chunk order mismatch: {name}')
        if any(not isinstance(record.get('data'), str) or len(record['data']) > 3_000
               for record in chunks):
            raise ValueError(f'Invalid chunk size: {name}')
        content = base64.b64decode(''.join(record['data'] for record in chunks), validate=True)
        if len(content) > LIMITS[name] or len(content) != manifest.get('size'):
            raise ValueError(f'File size mismatch: {name}')
        if hashlib.sha256(content).hexdigest() != manifest.get('sha256'):
            raise ValueError(f'File hash mismatch: {name}')
        decoded[name] = content
    if any(record.get('name') not in LIMITS for record in records if record.get('kind') == 'chunk'):
        raise ValueError('Unexpected chunk file')
    copied_bytes = sum(map(len, decoded.values()))
    if copied_bytes > TOTAL_LIMIT or copied_bytes != ends[0].get('copiedBytes'):
        raise ValueError('Total size mismatch')

    args.output.mkdir(parents=True, exist_ok=False)
    for name, content in decoded.items():
        (args.output / name).write_bytes(content)
    report = {'schema': 'rpk.php.cloud-log-readback.v1', **context,
              'runId': args.run_id, 'attempt': args.attempt, 'jobId': args.job_id,
              'version': args.version, 'files': statuses,
              'completeEnvelope': True, 'savedBytes': copied_bytes}
    (args.output / 'readback.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
