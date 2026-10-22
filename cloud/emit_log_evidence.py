"""Emit a bounded, encoded evidence copy when Actions artifact storage is unavailable."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


LIMITS = {
    'source-archive-sha256.txt': 128,
    'image-id.txt': 256,
    'container-id.txt': 256,
    'docker-start-output.txt': 256,
    'docker-wait-exit.txt': 128,
    'inspect.json': 65_536,
    'junit.xml': 262_144,
    'identity.txt': 65_536,
    'summary.json': 65_536,
    'docker-output.txt': 65_536,
    'docker-logs-exit.txt': 128,
}
TOTAL_LIMIT = 524_288
CHUNK_SIZE = 3_000


def line(record):
    print('RPK_CGI_EVIDENCE_V1 ' + json.dumps(record, sort_keys=True, separators=(',', ':')), flush=True)


def read_regular(path: Path, maximum: int):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | getattr(os, 'O_BINARY', 0))
    except FileNotFoundError:
        return None, 'missing'
    except OSError as error:
        return None, f'open-rejected:{error.errno}'
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            return None, 'not-bounded-regular-file'
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                return None, 'exceeds-limit'
            chunks.append(chunk)
        return b''.join(chunks), None
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=Path, required=True)
    parser.add_argument('--event', required=True)
    args = parser.parse_args()
    context = {
        'event': args.event,
        'repository': os.environ.get('GITHUB_REPOSITORY', ''),
        'commit': os.environ.get('GITHUB_SHA', ''),
    }
    line({'kind': 'begin', **context, 'fileCount': len(LIMITS), 'totalLimit': TOTAL_LIMIT})
    total = 0
    rejected = []
    for name, maximum in LIMITS.items():
        data, error = read_regular(args.host / name, maximum)
        if data is not None and total + len(data) > TOTAL_LIMIT:
            data, error = None, 'total-limit'
        if data is None:
            line({'kind': 'file', **context, 'name': name, 'status': error})
            rejected.append(name)
            continue
        total += len(data)
        encoded = base64.b64encode(data).decode('ascii')
        chunks = [encoded[index:index + CHUNK_SIZE]
                  for index in range(0, len(encoded), CHUNK_SIZE)]
        line({'kind': 'file', **context, 'name': name, 'status': 'present',
              'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
              'chunks': len(chunks)})
        for index, chunk in enumerate(chunks):
            line({'kind': 'chunk', **context, 'name': name,
                  'index': index, 'data': chunk})
    line({'kind': 'end', **context, 'copiedBytes': total})
    if rejected:
        print('Incomplete bounded job-log evidence: ' + ', '.join(rejected), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
