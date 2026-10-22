"""Check each copied upstream fixture against its pinned Git blob identity."""
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent / 'lab' / 'windows'
SOURCE = ROOT / 'source'
MANIFEST = ROOT / 'source-manifest.json'


def blob_hash(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()


def main():
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8-sig'))
    entries = manifest['files']
    names = [item['path'] for item in entries]
    if any(item.is_symlink() for item in SOURCE.rglob('*')):
        raise ValueError('Source inventory contains a link')
    actual = {item.relative_to(SOURCE).as_posix() for item in SOURCE.rglob('*') if item.is_file()}
    if len(names) != len(set(names)) or set(names) != actual:
        raise ValueError('Source inventory differs from pinned manifest')
    for entry in entries:
        data = (SOURCE / entry['path']).read_bytes()
        if blob_hash(data) != entry['gitBlobSha1']:
            raise ValueError(f"Git blob mismatch: {entry['path']}")
        if 'sha256' in entry and hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise ValueError(f"SHA-256 mismatch: {entry['path']}")
    print(f"Verified {len(entries)} pinned upstream source files at {manifest['ref']}")


if __name__ == '__main__':
    main()
