"""Check saved-log completeness without running PHP or Docker."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import emit_log_evidence as emitter
import verify_log_evidence as reader


REPOSITORY = 'Basilisk-bat/RPK-PHP-CGI-Lab'
COMMIT = 'a' * 40
VERSION = '8.5.12'


class EvidenceCompletenessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def host(self, label):
        directory = self.root / label
        directory.mkdir()
        for name in emitter.LIMITS:
            (directory / name).write_bytes(f'synthetic {name}\n'.encode('utf-8'))
        return directory

    def emit(self, host, run_id='142', attempt='1'):
        event = f'github-{run_id}-{attempt}-{VERSION}'
        output, errors = io.StringIO(), io.StringIO()
        if not hasattr(os, 'O_NOFOLLOW'):
            os.O_NOFOLLOW = 0  # Windows synthetic check; hosted Linux uses O_NOFOLLOW.
        if not hasattr(os, 'O_NONBLOCK'):
            os.O_NONBLOCK = 0
        with patch.object(sys, 'argv', ['emit_log_evidence.py', '--host', str(host),
                                        '--event', event]), patch.dict(os.environ, {
                                            'GITHUB_REPOSITORY': REPOSITORY,
                                            'GITHUB_SHA': COMMIT,
                                        }), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = emitter.main()
        return code, output.getvalue(), errors.getvalue()

    def read(self, packet, label, run_id='142', attempt='1', output=None):
        log = self.root / f'{label}-job.log'
        log.write_text(''.join('step\t' + line + '\n' for line in packet.splitlines()),
                       encoding='utf-8')
        destination = output or self.root / f'{label}-readback'
        with patch.object(sys, 'argv', [
            'verify_log_evidence.py', '--log', str(log), '--run-id', run_id,
            '--attempt', attempt, '--job-id', '321', '--repository', REPOSITORY,
            '--version', VERSION, '--commit', COMMIT, '--output', str(destination),
        ]), contextlib.redirect_stdout(io.StringIO()):
            code = reader.main()
        return code, destination

    def test_producer_emits_a_complete_packet(self):
        code, packet, errors = self.emit(self.host('complete-producer'))
        self.assertEqual(code, 0)
        self.assertEqual(errors, '')
        records = [json.loads(line.split(' ', 1)[1]) for line in packet.splitlines()]
        self.assertEqual((records[0]['kind'], records[-1]['kind']), ('begin', 'end'))
        self.assertEqual(len([row for row in records if row['kind'] == 'file'
                              and row['status'] == 'present']), len(emitter.LIMITS))

    def test_producer_fails_after_preserving_missing_and_oversized_diagnostics(self):
        for label, change, expected in (
            ('missing', lambda path: path.unlink(), 'missing'),
            ('oversized', lambda path: path.write_bytes(b'x' * (emitter.LIMITS['identity.txt'] + 1)),
             'not-bounded-regular-file'),
        ):
            with self.subTest(label=label):
                host = self.host(label)
                change(host / 'identity.txt')
                code, packet, errors = self.emit(host)
                records = [json.loads(line.split(' ', 1)[1]) for line in packet.splitlines()]
                identity = next(row for row in records if row['kind'] == 'file'
                                and row['name'] == 'identity.txt')
                self.assertEqual(code, 1)
                self.assertEqual(identity['status'], expected)
                self.assertEqual(records[-1]['kind'], 'end')
                self.assertIn('identity.txt', errors)

    def test_importer_marks_a_partial_envelope_incomplete(self):
        host = self.host('partial-import')
        (host / 'identity.txt').unlink()
        emitted_code, packet, _ = self.emit(host)
        self.assertEqual(emitted_code, 1)
        code, destination = self.read(packet, 'partial')
        readback = json.loads((destination / 'readback.json').read_text(encoding='utf-8'))
        self.assertEqual(code, 1)
        self.assertTrue(readback['completeEnvelope'])
        self.assertFalse(readback['allFilesPresent'])
        self.assertEqual(readback['resultStatus'], 'incomplete')
        self.assertIs(readback['selectedResultVerified'], False)
        self.assertEqual(readback['files']['identity.txt'], 'missing')
        self.assertFalse((destination / 'identity.txt').exists())

    def test_importer_keeps_complete_packets_saved_only_and_accepts_fresh_attempt(self):
        host = self.host('complete-import')
        first_code, first_packet, _ = self.emit(host, attempt='1')
        second_code, second_packet, _ = self.emit(host, attempt='2')
        self.assertEqual((first_code, second_code), (0, 0))
        first_read_code, first_dir = self.read(first_packet, 'attempt-1', attempt='1')
        second_read_code, second_dir = self.read(second_packet, 'attempt-2', attempt='2')
        self.assertEqual((first_read_code, second_read_code), (0, 0))
        first = json.loads((first_dir / 'readback.json').read_text(encoding='utf-8'))
        second = json.loads((second_dir / 'readback.json').read_text(encoding='utf-8'))
        for readback in (first, second):
            self.assertTrue(readback['allFilesPresent'])
            self.assertEqual(readback['resultStatus'], 'saved-records-only')
            self.assertIsNone(readback['selectedResultVerified'])
        self.assertNotEqual(first['event'], second['event'])
        saved = (first_dir / 'readback.json').read_bytes()
        with self.assertRaises(FileExistsError):
            self.read(first_packet, 'attempt-1-replay', attempt='1', output=first_dir)
        self.assertEqual((first_dir / 'readback.json').read_bytes(), saved)


if __name__ == '__main__':
    unittest.main()
