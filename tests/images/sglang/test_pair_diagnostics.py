"""Exercise code-only capture with real processes and a real signal dump."""
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'images/sglang'))
sys.path.insert(0, str(ROOT / 'images/sglang-router'))
import pair_supervisor as pair
from pair_diagnostics import StackSnapshots

PUBLIC_FILE = '/opt/sglang/python/sglang/srt/layers/public_fixture.py'
PUBLIC_LABEL = 'sglang/srt/layers/public_fixture.py'
CHILD = r'''
import importlib.util, os, signal, sys, time
from pathlib import Path
delayed = sys.argv[4] == 'delay'
if delayed: signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
spec=importlib.util.spec_from_file_location('progress',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
os.environ['SGLANG_PAIR_ROLE']='decode'
os.environ['SGLANG_PAIR_RUN_DIR']=sys.argv[2]
module.initialize(0)
secret_prompt='PRIVATE_PROMPT_TEXT'
secret_response='PRIVATE_RESPONSE_TEXT'
credential='PRIVATE_API_CREDENTIAL'
request_id='PRIVATE_CLIENT_REQUEST_ID'
source='def PRIVATE_FUNCTION_NAME():\n local_value="PRIVATE_LOCAL_VALUE"\n ready.write_text("ready")\n if delayed:\n  time.sleep(1)\n  signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGUSR2})\n while True: time.sleep(0.01)\n'
namespace={'time':time,'ready':Path(sys.argv[2])/'fixture.ready','delayed':delayed,'signal':signal}
exec(compile(source,sys.argv[3],'exec'),namespace)
exec(compile('PRIVATE_FUNCTION_NAME()', '/PRIVATE_FILENAME_SECRET.py', 'exec'),namespace)
'''


class SnapshotPrivacyTests(unittest.TestCase):
    def check_snapshot(self, stopped=False, delayed=False):
        fork = Path(os.environ.get('SGLANG_FORK_ROOT', '/var/lib/user-data/sglang-recovery/worker-clean'))
        progress = fork / 'python/sglang/srt/utils/pair_progress.py'
        self.assertTrue(progress.is_file(), 'set SGLANG_FORK_ROOT to the tested fork')
        output, errors = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            pair.CODE_LOCATIONS.add(PUBLIC_LABEL)
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                snapshots = StackSnapshots(directory, [('decode', 0)], pair.emit,
                                           catalog={PUBLIC_FILE: PUBLIC_LABEL})
                child = subprocess.Popen([sys.executable, '-c', CHILD, str(progress), directory, PUBLIC_FILE,
                                          'delay' if delayed else 'normal'],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    deadline = time.monotonic() + 5
                    while ('decode', 0) not in snapshots.peers or not (Path(directory)/'fixture.ready').is_file():
                        self.assertIsNone(child.poll())
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.01)
                    if stopped:
                        os.kill(child.pid, signal.SIGSTOP)
                    snapshots.request({('decode', 0): child.pid})
                    deadline = time.monotonic() + 3
                    while 'stack_dump_' not in output.getvalue():
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.01)
                finally:
                    if stopped:
                        os.kill(child.pid, signal.SIGCONT)
                    child.terminate()
                    child.wait(timeout=3)
                    snapshots.close()
                    pair.CODE_LOCATIONS.discard(PUBLIC_LABEL)
        raw = output.getvalue() + errors.getvalue()
        for value in ('PRIVATE_PROMPT_TEXT', 'PRIVATE_RESPONSE_TEXT', 'PRIVATE_API_CREDENTIAL',
                      'PRIVATE_CLIENT_REQUEST_ID', 'PRIVATE_LOCAL_VALUE', 'PRIVATE_FILENAME_SECRET',
                      'PRIVATE_FUNCTION_NAME'):
            self.assertNotIn(value, raw)
        self.assertEqual('', errors.getvalue())
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertLessEqual(len(rows), 130)
        return rows

    def test_real_faulthandler_exports_only_reviewed_locations(self):
        rows = self.check_snapshot()
        frames = [row for row in rows if row['event'] == 'stack_frame']
        self.assertTrue(frames, json.dumps(rows))
        self.assertTrue(all(row['location'] == PUBLIC_LABEL for row in frames))
        self.assertTrue(all(set(row) == {'timestamp_ns','run_id','source_revision','event','role','rank','thread','frame','location','line'} for row in frames))
        summary = next(row for row in rows if row['event'] == 'stack_dump_complete')
        self.assertGreater(summary['rejected'], 0)

    def test_unresponsive_process_does_not_block_snapshot_deadline(self):
        started = time.monotonic()
        rows = self.check_snapshot(stopped=True)
        self.assertLess(time.monotonic() - started, 4)
        self.assertTrue(any(row['event'] == 'stack_dump_unavailable' for row in rows))

    def test_delayed_signal_still_provides_code_frames_within_capture_budget(self):
        rows = self.check_snapshot(delayed=True)
        self.assertTrue(any(row['event'] == 'stack_frame' for row in rows), json.dumps(rows))

    def test_unapproved_location_cannot_enter_log_schema(self):
        record={'event':'stack_frame','role':'decode','rank':0,'location':'PRIVATE_PROMPT_TEXT','line':1}
        self.assertIsNone(pair.reviewed_event(record))
        for value in ('PRIVATE_API_CREDENTIAL', True, float('nan'), {}, []):
            record['location']=PUBLIC_LABEL
            record['line']=value
            self.assertIsNone(pair.reviewed_event(record))


if __name__ == '__main__':
    unittest.main()
