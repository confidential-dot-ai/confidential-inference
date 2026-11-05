"""Use real child processes to check the legacy worker output boundary."""
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest

from corpus import ROOT, SECRET
from safe_events import validate

PROGRAM = ROOT / 'images/sglang-router/private_process.py'

class LegacyWorkerTests(unittest.TestCase):
    def test_raw_native_python_exception_and_format_failures_are_not_logged(self):
        source = f'''
import logging,sys
print({SECRET!r},flush=True)
print({SECRET!r},file=sys.stderr,flush=True)
logging.error('format %d', {SECRET!r})
raise ValueError({SECRET!r})
'''
        result = subprocess.run([sys.executable,str(PROGRAM),sys.executable,'-c',source],capture_output=True,text=True,timeout=10)
        self.assertEqual(1,result.returncode)
        self.assertEqual('',result.stderr)
        self.assertNotIn(SECRET,result.stdout)
        records = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual('worker_process_started',records[0]['event'])
        self.assertEqual('worker_process_exit',records[-1]['event'])
        self.assertTrue(all(validate(record) for record in records))
        self.assertTrue(any(record['event']=='worker_process_output_dropped' for record in records))

    def test_surviving_helper_cannot_hide_worker_exit(self):
        source="import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);sys.exit(7)"
        result=subprocess.run([sys.executable,str(PROGRAM),sys.executable,'-c',source],capture_output=True,text=True,timeout=5)
        self.assertEqual(7,result.returncode)
        self.assertEqual('',result.stderr)
        self.assertEqual(7,json.loads(result.stdout.splitlines()[-1])['code'])

    def test_sigterm_reaches_worker_and_retains_its_exit_code(self):
        source="import signal,time;signal.signal(signal.SIGTERM,lambda *_:exit(0));print('ready',flush=True);time.sleep(60)"
        # The approved event below proves that the handler was installed.
        source=source.replace("print('ready',flush=True)","print('{\\\"schema_version\\\":1,\\\"component\\\":\\\"worker\\\",\\\"event\\\":\\\"worker_process_started\\\",\\\"role\\\":\\\"worker\\\"}',flush=True)")
        process=subprocess.Popen([sys.executable,str(PROGRAM),sys.executable,'-c',source],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            self.assertEqual('worker_process_started',json.loads(process.stdout.readline())['event'])
            self.assertEqual('worker_process_started',json.loads(process.stdout.readline())['event'])
            process.send_signal(signal.SIGTERM)
            output,errors=process.communicate(timeout=5)
            self.assertEqual('',errors)
            self.assertEqual(0,process.returncode)
            self.assertEqual('worker_process_exit',json.loads(output)['event'])
        finally:
            if process.poll() is None:process.kill();process.wait()

if __name__=='__main__':unittest.main()
