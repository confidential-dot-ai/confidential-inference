"""Exercise the actual snapshot producer against a slow local receiver."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

FORK=Path(os.environ.get('SGLANG_FORK_ROOT','/var/lib/user-data/sglang-recovery/worker-clean'))
spec=importlib.util.spec_from_file_location('snapshot_progress',FORK/'python/sglang/srt/utils/pair_progress.py')
progress=importlib.util.module_from_spec(spec);spec.loader.exec_module(progress)


class SnapshotDeliveryTests(unittest.TestCase):
    def capacity(self):
        capacity=int(Path('/proc/sys/net/unix/max_dgram_qlen').read_text())
        if capacity>4096:self.skipTest('local socket queue is too large for this bounded fixture')
        return capacity

    def test_burst_reaches_slow_receiver_without_losing_sequence_or_ack(self):
        total=self.capacity()+32
        with tempfile.TemporaryDirectory() as directory:
            receiver=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
            self.addCleanup(receiver.close)
            receiver.bind(str(Path(directory)/'events.sock'));receiver.settimeout(2)
            received=[]
            def read():
                for _ in range(total+1):
                    received.append(json.loads(receiver.recv(4096)))
                    time.sleep(.005)
            reader=threading.Thread(target=read,daemon=True);reader.start()
            started=time.monotonic()
            for sequence in reversed(range(total)):
                self.assertTrue(progress._send_diagnostic(directory,{
                    'event':'nccl_collective','role':'decode','rank':1,
                    'op':'broadcast','state':'scheduled','sequence':sequence,'count':8}))
            self.assertTrue(progress._send_diagnostic(directory,{
                'event':'nccl_snapshot','role':'decode','rank':1,'count':total,'rejected':0}))
            self.assertLess(time.monotonic()-started,1.5)
            reader.join((total+1)*.005+1)
            self.assertFalse(reader.is_alive())
            self.assertEqual(list(reversed(range(total))),[row['sequence'] for row in received[:-1]])
            self.assertEqual('nccl_snapshot',received[-1]['event'])

    def test_full_queue_keeps_snapshot_wait_bounded(self):
        total=self.capacity()+34
        with tempfile.TemporaryDirectory() as directory:
            receiver=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
            self.addCleanup(receiver.close)
            receiver.bind(str(Path(directory)/'events.sock'))
            started=time.monotonic()
            outcomes=[progress._send_diagnostic(directory,{'event':'nccl_snapshot',
                'role':'decode','rank':1,'count':0,'rejected':0}) for _ in range(total)]
            self.assertLess(time.monotonic()-started,1.5)
            self.assertIn(False,outcomes)


if __name__=='__main__':unittest.main()
