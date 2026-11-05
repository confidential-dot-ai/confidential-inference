"""Check actual reviewed records on the OTLP wire, including failure bounds."""
import contextlib
import io
import json
import os
import subprocess
from pathlib import Path
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'images/sglang'))
sys.path.insert(0,str(ROOT/'images/sglang-router'))
import pair_supervisor as pair
from private_log_sink import LogSink, NonblockingStdout


class DeliveryTests(unittest.TestCase):
    def test_full_stdout_pipe_cannot_block_supervisor_or_otlp_submission(self):
        source = """
import sys
sys.path.insert(0, sys.argv[1]);sys.path.insert(0, sys.argv[2])
import pair_supervisor as pair
from private_log_sink import NonblockingStdout
class Sink:
    count = 0
    def submit(self, record): self.count += 1
pair.LOG_STDOUT = NonblockingStdout()
pair.LOG_SINK = Sink()
for _ in range(20000): pair.emit('rank_failed', 'decode', rank=0)
assert pair.LOG_SINK.count == 20000
"""
        child = subprocess.Popen([sys.executable, '-c', source,
                                  str(ROOT/'images/sglang'),str(ROOT/'images/sglang-router')],
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            self.assertEqual(0,child.wait(timeout=5))
            output,errors=child.communicate(timeout=1)
        finally:
            if child.poll() is None:child.kill();child.wait()
        self.assertEqual(b'',errors)
        rows=[json.loads(line) for line in output.splitlines()]
        self.assertTrue(rows)
        self.assertLess(len(rows),20000)
        self.assertTrue(all(row['event']=='rank_failed' for row in rows))

    def test_oversized_stdout_record_cannot_leave_partial_json(self):
        read_fd,write_fd=os.pipe()
        try:
            writer=NonblockingStdout(write_fd)
            self.assertFalse(writer.write({'event':'x'*4096}))
            self.assertTrue(writer.write({'event':'router_failed'}))
            self.assertEqual({'event':'router_failed'},json.loads(os.read(read_fd,4096)))
        finally:
            os.close(read_fd);os.close(write_fd)

    def receiver(self, response=None):
        received=[]
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                body=json.dumps(response or {}).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*_):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        return server,received

    def test_only_source_reviewed_records_reach_otlp(self):
        server,received=self.receiver()
        sink=LogSink(f'http://127.0.0.1:{server.server_port}/v1/logs','inference-pd-a')
        pair.LOG_SINK=sink
        private='PRIVATE_PROMPT_RESPONSE_API_CREDENTIAL'
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                for field in ('prompt','response','message','tensor','locals','api_key','rid','run_id'):
                    with self.assertRaises(ValueError):pair.emit('rank_failed','decode',**{field:private})
                pair.emit('rank_progress_failed','decode',rank=0,code=2,age_ms=90001)
            result=sink.close(timeout=2)
        finally:pair.LOG_SINK=None
        self.assertEqual(1,result['exported']);self.assertEqual(0,result['dropped'])
        self.assertTrue(received)
        wire=json.dumps(received)
        self.assertNotIn(private,wire)
        resources=received[0]['resourceLogs'][0]
        self.assertEqual([{'key':'service.name','value':{'stringValue':'inference-pd-a'}}],resources['resource']['attributes'])
        row=json.loads(resources['scopeLogs'][0]['logRecords'][0]['body']['stringValue'])
        self.assertEqual('rank_progress_failed',row['event'])
        self.assertEqual(pair.RUN_ID,row['run_id'])
        self.assertEqual(90001,row['age_ms'])

    def test_partial_rejection_is_counted_without_response_text(self):
        server,_=self.receiver({'partialSuccess':{'rejectedLogRecords':'1','errorMessage':'PRIVATE_RESPONSE_FROM_SINK'}})
        sink=LogSink(f'http://127.0.0.1:{server.server_port}/v1/logs','sglang-router')
        output,errors=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(output),contextlib.redirect_stderr(errors):
            sink.submit({'event':'router_failed','role':'router'})
            result=sink.close(timeout=2)
        self.assertEqual(0,result['exported']);self.assertEqual(1,result['dropped'])
        self.assertEqual(2,result['failures'])
        self.assertEqual('',output.getvalue()+errors.getvalue())

    def test_queue_and_shutdown_are_bounded(self):
        sink=LogSink('http://127.0.0.1:1/v1/logs','sglang-router',timeout=0.02,capacity=2)
        started=time.monotonic()
        for _ in range(10000):sink.submit({'event':'router_failed','role':'router'})
        result=sink.close(timeout=0.5)
        self.assertLess(time.monotonic()-started,2)
        self.assertGreater(result['dropped'],0)
        self.assertLessEqual(sink.queue.qsize(),2)

    def test_unreviewed_export_destinations_are_refused(self):
        for url in ('https://example.com/v1/logs','http://user:PRIVATE@127.0.0.1:4318/v1/logs',
                    'http://127.0.0.1:4318/v1/logs?api_key=PRIVATE','http://127.0.0.1:4318/PRIVATE'):
            with self.assertRaises(ValueError):LogSink(url,'sglang-router')


if __name__=='__main__':unittest.main()
