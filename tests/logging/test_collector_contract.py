"""Run the exact collector image against the complete application corpus.

All endpoints and records in this test are local and synthetic. The chart's
processor order and log-output settings stay unchanged.
"""
import gzip
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from corpus import ROOT, SECRET, positives, negatives
from safe_events import validate

spec = importlib.util.spec_from_file_location('collector_fixture', ROOT / 'tests/telemetry/test_collector.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class CollectorContractTests(unittest.TestCase):
    def test_all_events_unapproved_inputs_metadata_and_sink_failures(self):
        received = []
        mode = {'status':200,'delay':0}
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                raw=self.rfile.read(int(self.headers['Content-Length']))
                if self.headers.get('Content-Encoding')=='gzip':raw=gzip.decompress(raw)
                received.append(json.loads(raw))
                time.sleep(mode['delay'])
                body=(SECRET + raw.decode()).encode() if mode['status']!=200 else b'{}'
                self.send_response(mode['status']);self.send_header('Content-Length',str(len(body)));self.end_headers()
                try:self.wfile.write(body)
                except OSError:pass
            def log_message(self,*_):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        image,config=fixture.render()
        config=fixture.local_pipeline(config,'127.0.0.1:1')
        config['service']['pipelines']={'logs':config['service']['pipelines']['logs']}
        config['service']['pipelines']['logs']['exporters']=['otlphttp/test']
        config['exporters']={'otlphttp/test':{
            'logs_endpoint':f'http://127.0.0.1:{server.server_port}/v1/logs',
            'encoding':'json','compression':'none','timeout':'100ms',
            'retry_on_failure':{'enabled':False},'sending_queue':{'enabled':False}}}
        name=f'safe-events-contract-{os.getpid()}'
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config.json';path.write_text(json.dumps(config));path.chmod(0o644)
            subprocess.run([fixture.RUNTIME,'run','-d','--name',name,'--network','host','-v',f'{path}:/etc/config.json:ro',image,'--config=/etc/config.json'],check=True,capture_output=True)
            try:
                for _ in range(60):
                    try:
                        fixture.urllib.request.urlopen('http://127.0.0.1:14133/',timeout=.5).close();break
                    except OSError:time.sleep(.1)
                def send(bodies):
                    records=[{'timeUnixNano':str(time.time_ns()),'severityText':SECRET,'eventName':SECRET,
                              'traceId':'a'*32,'spanId':'b'*16,'flags':1,
                              'body':body,'attributes':[fixture.attribute('prompt',SECRET)]} for body in bodies]
                    fixture.post('/v1/logs',{'resourceLogs':[{'schemaUrl':SECRET,
                        'resource':{'attributes':[fixture.attribute('service.name',SECRET),fixture.attribute('api_key',SECRET)]},
                        'scopeLogs':[{'schemaUrl':SECRET,'scope':{'name':SECRET,'version':SECRET,'attributes':[fixture.attribute('secret',SECRET)]},'logRecords':records}]}]})
                good=positives()
                self.assertTrue(all(good))
                send([{'stringValue':json.dumps(row)} for row in good])
                def count():return sum(len(s['logRecords']) for p in received for r in p['resourceLogs'] for s in r['scopeLogs'])
                deadline=time.monotonic()+10
                while count()<len(good) and time.monotonic()<deadline:time.sleep(.05)
                self.assertEqual(len(good),count())
                wire=json.dumps(received)
                self.assertNotIn(SECRET,wire)
                self.assertNotIn('a'*32,wire)
                self.assertNotIn('b'*16,wire)
                for packet in received:
                    for resource in packet['resourceLogs']:
                        for scope in resource['scopeLogs']:
                            for record in scope['logRecords']:
                                self.assertIsNotNone(validate(json.loads(record['body']['stringValue'])))
                actual=[json.loads(l['body']['stringValue'])['event'] for p in received for r in p['resourceLogs'] for s in r['scopeLogs'] for l in s['logRecords']]
                self.assertEqual(sorted(row['event'] for row in good),sorted(actual))
                # Mixed valid and invalid records prove per-record rejection.
                before=count()
                bad=[{'stringValue':json.dumps(row)} for row in negatives()]
                bad += [{'stringValue':SECRET},{'stringValue':'{'+SECRET},{'stringValue':'x'*4097},
                        {'kvlistValue':{'values':[fixture.attribute('prompt',SECRET)]}}]
                for offset in range(0,len(bad),200):send(bad[offset:offset+200])
                time.sleep(.3)
                self.assertEqual(before,count())
                for status,delay in [(400,0),(503,0),(200,.3)]:
                    mode.update(status=status,delay=delay)
                    before=len(received)
                    try:
                        send([{'stringValue':json.dumps(good[0])}])
                    except fixture.urllib.error.HTTPError as error:
                        self.assertIn(error.code,(400,500,503))
                        error.read()  # Internal export failure; never print the response.
                    deadline=time.monotonic()+3
                    while len(received)==before and time.monotonic()<deadline:time.sleep(.02)
                    self.assertGreater(len(received),before)
                    time.sleep(.35)
                with fixture.urllib.request.urlopen('http://127.0.0.1:18888/metrics',timeout=2) as response:
                    metrics=response.read().decode()
                self.assertIn('otelcol_processor_filter_logs_filtered',metrics)
                self.assertNotIn(SECRET,metrics)
                logs=subprocess.run([fixture.RUNTIME,'logs',name],capture_output=True,text=True,check=True)
                self.assertNotIn(SECRET,logs.stdout+logs.stderr)
                self.assertNotIn(SECRET,json.dumps(received))
                if os.environ.get('SAFE_LOGGING_CAPTURE'):
                    Path(os.environ['SAFE_LOGGING_CAPTURE']).write_text('\n'.join(json.dumps(packet) for packet in received)+'\n')
            finally:
                subprocess.run([fixture.RUNTIME,'rm','-f',name],capture_output=True)
                server.shutdown();server.server_close()

if __name__=='__main__':unittest.main()
