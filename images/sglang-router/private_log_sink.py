"""Bounded OTLP/HTTP delivery for records reviewed by the private log writers.

No automatic request instrumentation, trace baggage or credentials are read.
The caller constructs the record before it reaches this sender.
"""
import json
import os
import queue
import re
import threading
import time
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


class LogSink:
    def __init__(self, endpoint, service, *, timeout=0.5, capacity=1024):
        parsed = urllib.parse.urlsplit(endpoint)
        internal = parsed.hostname == '127.0.0.1' or re.fullmatch(
            r'telemetry-collector\.[a-z0-9-]+\.svc\.cluster\.local', parsed.hostname or '')
        if (parsed.scheme != 'http' or not internal or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path != '/v1/logs'
                or parsed.port is None):
            raise ValueError('invalid internal log endpoint')
        if not re.fullmatch(r'(sglang-router|inference-pd-[a-z0-9-]{1,24})', service):
            raise ValueError('invalid diagnostic service name')
        self.endpoint, self.service, self.timeout = endpoint, service, timeout
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.queue = queue.Queue(maxsize=capacity)
        self.stop = threading.Event()
        self.sent = self.dropped = self.failures = 0
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    @classmethod
    def from_environment(cls):
        endpoint = os.environ.get('OTEL_EXPORTER_OTLP_LOGS_ENDPOINT')
        if not endpoint:
            return None
        return cls(endpoint, os.environ.get('OTEL_SERVICE_NAME', 'sglang-router'))

    def submit(self, record):
        # Store serialized, bounded records. Never retain a request object.
        body = json.dumps(record, separators=(',', ':'))
        if len(body.encode()) > 4096:
            self.dropped += 1
            return
        try:
            self.queue.put_nowait((time.time_ns(), body))
        except queue.Full:
            self.dropped += 1

    def _run(self):
        while not self.stop.is_set() or not self.queue.empty():
            try:
                batch = [self.queue.get(timeout=0.05)]
            except queue.Empty:
                continue
            while len(batch) < 32:
                try:
                    batch.append(self.queue.get_nowait())
                except queue.Empty:
                    break
            records = [{'timeUnixNano': str(stamp), 'severityNumber': 17,
                        'severityText': 'ERROR', 'body': {'stringValue': body}}
                       for stamp, body in batch]
            payload = {'resourceLogs': [{'resource': {'attributes': [
                {'key': 'service.name', 'value': {'stringValue': self.service}}]},
                'scopeLogs': [{'scope': {'name': 'ci.private.diagnostics'}, 'logRecords': records}]}]}
            encoded = json.dumps(payload, separators=(',', ':')).encode()
            request = urllib.request.Request(self.endpoint, data=encoded,
                                             headers={'Content-Type': 'application/json'}, method='POST')
            delivered = False
            for _ in range(2):
                try:
                    with self.opener.open(request, timeout=self.timeout) as response:
                        delivered = response.status == 200
                        raw = response.read(4097)
                        if len(raw) > 4096:
                            delivered = False
                        elif raw:
                            result = json.loads(raw)
                            partial = result.get('partialSuccess', {})
                            rejected = partial.get('rejectedLogRecords', '0')
                            delivered &= ((type(rejected) is int and rejected == 0)
                                          or (type(rejected) is str and rejected == '0'))
                    if delivered:
                        break
                    self.failures += 1
                except Exception:
                    self.failures += 1
            if delivered:
                self.sent += len(batch)
            else:
                self.dropped += len(batch)
            for _ in batch:
                self.queue.task_done()

    def close(self, timeout=1.0):
        self.stop.set()
        self.thread.join(timeout)
        return {'exported': self.sent, 'dropped': self.dropped,
                'pending': self.queue.unfinished_tasks, 'failures': self.failures}
