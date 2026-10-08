"""Exercise the built router against local HTTP workers, without a cluster."""
import hashlib
import tempfile
from pathlib import Path
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socket
import subprocess
import threading
import time
import unittest
import uuid


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Worker(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def reply(self, document):
        body = json.dumps(document).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply({'served_model_name': self.server.model, 'is_generation': True})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        if body.get('model') != self.server.model:
            self.send_response(400)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if not body.get('stream'):
            self.reply({'model': self.server.model, 'choices': [{'text': self.server.model}]})
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(b'data: {"choices":[{"text":"first"}]}\n\n')
        self.wfile.flush()
        if not self.server.release.wait(20):
            return
        self.wfile.write(b'data: [DONE]\n\n')
        self.wfile.flush()
        self.close_connection = True


@unittest.skipUnless(os.environ.get('ROUTER_TEST_IMAGE'), 'Set ROUTER_TEST_IMAGE to the built digest.')
class RouterImageTests(unittest.TestCase):
    def test_model_routing_and_stream_drain_in_published_image(self):
        workers = []
        name = 'ci-router-test-' + uuid.uuid4().hex[:12]
        self.addCleanup(subprocess.run, ['docker', 'rm', '-f', name], capture_output=True)
        for model in ('model-old', 'model-new'):
            server = ThreadingHTTPServer(('127.0.0.1', 0), Worker)
            server.daemon_threads = True
            server.model = model
            server.release = threading.Event()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            self.addCleanup(server.release.set)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            workers.append(server)
        route_dir = tempfile.TemporaryDirectory(prefix='ci-router-model-routes-')
        self.addCleanup(route_dir.cleanup)
        os.chmod(route_dir.name, 0o755)
        route_path = Path(route_dir.name) / 'routes.json'

        def write_routes(revision, backends):
            document = {'schemaVersion': 1, 'revision': revision,
                        'routes': {'public-model': backends} if backends else {}}
            raw = json.dumps(document, sort_keys=True).encode()
            temporary = route_path.with_suffix('.tmp')
            temporary.write_bytes(raw)
            os.chmod(temporary, 0o644)
            os.replace(temporary, route_path)
            return hashlib.sha256(raw).hexdigest()

        write_routes(0, [])
        port = free_port()
        urls = ['http://127.0.0.1:' + str(w.server_port) for w in workers]
        subprocess.run(['docker', 'run', '-d', '--name', name, '--network', 'host',
                        '--mount', 'type=bind,src=' + route_dir.name + ',dst=/model-routes,readonly',
                        '-e', 'CI_ROUTER_MODEL_ROUTES_FILE=/model-routes/routes.json',
                        os.environ['ROUTER_TEST_IMAGE'], '--host', '127.0.0.1',
                        '--port', str(port), '--prometheus-host', '127.0.0.1',
                        '--prometheus-port', str(free_port()),
                        '--policy', 'round_robin', '--enable-igw', '--disable-retries',
                        '--worker-startup-timeout-secs', '20'], check=True, capture_output=True)

        def request(method, path, body=None):
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            try:
                connection.request(method, path, None if body is None else json.dumps(body),
                                   {'Content-Type': 'application/json'})
                response = connection.getresponse()
                raw = response.read()
                try:
                    document = json.loads(raw) if raw else None
                except ValueError:
                    document = raw.decode()
                return response.status, document
            finally:
                connection.close()

        def wait_for(predicate):
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                try:
                    value = predicate()
                    if value:
                        return value
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(0.1)
            logs = subprocess.run(['docker', 'logs', name], capture_output=True, text=True)
            self.fail('Router did not reach the required state: ' + (logs.stdout + logs.stderr)[-9000:])

        wait_for(lambda: request('GET', '/health')[0] == 200)
        for url in urls:
            self.assertEqual(request('POST', '/workers', {'url': url})[0], 202)
        active = wait_for(lambda: (lambda result: result[1]['workers']
                                  if result[0] == 200 and result[1]['total'] == 2 else None)
                         (request('GET', '/workers')))
        old = next(w for w in active if w['url'] == urls[0])
        worker_id = old.get('id', old.get('worker_id'))
        self.assertIsNotNone(worker_id, old)
        drain = '/workers/' + worker_id + '/drain'
        payload = {'model': 'model-old', 'prompt': 'test', 'max_tokens': 4}
        self.assertEqual(request('POST', '/v1/completions', payload)[1]['model'], 'model-old')
        other = {**payload, 'model': 'model-new'}
        self.assertEqual(request('POST', '/v1/completions', other)[1]['model'], 'model-new')

        alias_payload = {**payload, 'model': 'public-model'}
        mixed_hash = write_routes(1, ['model-old', 'model-new'])
        reload_path = '/model-routes/reload'
        self.assertEqual(request('POST', reload_path, {'expected_revision': 0, 'sha256': 'wrong'})[0], 409)
        self.assertEqual(request('POST', reload_path, {'expected_revision': 7, 'sha256': mixed_hash})[0], 409)
        self.assertEqual(request('POST', reload_path, {'expected_revision': 0, 'sha256': mixed_hash})[0], 200)
        self.assertEqual(request('POST', reload_path, {'expected_revision': 0, 'sha256': mixed_hash})[0], 200)
        observed = set()
        for _ in range(8):
            status, result = request('POST', '/v1/completions', alias_payload)
            self.assertEqual(status, 200)
            observed.add(result['model'])
        self.assertEqual(observed, {'model-old', 'model-new'})
        unknown_hash = write_routes(2, ['unknown'])
        self.assertEqual(request('POST', reload_path, {'expected_revision': 1, 'sha256': unknown_hash})[0], 409)
        self.assertEqual(request('GET', '/model-routes')[1]['revision'], 1)
        old_hash = write_routes(2, ['model-old'])
        self.assertEqual(request('POST', reload_path, {'expected_revision': 1, 'sha256': old_hash})[0], 200)

        stream = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
        self.addCleanup(stream.close)
        stream.request('POST', '/v1/completions', json.dumps({**alias_payload, 'stream': True}),
                       {'Content-Type': 'application/json'})
        response = stream.getresponse()
        self.assertEqual(response.status, 200)
        self.assertIn(b'first', response.readline())
        next_hash = write_routes(3, ['model-new'])
        self.assertEqual(request('POST', reload_path, {'expected_revision': 2, 'sha256': next_hash})[0], 200)
        for _ in range(4):
            status, result = request('POST', '/v1/completions', alias_payload)
            self.assertEqual(status, 200)
            self.assertEqual(result['model'], 'model-new')
        status, evidence = request('POST', drain, {})
        self.assertEqual(status, 200)
        self.assertEqual(evidence['active_requests'], 1)
        self.assertNotEqual(request('POST', '/v1/completions', payload)[0], 200)
        status, result = request('POST', '/v1/completions', other)
        self.assertEqual(status, 200)
        self.assertEqual(result['model'], 'model-new')
        self.assertNotEqual(request('POST', '/v1/completions', {**payload, 'model': 'unknown'})[0], 200)
        self.assertEqual(request('DELETE', drain)[0], 409, 'Do not clear the fence with a live stream.')
        # A queued management registration must not defeat the withdrawal fence.
        self.assertEqual(request('POST', '/workers', {'url': urls[0]})[0], 202)
        time.sleep(1)
        self.assertEqual(request('GET', drain)[1]['active_requests'], 1)
        self.assertNotEqual(request('POST', '/v1/completions', payload)[0], 200)
        workers[0].release.set()
        self.assertIn(b'[DONE]', response.read())
        wait_for(lambda: request('GET', drain)[1]['active_requests'] == 0)
        self.assertEqual(request('DELETE', drain)[0], 204)
        self.assertEqual(request('POST', '/workers', {'url': urls[0]})[0], 202)
        wait_for(lambda: request('GET', '/workers')[1]['total'] == 2)
        status, result = request('POST', '/v1/completions', payload)
        self.assertEqual(status, 200)
        self.assertEqual(result['model'], 'model-old')


        # A restart reads the committed file. There is no route-control replay.
        subprocess.run(['docker', 'restart', name], check=True, capture_output=True)
        wait_for(lambda: request('GET', '/health')[0] == 200)
        routes = request('GET', '/model-routes')[1]
        self.assertEqual(routes['revision'], 3)
        self.assertEqual(routes['routes'], {'public-model': ['model-new']})
        for url in urls:
            self.assertEqual(request('POST', '/workers', {'url': url})[0], 202)
        wait_for(lambda: request('GET', '/workers')[1]['total'] == 2)
        status, result = request('POST', '/v1/completions', alias_payload)
        self.assertEqual(status, 200)
        self.assertEqual(result['model'], 'model-new')


if __name__ == '__main__':
    unittest.main()
