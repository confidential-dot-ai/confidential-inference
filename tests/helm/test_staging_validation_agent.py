"""Check the exact staging task protocol and its endpoint limits."""
from pathlib import Path
import runpy
import unittest
import urllib.error
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
AGENT = runpy.run_path(str(ROOT / 'helm/confidential-inference/files/staging-validation-agent.py'))
GATEWAY = 'c8s-gateway.confidential-inference-staging.svc.cluster.local'
ROUTER = 'sglang-router.confidential-inference-staging.svc.cluster.local'


class StagingAgentTests(unittest.TestCase):
    def check(self, url, method='GET', **extra):
        return AGENT['validate_action']({'name': 'test', 'url': url, 'method': method, **extra},
                                        [GATEWAY], [ROUTER])

    def test_only_missing_task_is_idle_and_authentication_failure_is_visible(self):
        for status in (404, 401, 403, 500):
            error = urllib.error.HTTPError("https://kubernetes.default.svc/held-task", status, "safe", {}, None)
            with mock.patch.object(AGENT['urllib'].request, 'urlopen', side_effect=error):
                if status == 404:
                    self.assertIsNone(AGENT['read_task_secret'](object(), object()))
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        AGENT['read_task_secret'](object(), object())

    def test_native_configuration_status_and_public_inference_are_permitted(self):
        for path in ('/runtime-config', '/metrics'):
            self.check(f'http://{GATEWAY}:9090{path}')
        for path in ('/model-routes', '/model-routes/status', '/health', '/readiness'):
            self.check(f'http://{ROUTER}:30000{path}')
        self.check(f'http://{GATEWAY}:9443/v1/chat/completions', 'POST', body='{}')

    def test_mutations_unlisted_targets_and_unbounded_inputs_are_rejected(self):
        urls = [f'http://{GATEWAY}:9443/admin/v1/api-keys/snapshot',
                f'http://{GATEWAY}:9443/admin/v1/api-keys/source',
                f'http://{ROUTER}:30000/workers/held/drain',
                f'http://{ROUTER}:30000/model-routes/reload',
                f'http://{GATEWAY}:9443/runtime-config',
                f'http://{ROUTER}:9090/model-routes/status',
                f'http://{ROUTER}:30000/model-routes/status?override=1',
                f'http://user@{GATEWAY}:9090/runtime-config',
                f'http://{GATEWAY}:9090/runtime-config#fragment',
                'http://unlisted.confidential-inference-staging.svc.cluster.local:9090/runtime-config']
        for url in urls:
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.check(url)
        for method in ('PUT', 'POST', 'DELETE'):
            with self.subTest(method=method), self.assertRaises(ValueError):
                self.check(f'http://{GATEWAY}:9090/runtime-config', method)
        with self.assertRaises(ValueError):
            self.check(f'http://{GATEWAY}:9090/runtime-config', body='{}')
        with self.assertRaises(ValueError):
            self.check(f'http://{GATEWAY}:9443/v1/chat/completions', 'POST', body='x' * (4 * 1024 * 1024 + 1))


if __name__ == '__main__':
    unittest.main()
