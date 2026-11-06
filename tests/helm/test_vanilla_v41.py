"""Check isolation, sampling mode, model identity and liveness for plain V4.1."""
import json
from pathlib import Path
import subprocess
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]
MODEL = "deepseek-ai/DeepSeek-V4.1-Flash-1017"


class VanillaV41Tests(unittest.TestCase):
    def test_two_full_workers_and_exact_1017_identity(self):
        output = subprocess.check_output([
            "helm", "template", "test", str(ROOT / "helm/confidential-inference"),
            "--namespace", "confidential-inference",
            "-f", str(ROOT / "tests/helm/fixtures/vanilla-v41-values.yaml"),
        ], text=True)
        docs = [d for d in yaml.safe_load_all(output) if d]
        workers = [d for d in docs if d['kind'] == 'StatefulSet'
                   and d['metadata']['name'].startswith('inference-worker-')]
        self.assertEqual(2, len(workers))
        nodes = set()
        for worker in workers:
            spec = worker['spec']['template']['spec']
            nodes.add(spec['nodeSelector']['kubernetes.io/hostname'])
            c = next(c for c in spec['containers'] if c['name'] == 'sglang')
            args = c['args']
            self.assertIn('--tp=4', args)
            self.assertIn('--served-model-name=' + MODEL, args)
            self.assertIn('--tool-call-parser=deepseekv41', args)
            self.assertIn('--private-server-output', args)
            self.assertIn('--flashinfer-allreduce-fusion-backend=trtllm', args)
            self.assertFalse(any('speculative-algorithm' in a or 'disaggregation-mode' in a
                                 or 'hierarchical-cache' in a for a in args))
            self.assertEqual('/health', c['livenessProbe']['httpGet']['path'])
            self.assertLessEqual(c['livenessProbe']['timeoutSeconds'], 5)
            self.assertEqual(4, int(c['resources']['limits']['nvidia.com/gpu']))
        self.assertEqual(2, len(nodes))
        gateway = next(d for d in docs if d['kind'] == 'Deployment'
                       and d['metadata']['name'] == 'gateway')
        env = next(c for c in gateway['spec']['template']['spec']['containers']
                   if c['name'] == 'gateway')['env']
        settings = json.loads(next(e['value'] for e in env if e['name'] == 'GATEWAY_RUNTIME_CONFIG'))
        self.assertEqual([MODEL], settings['catalogModelIds'])
        self.assertEqual([MODEL], settings['inferenceModelIds'])


if __name__ == '__main__':
    unittest.main()
