"""Check that the rehearsal image verifier rejects runtime or byte changes."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

path = Path(__file__).resolve().parents[1] / 'images/sglang/rehearsal/verify.py'
spec = importlib.util.spec_from_file_location('worker_rehearsal_verify', path)
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class WorkerRehearsalImageTests(unittest.TestCase):
    def setUp(self):
        self.receipt = {'status': 'published', 'base': 'base@sha256:held',
                        'image': 'new@sha256:held', 'sourceCommit': 'a' * 40}
        self.manifest = {'layers': [{'digest': 'sha256:bytes', 'size': 123, 'mediaType': 'gzip'}]}
        self.base = {'rootfs': {'diff_ids': ['sha256:uncompressed']},
                     'config': {'Cmd': ['serve'], 'Env': ['MODE=prod'], 'User': '1000', 'Labels': {}}}
        self.new = copy.deepcopy(self.base)
        self.new['config']['Labels'] = {'org.opencontainers.image.revision': 'a' * 40,
                                       'ai.confidential.worker.rehearsal': 'worker-model-update-v1'}

    def test_same_bytes_allow_only_documented_label_and_layer_annotation_changes(self):
        base = copy.deepcopy(self.manifest)
        base['layers'][0]['annotations'] = {'buildkit/rewritten-timestamp': 'old'}
        with patch.object(verify, 'read_image', side_effect=[(base, self.base), (self.manifest, self.new)]):
            result = verify.verify(self.receipt)
        self.assertTrue(result['sameLayers'])
        self.assertTrue(result['sameRuntimeConfig'])

    def test_changed_files_startup_or_unapproved_labels_fail(self):
        for mutate in (lambda m, c: m['layers'][0].update(digest='sha256:other'),
                       lambda m, c: c['rootfs'].update(diff_ids=['sha256:other']),
                       lambda m, c: c['config'].update(Cmd=['different-server']),
                       lambda m, c: c['config'].update(Env=['MODE=other']),
                       lambda m, c: c['config']['Labels'].update({'unapproved': 'value'}),
                       lambda m, c: c['config']['Labels'].update({'org.opencontainers.image.revision': 'b' * 40})):
            manifest, config = copy.deepcopy(self.manifest), copy.deepcopy(self.new)
            mutate(manifest, config)
            with patch.object(verify, 'read_image', side_effect=[(self.manifest, self.base), (manifest, config)]), \
                 self.assertRaises(RuntimeError):
                verify.verify(self.receipt)
