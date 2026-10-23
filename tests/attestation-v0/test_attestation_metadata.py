"""Check metadata without presenting it as connection evidence."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import runpy
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
VERIFY = runpy.run_path(str(ROOT / 'scripts/verify-public-attestation.py'))


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.response = json.loads((ROOT / 'tests/api/fixtures/workload-attestation.v3.valid.json').read_text())
        self.policy = self.response['c8s']['activeAllowlist']['document']
        self.raw = json.dumps(self.policy, separators=(',', ':')).encode() + b'\n'
        self.response['c8s']['activeAllowlist']['sha256'] = 'sha256:' + hashlib.sha256(self.raw).hexdigest()
        self.args = argparse.Namespace(metadata_only=True, operator_public_key=None, expected_operator_key_sha256=None)

    def check(self, response=None, raw=None):
        value = self.response if response is None else response
        VERIFY['validate_schema'](value, VERIFY['RESPONSE_SCHEMA'], 'metadata')
        return VERIFY['verify_policy_metadata'](value, self.args, value['release']['id'],
            self.response['release']['bundleSha256'], self.raw if raw is None else raw, self.policy)

    def test_success_reports_only_a_trusted_input_match(self):
        result = self.check()
        self.assertTrue(result['metadataMatchesTrustedInputs'])
        self.assertFalse(result['connectionVerified'])
        self.assertNotIn('verified', result)
        self.assertNotIn('receipts', result)

    def test_metadata_mode_is_explicit(self):
        self.args.metadata_only = False
        with self.assertRaisesRegex(VERIFY['VerificationError'], 'not workload receipts'):
            self.check()

    def test_exact_bytes_include_a_received_newline(self):
        with self.assertRaisesRegex(VERIFY['VerificationError'], 'trusted exact bytes'):
            self.check(raw=self.raw.rstrip(b'\n'))

    def test_changed_policy_release_and_url_fail(self):
        for field in ('policy', 'release', 'url'):
            changed = copy.deepcopy(self.response)
            if field == 'policy':
                changed['c8s']['activeAllowlist']['document']['workloads'] = {'unapproved': {'containers': [], 'initContainers': []}}
            elif field == 'release':
                changed['release']['bundleSha256'] = 'sha256:' + '0' * 64
            else:
                changed['release']['url'] = 'https://github.com/other/release'
            with self.subTest(field=field), self.assertRaises(VERIFY['VerificationError']):
                self.check(changed)

    def test_version_specific_errors_name_the_field(self):
        changed = copy.deepcopy(self.response)
        del changed['release']['url']
        with self.assertRaisesRegex(VERIFY['VerificationError'], 'release'):
            self.check(changed)
        changed['schemaVersion'] = []
        with self.assertRaises(VERIFY['VerificationError']):
            self.check(changed)

    def test_pending_release_has_no_false_identity_and_fails_verification(self):
        changed = copy.deepcopy(self.response)
        desired = changed['release']
        changed['release'] = None
        changed['releaseSelection'] = {
            'status': 'pending', 'desired': desired,
            'desiredPolicySha256': 'sha256:' + 'a' * 64,
            'observedPolicySha256': changed['c8s']['activeAllowlist']['sha256'],
        }
        VERIFY['validate_schema'](changed, VERIFY['RESPONSE_SCHEMA'], 'metadata')
        with self.assertRaisesRegex(VERIFY['VerificationError'], 'selection is pending'):
            VERIFY['verify_policy_metadata'](changed, self.args, desired['id'],
                desired['bundleSha256'], self.raw, self.policy)
        changed['releaseSelection']['status'] = 'matched'
        with self.assertRaises(VERIFY['VerificationError']):
            VERIFY['validate_schema'](changed, VERIFY['RESPONSE_SCHEMA'], 'metadata')

    def test_matched_release_keeps_existing_verification(self):
        self.response['releaseSelection'] = {
            'status': 'matched', 'desired': copy.deepcopy(self.response['release']),
            'desiredPolicySha256': self.response['c8s']['activeAllowlist']['sha256'],
            'observedPolicySha256': self.response['c8s']['activeAllowlist']['sha256'],
        }
        self.assertTrue(self.check()['metadataMatchesTrustedInputs'])


if __name__ == '__main__':
    unittest.main()
