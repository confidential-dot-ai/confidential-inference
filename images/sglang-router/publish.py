#!/usr/bin/env python3
"""Publish one reviewed local router image and record its immutable digest."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
RECIPE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    if args.receipt.exists():
        parser.error('Keep the existing publication receipt. Use a new attempt.')
    image = json.loads(subprocess.check_output(['docker', 'image', 'inspect', args.image]))[0]
    labels = image['Config'].get('Labels', {})
    source = labels.get('org.opencontainers.image.revision', '')
    if not re.fullmatch(r'[0-9a-f]{40}', source) or image['Architecture'] != 'amd64' or image['Os'] != 'linux':
        parser.error('The local image has no held source commit or platform.')
    if labels.get('org.opencontainers.image.title') != 'Confidential Inference SGLang Router':
        parser.error('The local image is not the router artifact.')
    subprocess.run(['git', '-C', str(ROOT), 'cat-file', '-e', source + '^{commit}'], check=True)
    subprocess.run(['git', '-C', str(ROOT), 'diff', '--quiet', source, '--',
                    'images/sglang-router/Dockerfile', 'images/sglang-router/source.lock',
                    'images/sglang-router/Cargo.lock', 'images/sglang-router/requirements.lock',
                    'images/sglang-router/patches'], check=True)
    reference = json.loads((RECIPE / 'source.lock').read_text())['deploymentImage']['reference']
    if reference != 'ghcr.io/confidential-dot-ai/confidential-inference/sglang-router':
        parser.error('The publication repository differs from the reviewed router repository.')
    tag = reference + ':worker-model-rehearsal-' + source
    started, clock = time.time(), time.monotonic()
    receipt = {'schemaVersion': 'confidential.ai/router-development-publication/v1',
               'sourceCommit': source, 'localImageId': image['Id'], 'tag': tag,
               'startedAt': started, 'status': 'publishing', 'signedRelease': False}
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    try:
        subprocess.run(['docker', 'tag', image['Id'], tag], check=True)
        subprocess.run(['docker', 'push', tag], check=True)
        published = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tag]))[0]
        refs = [value for value in published['RepoDigests'] if value.startswith(reference + '@sha256:')]
        if len(refs) != 1:
            raise RuntimeError('The publication has no unique repository digest.')
        receipt.update(status='published', image=refs[0])
    except BaseException as error:
        receipt.update(status='failed', errorType=type(error).__name__)
        raise
    finally:
        receipt.update(finishedAt=time.time(), durationSeconds=time.monotonic() - clock)
        args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'image': receipt['image'], 'durationSeconds': receipt['durationSeconds']}))


if __name__ == '__main__':
    main()
