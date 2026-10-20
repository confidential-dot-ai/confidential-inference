#!/usr/bin/env python3
"""Publish a metadata-only worker change for a controlled candidate rehearsal."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
RECIPE = Path(__file__).resolve().parent
BASE = 'ghcr.io/confidential-dot-ai/confidential-inference/sglang@sha256:dc3af4232bfc45903fb4e6401d955a248e60d5c8b1aa42cbfa95c41e6d562c14'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    if args.receipt.exists():
        parser.error('The receipt already exists. Keep it and use a new attempt.')
    if (RECIPE / 'Dockerfile').read_text().splitlines()[0] != 'FROM ' + BASE:
        parser.error('The rehearsal base differs from the reviewed pin.')
    subprocess.run(['git', '-C', str(ROOT), 'diff', '--quiet', 'HEAD', '--', str(RECIPE)], check=True)
    source = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    epoch = subprocess.check_output(['git', '-C', str(ROOT), 'show', '-s', '--format=%ct', source], text=True).strip()
    tag = 'ghcr.io/confidential-dot-ai/confidential-inference/sglang:worker-rehearsal-' + source
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    metadata = args.receipt.with_name(args.receipt.stem + '-build-metadata.json')
    if metadata.exists():
        parser.error('Build metadata already exists. Keep the previous attempt.')
    started, clock = time.time(), time.monotonic()
    receipt = {'schemaVersion': 'confidential.ai/worker-rehearsal-image/v1', 'sourceCommit': source,
               'base': BASE, 'tag': tag, 'startedAt': started, 'status': 'building',
               'change': 'OCI metadata only; worker files and startup are inherited from the pinned base'}
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    try:
        subprocess.run(['docker', 'buildx', 'build', '--platform', 'linux/amd64', '--provenance=false',
                        '--sbom=false', '--push', '--metadata-file', str(metadata),
                        '--build-arg', 'SOURCE_REVISION=' + source,
                        '--build-arg', 'SOURCE_DATE_EPOCH=' + epoch,
                        '--file', str(RECIPE / 'Dockerfile'), '--tag', tag, str(RECIPE)], check=True)
        digest = json.loads(metadata.read_text())['containerimage.digest']
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest) or digest == BASE.split('@')[1]:
            raise RuntimeError('The build did not produce a distinct pinned worker digest.')
        receipt.update(status='published', image=tag.split(':')[0] + '@' + digest)
    except BaseException as error:
        receipt.update(status='failed', errorType=type(error).__name__)
        raise
    finally:
        receipt.update(finishedAt=time.time(), durationSeconds=time.monotonic() - clock)
        args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'image': receipt['image'], 'durationSeconds': receipt['durationSeconds']}))


if __name__ == '__main__':
    main()
