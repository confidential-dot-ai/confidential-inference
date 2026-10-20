#!/usr/bin/env python3
"""Verify that the published rehearsal image changes metadata only."""
import argparse
import json
from pathlib import Path
import subprocess
import time


def read_image(reference):
    def raw(ref):
        return json.loads(subprocess.check_output(['docker', 'buildx', 'imagetools', 'inspect', '--raw', ref]))
    manifest = raw(reference)
    if 'manifests' in manifest:
        matches = [item for item in manifest['manifests'] if item.get('platform', {}).get('os') == 'linux'
                   and item.get('platform', {}).get('architecture') == 'amd64']
        if len(matches) != 1:
            raise RuntimeError('The image does not have one Linux amd64 manifest.')
        reference = reference.split('@')[0] + '@' + matches[0]['digest']
        manifest = raw(reference)
    config = json.loads(subprocess.check_output(['docker', 'buildx', 'imagetools', 'inspect',
                                                '--format', '{{json .Image}}', reference]))
    return manifest, config


def verify(receipt):
    if receipt.get('status') != 'published':
        raise RuntimeError('A published image receipt is required.')
    base, old = read_image(receipt['base'])
    image, new = read_image(receipt['image'])
    # BuildKit can omit layer annotations. The digest, size, and media type
    # identify the same compressed layer bytes despite that metadata difference.
    layers = lambda manifest: [{key: item[key] for key in ('digest', 'size', 'mediaType')}
                               for item in manifest['layers']]
    if layers(base) != layers(image) or old['rootfs'] != new['rootfs']:
        raise RuntimeError('The rehearsal image changes filesystem layers.')
    old_config, new_config = old['config'], new['config']
    runtime = lambda config: {key: value for key, value in config.items() if key != 'Labels'}
    if runtime(old_config) != runtime(new_config):
        raise RuntimeError('The rehearsal image changes worker startup settings.')
    before, after = old_config.get('Labels', {}), new_config.get('Labels', {})
    changed = {key for key in before.keys() | after.keys() if before.get(key) != after.get(key)}
    allowed = {'org.opencontainers.image.source', 'org.opencontainers.image.revision',
               'ai.confidential.build.source-date-epoch', 'ai.confidential.worker.rehearsal'}
    if not changed <= allowed or after.get('org.opencontainers.image.revision') != receipt['sourceCommit'] \
            or after.get('ai.confidential.worker.rehearsal') != 'worker-model-update-v1':
        raise RuntimeError('The rehearsal image labels differ from the held source.')
    return {'schemaVersion': 'confidential.ai/worker-rehearsal-image-verification/v1',
            'base': receipt['base'], 'image': receipt['image'], 'sameLayers': True,
            'sameRuntimeConfig': True, 'changedLabels': sorted(changed), 'verifiedAt': time.time()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    result = verify(json.loads(args.receipt.read_text()))
    output = args.receipt.with_name(args.receipt.stem + '-verification.json')
    if output.exists():
        parser.error('Verification evidence already exists. Keep it.')
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'image': result['image'], 'sameLayers': True, 'sameRuntimeConfig': True}))


if __name__ == '__main__':
    main()
