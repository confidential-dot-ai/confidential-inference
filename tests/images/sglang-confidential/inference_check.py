"""Public synthetic inference checks. Reports contain numeric results only."""
import argparse
import concurrent.futures
import json
import math
from pathlib import Path
import random
import statistics
import subprocess
import time
import urllib.error
import urllib.request
import uuid

MODEL = 'deepseek-ai/DeepSeek-V4.1-Flash'
METRICS = {'sglang:kv_transfer_total_mb_sum', 'sglang:kv_transfer_total_mb_count',
           'sglang:kv_transfer_latency_ms_sum', 'sglang:kv_transfer_latency_ms_count',
           'sglang:num_transfer_failed_reqs_total', 'sglang:num_bootstrap_failed_reqs_total'}


def metrics(url, canary):
    with urllib.request.urlopen(url, timeout=5) as response:
        raw = response.read().decode()
    assert canary not in raw, 'synthetic private value found in metrics'
    totals = {name: 0.0 for name in METRICS}
    for line in raw.splitlines():
        if line.startswith('#') or not line.strip():
            continue
        metric = line.split('{', 1)[0].split()[0]
        if metric not in METRICS:
            continue
        value = float(line.rsplit(' ', 1)[1])
        assert math.isfinite(value) and value >= 0
        totals[metric] += value
    return totals


def call(origin, index, stream=False, chat=False, words=64, canary='', long_decode=False):
    rng = random.Random(107 + index)
    numbers = ' '.join(str(rng.randrange(10000)) for _ in range(words))
    task = ('Count from 1 to 100, with one number on each line.' if long_decode
            else f'Reply with exactly this identifier and no other text: {canary}' if canary
            else 'Reply with the word READY.')
    prompt = f'Synthetic test {index}. {canary} Read these numbers: {numbers}. {task}'
    payload = {'model': MODEL, 'max_tokens': 128 if long_decode else 64, 'temperature': 0, 'stream': stream}
    route = '/v1/chat/completions' if chat else '/v1/completions'
    if chat:
        payload.update(messages=[{'role': 'user', 'content': prompt}],
                       chat_template_kwargs={'enable_thinking': False})
    else:
        template = json.loads(Path('/var/lib/user-data/sglang-recovery/test-chat-template.json').read_text())
        payload['prompt'] = template['prefix'] + prompt + template['suffix']
    if stream:
        payload['stream_options'] = {'include_usage': True}
    request = urllib.request.Request(origin + route, data=json.dumps(payload).encode(),
                                     headers={'Content-Type': 'application/json',
                                              'Authorization': 'Bearer ' + canary if canary else 'Bearer synthetic'})
    started = time.perf_counter()
    first = None
    usage = {}
    chars = 0
    output = []
    done = False
    with urllib.request.urlopen(request, timeout=180) as response:
        assert response.status == 200
        if stream:
            for raw in response:
                if not raw.startswith(b'data:'):
                    continue
                data = raw[5:].strip()
                if data == b'[DONE]':
                    done = True
                    break
                value = json.loads(data)
                usage = value.get('usage') or usage
                for choice in value.get('choices', []):
                    text = choice.get('text', '') if not chat else ''.join(
                        choice.get('delta', {}).get(key) or '' for key in ('content', 'reasoning_content'))
                    if text and first is None:
                        first = time.perf_counter()
                    chars += len(text)
                    output.append(text)
            assert done, 'missing stream completion'
        else:
            value = json.load(response)
            assert value.get('choices'), 'empty choices'
            usage = value.get('usage') or {}
            for choice in value['choices']:
                text = choice.get('text', '') if not chat else ''.join(
                    choice.get('message', {}).get(key) or '' for key in ('content', 'reasoning_content'))
                chars += len(text)
                output.append(text)
    duration = time.perf_counter() - started
    assert chars > 0, 'empty generated output'
    assert usage.get('completion_tokens', 0) > 0, 'missing completion usage'
    if long_decode:
        assert usage['completion_tokens'] >= 32, 'long decode check ended too early'
        lines = ''.join(output).strip().splitlines()
        assert len(lines) >= 16 and all(line.strip() == str(i + 1) for i, line in enumerate(lines[:16])), 'incorrect generated sequence'
    elif canary:
        assert ''.join(output).strip() == canary, 'incorrect identifier echo'
    else:
        assert ''.join(output).strip() == 'READY', 'incorrect generated answer'
    return {'index': index, 'stream': stream, 'chat': chat, 'inputWords': words,
            'durationSeconds': duration,
            'firstContentSeconds': first - started if first is not None else None,
            'outputCharacters': chars, 'promptTokens': usage.get('prompt_tokens'),
            'completionTokens': usage.get('completion_tokens')}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--origin', required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--container', action='append', default=[])
    parser.add_argument('--worker-metrics-url', action='append', default=[])
    parser.add_argument('--correctness-only', action='store_true')
    args = parser.parse_args()
    canary = 'PRIVATE_SYNTHETIC_' + uuid.uuid4().hex
    before = [metrics(url, canary) for url in args.worker_metrics_url]
    rows = []
    for chat in (False, True):
        for stream in (False, True):
            rows.append(call(args.origin, len(rows), stream, chat, canary=canary))
    if args.correctness_only:
        rows.append(call(args.origin, 90000, words=512, long_decode=True))
    for words in (() if args.correctness_only else (64, 512)):
        for concurrency in (1, 4):
            # One warm request for each shape. Its result is not in the timing sample.
            call(args.origin, words + 10000, words=words, long_decode=True)
            started = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                batch = list(pool.map(lambda i: call(args.origin, i + words * 100 + concurrency * 1000, words=words, long_decode=True), range(8)))
            elapsed = time.perf_counter() - started
            print(json.dumps({'label': args.label, 'words': words, 'concurrency': concurrency,
                              'requests': len(batch), 'elapsedSeconds': elapsed,
                              'medianRequestSeconds': statistics.median(r['durationSeconds'] for r in batch),
                              'outputTokensPerSecond': sum(r['completionTokens'] for r in batch) / elapsed}), flush=True)
            rows.extend(batch)
    for container in args.container:
        logs = subprocess.check_output(['docker', 'logs', container], stderr=subprocess.STDOUT)
        assert canary.encode() not in logs, 'synthetic private value found in logs'
    changes = [{name: after[name] - prior[name] for name in METRICS}
               for url, prior in zip(args.worker_metrics_url, before)
               for after in [metrics(url, canary)]]
    if changes:
        assert sum(row['sglang:kv_transfer_total_mb_sum'] for row in changes) > 0, 'no KV transfer bytes observed'
        for row in changes:
            assert row['sglang:num_transfer_failed_reqs_total'] == 0
            assert row['sglang:num_bootstrap_failed_reqs_total'] == 0
    print(json.dumps({'label': args.label, 'status': 'pass', 'privacyCanaryAbsent': True,
                      'checkedContainers': len(args.container), 'kvMetricChanges': changes,
                      'requests': rows}), flush=True)


if __name__ == '__main__':
    main()
