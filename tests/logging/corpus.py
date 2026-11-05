"""Synthetic records shared by producer and real collector tests."""
import copy
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'images/sglang-router'))
from safe_events import CONTRACT, envelope

SECRET = 'SYNTHETIC_PROMPT_OUTPUT_HEADER_TOKEN_581204'


def sample(name):
    rule = CONTRACT['field_types'][name]
    if 'enum' in rule:
        return rule['enum'][0]
    if name == 'location':
        return 'sglang/srt/managers/scheduler.py'
    if name == 'run_id':
        return '1' * 32
    if name == 'source_revision':
        return '2' * 40
    return max(rule['min'], 1)


def positives():
    return [envelope({'event': event, 'timestamp_ns':time.time_ns(), 'source_revision':'2'*40, **{key: sample(key) for key in spec['fields']}})
            for event, spec in CONTRACT['events'].items()]


def negatives():
    rows = []
    for good in positives():
        for key in ('prompt', 'body', 'response', 'headers', 'key_id', 'request_id', 'exception'):
            rows.append({**good, key: SECRET})
        for key in good:
            for bad in (SECRET, None, True, {SECRET: SECRET}, [SECRET]):
                # A false schema version or an unknown code must fail too.
                if bad != good[key] or type(bad) is not type(good[key]):
                    rows.append({**good, key: bad})
        for required in CONTRACT['events'][good['event']]['required']:
            row = dict(good)
            del row[required]
            rows.append(row)
    rows += [None, True, [], {}, SECRET, {'event': SECRET}, {'event': []}]
    return rows
