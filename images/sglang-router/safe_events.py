"""Validate application events before local output or delivery queues."""
import json
from pathlib import Path
import re

CONTRACT = json.loads(Path(__file__).with_name('safe_events.json').read_text())


def valid_field(name, value):
    rule = CONTRACT['field_types'][name]
    if 'enum' in rule:
        return type(value) is str and value in rule['enum']
    if 'pattern' in rule:
        return type(value) is str and re.fullmatch(rule['pattern'], value) is not None
    return type(value) is int and rule['min'] <= value <= rule['max']


def validate(record):
    if type(record) is not dict or len(record) > 48:
        return None
    record = dict(record)  # Freeze the primitive fields before validation.
    event = record.get('event')
    if type(event) is not str or event not in CONTRACT['events']:
        return None
    spec = CONTRACT['events'][event]
    if type(record.get('schema_version')) is not int or record['schema_version'] != CONTRACT['schema_version']:
        return None
    if record.get('component') != spec['component']:
        return None
    allowed = set(CONTRACT['envelope_fields']) | set(spec['fields'])
    if record.keys() - allowed or not set(spec['required']) <= record.keys():
        return None
    for key, value in record.items():
        if key not in {'event', 'component', 'schema_version'} and not valid_field(key, value):
            return None
    try:
        if len(json.dumps(record, separators=(',', ':')).encode()) > CONTRACT['maximum_record_bytes']:
            return None
    except (ValueError, TypeError, RecursionError):
        return None
    return dict(record)


def envelope(record):
    """Add only fixed version and source identity. Never infer a new event."""
    if type(record) is not dict or type(record.get('event')) is not str:
        return None
    spec = CONTRACT['events'].get(record['event'])
    if spec is None:
        return None
    return validate({'schema_version': CONTRACT['schema_version'], 'component': spec['component'], **record})
