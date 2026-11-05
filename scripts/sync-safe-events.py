#!/usr/bin/env python3
"""Keep the chart and Rust copies equal to the application event contract."""
import argparse
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = root / 'images/sglang-router/safe_events.json'
targets = [root / 'helm/confidential-inference/files/safe_events.json',
           root / 'services/gateway/src/safe_events.json']
parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
for target in targets:
    if args.check:
        if not target.exists() or target.read_bytes() != source.read_bytes():
            raise SystemExit('application event contract copies differ')
    else:
        target.write_bytes(source.read_bytes())
