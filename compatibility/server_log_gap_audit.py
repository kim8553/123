#!/usr/bin/env python3
"""Summarize unhandled server routes without publishing log content or addresses."""
import argparse
import json
import re
from collections import Counter
from pathlib import Path

_PREFIX = re.compile(r'^\d{4}/\d\d/\d\d\s+\d\d:\d\d:\d\d\s+\S+:\d+:\s*')
_UNHANDLED = re.compile(r'^(?P<family>[\w -]+?)\s+unhandled(?:\s+sub=(?P<sub>\d+))?\b', re.I)


def audit(path: Path):
    counts = Counter()
    lines = 0
    with path.open('r', encoding='utf-8', errors='replace') as src:
        for line in src:
            lines += 1
            if 'unhandled' not in line.lower():
                continue
            text = _PREFIX.sub('', line.strip())
            match = _UNHANDLED.match(text)
            if not match:
                counts['UNCLASSIFIED'] += 1
                continue
            family = match.group('family').strip().lower()
            if not re.fullmatch(r'[a-z_0-9 -]{1,40}', family):
                counts['UNCLASSIFIED'] += 1
            else:
                counts[f'{family} / sub={match.group("sub") or "unspecified"}'] += 1
    return {'file': path.name, 'lines_scanned': lines,
            'unhandled_observations': sum(counts.values()),
            'route_counts': dict(sorted(counts.items())),
            'interpretation': 'Observed server log branches only; not proof of official protocol mismatch or missing skills.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('server_log', type=Path)
    args = p.parse_args()
    print(json.dumps(audit(args.server_log), indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
