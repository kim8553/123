#!/usr/bin/env python3
"""Read-only audit of skill INI identities as byte strings, matching Go's INI key handling.

No skill patches, EXE changes, raw client data, or character saves are emitted.
This models INI section-name bytes and duplicate fields; it does not execute the game.
"""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import zipfile

NEW = 'resources/modern/share/skill/skill_new.ini'
INIT = 'resources/modern/share/skill/skill_init.ini'
ROLE = 'data/skills.json'
TEMPLATE = 'data/技能数据.json'
STATIC = 5675


def member(archive, suffix):
    matches = [n for n in archive.namelist() if n == suffix or n.endswith('/' + suffix)]
    if len(matches) != 1:
        raise ValueError(f'Expected precisely one {suffix}, got {len(matches)}')
    return archive.read(matches[0])


def parse_ini_bytes(content):
    """Use raw string key bytes and trim ASCII whitespace as in observed Go loader.

    Go's strings.TrimSpace also trims Unicode space runes; these INI keys only
    require ASCII whitespace. This deliberately does not emulate skill execution.
    """
    sections = {}
    appearances = defaultdict(list)
    current = None
    for line in content.splitlines():
        line = line.strip()
        if not line or line[:1] in (b';', b'#'):
            continue
        if line.startswith(b'[') and line.endswith(b']'):
            current = line[1:-1].strip()
            if not current:
                raise ValueError('Empty skill section')
            sections.setdefault(current, {})
            appearances[current].append({})
        elif current is not None and b'=' in line:
            field, value = [p.strip() for p in line.split(b'=', 1)]
            if field:
                # Repeated sections share a map: later field assignments overwrite.
                sections[current][field.lower()] = value
                appearances[current][-1][field.lower()] = value
    by_static = defaultdict(list)
    for key, fields in sections.items():
        raw = fields.get(b'staticdata', b'')
        if not raw.isdigit():
            raise ValueError(f'Invalid StaticData for section hex={key.hex()}')
        by_static[int(raw)].append(key)
    return sections, appearances, by_static


def summarize_duplicate(keys, appearances):
    result = []
    for section, occurrences in sorted(appearances.items()):
        if len(occurrences) < 2:
            continue
        all_fields = set().union(*(set(row) for row in occurrences))
        conflicts = {
            key.decode('ascii', 'replace'): sorted({row.get(key, b'').decode('ascii', 'replace') for row in occurrences})
            for key in sorted(all_fields) if len({row.get(key) for row in occurrences}) > 1
        }
        static = keys[section].get(b'staticdata', b'')
        result.append({
            'static_data': int(static), 'config_id_ascii': section.decode('ascii', 'replace'),
            'occurrences': len(occurrences), 'conflicting_fields': conflicts,
        })
    return sorted(result, key=lambda row: row['static_data'])


def summarize_id(key, encoding):
    return {'raw_hex': key.hex(), 'display': key.decode(encoding, 'replace')}


def audit(archive_path):
    with zipfile.ZipFile(archive_path) as z:
        sources = {name: member(z, name) for name in (NEW, INIT, ROLE, TEMPLATE)}
    new, new_appear, new_static = parse_ini_bytes(sources[NEW])
    init, init_appear, init_static = parse_ini_bytes(sources[INIT])
    roles = json.loads(sources[ROLE])['roles']
    templates = json.loads(sources[TEMPLATE])['skills']
    role_rows = [row for role in ('2', '4') for row in roles[role]['skills']]
    target_rows = [row for row in role_rows if row.get('static_data') == STATIC]
    target_template_rows = [row for row in templates if row.get('static_data') == STATIC]
    if len(target_rows) != 2 or len(target_template_rows) != 1:
        raise ValueError('Unexpected StaticData=5675 role/template multiplicity')
    ids = {row['config_id'] for row in target_rows + target_template_rows}
    if len(ids) != 1:
        raise ValueError('StaticData=5675 uses differing role/template IDs')
    json_id = ids.pop()
    json_bytes = json_id.encode('utf-8')
    target_new, target_init = new_static.get(STATIC, []), init_static.get(STATIC, [])
    if len(target_new) != 1 or len(target_init) != 1:
        raise ValueError('StaticData=5675 resource IDs are not unique')
    common = new_static.keys() & init_static.keys()
    matches = [sid for sid in common if set(new_static[sid]) == set(init_static[sid])]
    mismatches = [sid for sid in common if set(new_static[sid]) != set(init_static[sid])]
    duplicate_init = summarize_duplicate(init, init_appear)
    duplicate_new = summarize_duplicate(new, new_appear)
    return {
        'status': 'INVESTIGATION_REQUIRED', 'safe_to_patch': False,
        'provenance': {name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()},
        'encoding_facts': {'skill_init_strict_utf8': is_utf8(sources[INIT]),
                           'skill_new_strict_utf8': is_utf8(sources[NEW])},
        'shared_static_ids': len(common), 'matching_normalized_raw_ids': len(matches),
        'different_normalized_raw_ids': sorted(mismatches),
        'only_in_skill_new_static_ids': sorted(new_static.keys() - init_static.keys()),
        'only_in_skill_init_static_ids': sorted(init_static.keys() - new_static.keys()),
        'target_5675': {
            'json_id': json_id, 'json_id_utf8_hex': json_bytes.hex(),
            'skill_init': summarize_id(target_init[0], 'utf-8'),
            'skill_new': summarize_id(target_new[0], 'gb18030'),
            'json_matches_init_raw_key': json_bytes == target_init[0],
            'json_matches_new_raw_key': json_bytes == target_new[0],
        },
        'duplicate_init_sections': duplicate_init, 'duplicate_new_sections': duplicate_new,
        'duplicate_init_with_conflicting_fields': sum(bool(d['conflicting_fields']) for d in duplicate_init),
        'warnings': [
            'This models bytes and section parsing only, not actual server casting or client behavior.',
            'The server EXE has not been patched; do not install the previously proposed JSON rename.',
            'Duplicate-field interpretation is based on observed server loader disassembly, not a Windows gameplay test.',
        ],
    }


def is_utf8(content):
    try:
        content.decode('utf-8')
    except UnicodeDecodeError:
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('server_zip', type=Path, help='Unmodified, nested server ZIP')
    parser.add_argument('--report', type=Path, help='Optional redacted JSON audit path')
    args = parser.parse_args()
    result = audit(args.server_zip)
    text = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.report:
        if args.report.resolve() == args.server_zip.resolve():
            parser.error('Refusing to overwrite server archive')
        args.report.write_text(text, encoding='utf-8')
    print(text, end='')


if __name__ == '__main__':
    main()
