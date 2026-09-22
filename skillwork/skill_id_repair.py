#!/usr/bin/env python3
"""Audit a server skill ID inconsistency; optionally create a reversible DATA-ONLY patch.

Never edits the source archive, server EXE, user saves, or remote repositories.
The generated ZIP contains only two patched JSON files, not a deployable server.
"""
import argparse
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path

TARGETS = {'data/skills.json': 2, 'data/技能数据.json': 1}
INI = 'resources/modern/share/skill/skill_new.ini'
INIT = 'resources/modern/share/skill/skill_init.ini'
OLD = 'ȭ'
STATIC = 5675


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def find_entry(archive, suffix):
    matches = [n for n in archive.namelist() if n.endswith('/' + suffix) or n == suffix]
    if len(matches) != 1:
        raise ValueError(f'Expected one {suffix!r}, found {len(matches)}')
    return matches[0]


def sections_by_static_data(ini_bytes, static_id):
    # The supplied skill_new.ini uses GB18030/GBK section names, not UTF-8.
    text = ini_bytes.decode('gb18030', errors='strict')
    headers = list(re.finditer(r'^\[([^\]\r\n]+)\][ \t]*\r?$', text, re.M))
    result = []
    for i, header in enumerate(headers):
        part = text[header.end():headers[i + 1].start() if i + 1 < len(headers) else len(text)]
        for line in part.splitlines():
            match = re.fullmatch(r'\s*StaticData\s*=\s*(\d+)\s*', line, re.I)
            if match and int(match.group(1)) == static_id:
                result.append(header.group(1))
    return result


def skill_rows(obj, path):
    if path == 'data/skills.json':
        roles = obj['roles']
        if set(roles) != {'2', '4'}:
            raise ValueError('Unexpected role set; refusing to change it')
        return [row for role in ('2', '4') for row in roles[role]['skills']]
    return obj['skills']


def patch_one(data, path, new_id):
    original = json.loads(data)
    rows = skill_rows(original, path)
    matches = [row for row in rows if row.get('config_id') == OLD]
    if len(matches) != TARGETS[path] or any(row.get('static_data') != STATIC for row in matches):
        raise ValueError(f'{path}: unexpected old ID count or StaticData; no patch made')
    if any(row.get('config_id') == new_id for row in rows):
        raise ValueError(f'{path}: destination ID exists; no patch made')
    needle = json.dumps(OLD, ensure_ascii=False).encode('utf-8')
    replacement = json.dumps(new_id, ensure_ascii=False).encode('utf-8')
    # Do not rewrite unrelated JSON, reorder fields, or alter skill level/progress.
    exact = b'"config_id": ' + needle
    if data.count(exact) != TARGETS[path]:
        raise ValueError(f'{path}: expected exact JSON layout not found; no patch made')
    patched = data.replace(exact, b'"config_id": ' + replacement)
    changed = json.loads(patched)
    changed_rows = skill_rows(changed, path)
    if len(changed_rows) != len(rows):
        raise ValueError(f'{path}: row count changed')
    for old_row, changed_row in zip(rows, changed_rows):
        expected = dict(old_row)
        if old_row.get('config_id') == OLD:
            expected['config_id'] = new_id
        if expected != changed_row:
            raise ValueError(f'{path}: an unintended field changed')
    return patched


def run(source, output=None):
    with zipfile.ZipFile(source) as archive:
        inputs = {path: archive.read(find_entry(archive, path)) for path in TARGETS}
        names = sections_by_static_data(archive.read(find_entry(archive, INI)), STATIC)
        init_names = sections_by_static_data(archive.read(find_entry(archive, INIT)), STATIC)
    # A single matching StaticData in skill_new.ini is insufficient: the server
    # separately loads skill_init.ini and may index skills by its section name.
    # Never emit a candidate patch when either source is ambiguous or differs.
    conflicted = len(names) != 1 or len(init_names) != 1 or names != init_names or names == [OLD]
    if conflicted:
        report = {
            'status': 'BLOCKED_RESOURCE_CONFLICT', 'can_patch': False,
            'static_data': STATIC, 'json_config_id': OLD,
            'skill_new_ids': names, 'skill_init_ids': init_names,
            'reason': 'Skill resources disagree or do not uniquely identify the same config_id; no safe replacement established.',
            'files': {path: {'old_sha256': sha256(data)} for path, data in inputs.items()},
        }
        if output is not None:
            raise ValueError('BLOCKED_RESOURCE_CONFLICT: skill_new.ini and skill_init.ini disagree; no patch created')
        return report
    if len(names) != 1 or not names[0] or names[0] == OLD:
        raise ValueError(f'Expected a unique distinct resource name at StaticData={STATIC}, got {names!r}')
    result = {'status': 'AUDIT_ONLY' if output is None else 'DATA_PATCH_CREATED',
              'can_patch': True, 'old_config_id': OLD, 'resource_config_id': names[0],
              'skill_init_config_id': init_names[0], 'static_data': STATIC,
              'files': {}}
    changed = {}
    for path, data in inputs.items():
        patched = patch_one(data, path, names[0])
        changed[path] = patched
        result['files'][path] = {'old_sha256': sha256(data), 'new_sha256': sha256(patched),
                                 'replacements': TARGETS[path]}
    if output is not None:
        out = Path(output)
        if out.resolve() == Path(source).resolve():
            raise ValueError('Refusing to overwrite source archive')
        out.parent.mkdir(parents=True, exist_ok=True)
        notes = ('EXPERIMENTAL DATA-ONLY SKILL ID REPAIR\n'
                 'Replaces ȭ -> 裂天拳 ONLY where config_id has StaticData 5675.\n'
                 'This is NOT an EXE patch, a missing-skill implementation, or evidence of official-client compatibility.\n'
                 'Back up original data/skills.json, data/技能数据.json, and player saves.\n'
                 'Old persisted references to ȭ are NOT migrated. Do NOT apply to production without a save migration and Windows gameplay test.\n')
        with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as patch_zip:
            for path, content in changed.items():
                patch_zip.writestr(path, content)
            patch_zip.writestr('SKILL_PATCH_README.txt', notes)
            patch_zip.writestr('audit.json', json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        result['patch_zip'] = str(out)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('server_zip', type=Path, help='Inner server ZIP, containing data/skills.json')
    parser.add_argument('--output', type=Path, help='Optional output ZIP; original server ZIP remains untouched')
    args = parser.parse_args()
    result = run(args.server_zip, args.output)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if not result['can_patch']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
