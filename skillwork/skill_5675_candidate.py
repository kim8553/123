#!/usr/bin/env python3
"""Generate a reversible SKILL-ONLY LAB CANDIDATE. Never modifies the EXE or source archive."""
import argparse
import hashlib
import io
import json
import zipfile
from pathlib import Path

from skill_cast_path_audit import (EXPECTED_EXE_SHA256, ROLE_DATA, SKILL_INIT,
                                   SKILL_NEW, TEMPLATE_DATA, by_static,
                                   inspect_exe, inspect_resources, read_one, sections)

FACULTY = 'data/faculty.json'
OLD_HEADER = b'[\xc1\xd1\xcc\xec\xc8\xad]'  # skill_new.ini GB18030: 裂天拳
NEW_HEADER = b'[\xc8\xad]'                  # JSON / skill_init raw ID: UTF-8 ȭ
OLD_ID = '\u022d'
EXPECTED_SKILL_NEW_SHA256 = '4263a384d38b40f50289b4121949d6fb497a56f0b482e7560f478cb6929b8056'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def make_candidate(payloads):
    """Pure byte edit guarded by exact original version and all related server IDs."""
    original = payloads[SKILL_NEW]
    if sha(original) != EXPECTED_SKILL_NEW_SHA256:
        raise ValueError('UNKNOWN_SKILL_NEW_VERSION: no patch')
    resource = inspect_resources({p: payloads[p] for p in (SKILL_NEW, SKILL_INIT, ROLE_DATA, TEMPLATE_DATA)})
    if not (resource['json_equals_skill_init_key'] and
            not resource['json_equals_skill_new_key'] and
            resource['json_utf8_hex'] == NEW_HEADER[1:-1].hex() and
            resource['skill_new_raw_key_hex'] == OLD_HEADER[1:-1].hex() and
            resource['json_key_occurrences_in_skill_new'] == 0 and
            resource['skill_new_script_ascii'] == 'SkillNormal'):
        raise ValueError('SKILL_ID_PRECONDITION_FAILED: no patch')
    faculty = json.loads(payloads[FACULTY])
    roles = faculty.get('roles', {})
    if set(roles) != {'2', '3', '4'} or any(
            sum(row.get('config_id') == OLD_ID for row in roles[role]['taolu']) != 1
            for role in ('2', '3', '4')):
        raise ValueError('FACULTY_ID_PRECONDITION_FAILED: no patch')
    if original.count(OLD_HEADER) != 1 or NEW_HEADER in original:
        raise ValueError('NONUNIQUE_HEADER: no patch')
    changed = original.replace(OLD_HEADER, NEW_HEADER)
    after_resource = inspect_resources({**payloads, SKILL_NEW: changed})
    if not (after_resource['json_equals_skill_new_key'] and
            after_resource['json_equals_skill_init_key'] and
            after_resource['json_key_occurrences_in_skill_new'] == 1):
        raise ValueError('CATALOG_KEY_NOT_ALIGNED: no patch')
    before, after = sections(original), sections(changed)
    if len(before) != 17855 or len(after) != len(before):
        raise ValueError('SKILL_SECTION_COUNT_CHANGED: no patch')
    differences = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
    if len(differences) != 1:
        raise ValueError('NON_TARGET_SKILL_CHANGED: no patch')
    index = differences[0]
    a, b = before[index], after[index]
    if (a['key'] != OLD_HEADER[1:-1] or b['key'] != NEW_HEADER[1:-1] or
            a['fields'] != b['fields'] or
            len(by_static(before, 5675)) != 1 or len(by_static(after, 5675)) != 1 or
            len({s['key'] for s in after}) != len(after) or
            changed.replace(NEW_HEADER, OLD_HEADER) != original):
        raise ValueError('NON_REVERSIBLE_OR_COLLIDING_CHANGE: no patch')
    return changed, {
        'status': 'EXPERIMENTAL_OFFLINE_CATALOG_KEY_CANDIDATE',
        'deployable_or_tested_in_game': False, 'exe_modified': False,
        'static_data': 5675, 'preserved_json_and_save_id': OLD_ID,
        'original_ini_sha256': sha(original), 'candidate_ini_sha256': sha(changed),
        'original_section_hex': OLD_HEADER.hex(), 'candidate_section_hex': NEW_HEADER.hex(),
        'changed_section_count': len(differences), 'skill_section_count': len(before),
        'faculty_roles_with_existing_id': ['2', '3', '4'],
        'original_exe_sha256_required': EXPECTED_EXE_SHA256,
        'limitations': ['No real cast, cooldown, damage, login, save or client test.',
                        'Changing a resource section may break unobserved references.',
                        'Never combine with the withdrawn JSON ID replacement.'],
    }


def create(archive_path, exe_path, output_path, go='go'):
    # Build identity and exact disassembly preconditions; no executable patching.
    inspect_exe(exe_path, go)
    with zipfile.ZipFile(archive_path) as z:
        payloads = {p: read_one(z, p) for p in (SKILL_NEW, SKILL_INIT, ROLE_DATA, TEMPLATE_DATA, FACULTY)}
    candidate, report = make_candidate(payloads)
    if output_path.resolve() in {archive_path.resolve(), exe_path.resolve()}:
        raise ValueError('Refusing to overwrite original input')
    notes = ('LAB CANDIDATE ONLY - DO NOT INSTALL ON LIVE SERVER.\n'
             'Only skill_new.ini section key for StaticData=5675 is changed.\n'
             'Existing JSON, skill_init.ini, faculty.json, character saves and EXE are NOT edited.\n'
             'Restore the original skill_new.ini from your original server archive or backup.\n'
             'Prior JSON rename ZIP is withdrawn and MUST NOT be combined with this candidate.\n'
             'Requires isolated Windows server/client cast + persistence tests before use.\n')
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        z.writestr(SKILL_NEW, candidate)
        z.writestr('EXPERIMENTAL_README.txt', notes)
        z.writestr('audit.json', json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    with zipfile.ZipFile(output_path) as z:
        if z.testzip() is not None or sha(z.read(SKILL_NEW)) != report['candidate_ini_sha256']:
            output_path.unlink(missing_ok=True)
            raise ValueError('Candidate ZIP validation failed')
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('server_zip', type=Path)
    ap.add_argument('server_exe', type=Path)
    ap.add_argument('--output', required=True, type=Path, help='LAB candidate ZIP; NOT a deployed game update')
    ap.add_argument('--go', default='go')
    args = ap.parse_args()
    print(json.dumps(create(args.server_zip, args.server_exe, args.output, args.go), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
