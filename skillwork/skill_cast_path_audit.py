#!/usr/bin/env python3
"""Read-only, build-pinned audit of skill 5675's server catalog/normal-cast path.

Inspects only the supplied server's skill resources and a *matching SHA-256* Go PE.
Does not alter binaries, character saves, skill data or network traffic.
"""
import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path

EXPECTED_EXE_SHA256 = 'c18538e2d32ff31c332b187d57af875d5fc226285ff4d96b46d8c61b4204639c'
TARGET_STATIC = 5675
SKILL_NEW = 'resources/modern/share/skill/skill_new.ini'
SKILL_INIT = 'resources/modern/share/skill/skill_init.ini'
ROLE_DATA = 'data/skills.json'
TEMPLATE_DATA = 'data/技能数据.json'
HEADER = re.compile(rb'^\[([^\]\r\n]+)\][ \t]*\r?$')
PAIR = re.compile(rb'^\s*([A-Za-z_][A-Za-z_0-9]*)\s*=\s*([^\r\n]*)\s*$')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_one(archive, suffix):
    matches = [n for n in archive.namelist() if n == suffix or n.endswith('/' + suffix)]
    if len(matches) != 1:
        raise ValueError(f'Expected one {suffix}, found {len(matches)}')
    return archive.read(matches[0])


def sections(data):
    """Return raw section names and parsed ASCII property names (no text recoding)."""
    result = []
    current = None
    for line in data.splitlines():
        m = HEADER.fullmatch(line)
        if m:
            current = {'raw_name': m.group(1), 'key': m.group(1).strip(b' \t'), 'fields': {}}
            result.append(current)
            continue
        if current is None:
            continue
        p = PAIR.fullmatch(line)
        if p:
            current['fields'][p.group(1).lower()] = p.group(2).strip(b' \t')
    return result


def by_static(sections_, sid):
    matches = []
    for section in sections_:
        v = section['fields'].get(b'staticdata', b'')
        if v.isdigit() and int(v) == sid:
            matches.append(section)
    return matches


def json_skill_rows(raw, role_data):
    obj = json.loads(raw)
    if role_data:
        if not isinstance(obj.get('roles'), dict):
            raise ValueError('role JSON schema changed')
        return [r for role in obj['roles'].values() for r in role['skills'] if r.get('static_data') == TARGET_STATIC]
    return [r for r in obj['skills'] if r.get('static_data') == TARGET_STATIC]


def inspect_resources(payloads):
    ini_new = sections(payloads[SKILL_NEW]); ini_init = sections(payloads[SKILL_INIT])
    found_new = by_static(ini_new, TARGET_STATIC); found_init = by_static(ini_init, TARGET_STATIC)
    role = json_skill_rows(payloads[ROLE_DATA], True)
    templ = json_skill_rows(payloads[TEMPLATE_DATA], False)
    if len(found_new) != 1 or len(found_init) != 1 or len(role) != 2 or len(templ) != 1:
        raise ValueError('5675 resource or JSON identity is not unique; abort')
    json_ids = [r['config_id'] for r in role + templ]
    if not all(isinstance(s, str) for s in json_ids) or len(set(json_ids)) != 1:
        raise ValueError('5675 JSON skill IDs disagree; abort')
    json_key = json_ids[0].encode('utf-8')
    new = found_new[0]; init = found_init[0]
    # The loop in loadCombatSkillCatalog enumerates names in its first skill_new map;
    # this is a necessary catalog-key precondition, NOT a simulated server cast.
    new_key_count = sum(section['key'] == json_key for section in ini_new)
    return {
        'static_data': TARGET_STATIC,
        'json_config_id': json_ids[0],
        'json_utf8_hex': json_key.hex(),
        'skill_new_raw_key_hex': new['key'].hex(),
        'skill_init_raw_key_hex': init['key'].hex(),
        'json_equals_skill_init_key': json_key == init['key'],
        'json_equals_skill_new_key': json_key == new['key'],
        'json_key_occurrences_in_skill_new': new_key_count,
        'skill_new_script_ascii': new['fields'].get(b'script', b'').decode('ascii', 'replace'),
        'skill_new_item_type_ascii': new['fields'].get(b'itemtype', b'').decode('ascii', 'replace'),
        'source_sha256': {path: sha256(value) for path, value in payloads.items()},
    }


def run_go(go, exe, args):
    r = subprocess.run([go, *args, str(exe)], capture_output=True, text=True, timeout=90, check=False)
    if r.returncode:
        raise RuntimeError(f'Go inspection failed for {args!r}: exit {r.returncode}: {r.stderr[:160]}')
    return r.stdout


def inspect_exe(exe, go='go'):
    h = sha256(exe.read_bytes())
    if h != EXPECTED_EXE_SHA256:
        raise ValueError('UNKNOWN_SERVER_EXE_SHA256: refusing version-dependent control-flow conclusions')
    specs = {
        'resource_loader': (r'^main\.loadSkillResourceTables$', ('go:func.*+4112', 'path/filepath.join')),
        'resource_loader_closure': (r'^main\.loadSkillResourceTables.func1$', ('CALL main.loadINISections(SB)',)),
        'catalog_builder': (r'^main\.loadCombatSkillCatalog$', ('CALL main.loadSkillResourceTables(SB)', 'CALL runtime.mapiterinit(SB)', 'CALL runtime.mapassign_faststr(SB)')),
        'catalog_definition': (r'combatSkillCatalog.*definition$', ('CALL runtime.mapaccess2_faststr(SB)', 'CALL runtime.mapaccess2(SB)')),
        'cast_handler': (r'^main\.handleSkillCustom$', ('CALL main.(*playerActor).learnedSkillLevel(SB)', 'CALL main.(*combatSkillCatalog).definition(SB)', 'CALL main.(*playerActor).beginSkillUse(SB)', 'CALL main.stagePlayerSkillEffects(SB)')),
        'init_view_loader': (r'^main\.loadSkillInitViews$', ('CALL main.loadINISections(SB)',)),
        'ini_parser': (r'^main\.loadINISections$', ('CALL strings.TrimSpace(SB)',)),
    }
    checks = {}
    for name, (pattern, required) in specs.items():
        asm = run_go(go, exe, ['tool', 'objdump', '-s', pattern])
        if not asm.startswith('TEXT '):
            raise ValueError(f'Missing disassembly for {name}')
        absent = [call for call in required if call not in asm]
        if absent:
            raise ValueError(f'Unexpected {name} call graph: missing {absent}')
        checks[name] = True
        if name == 'cast_handler':
            steps = [asm.find(x) for x in required]
            if steps != sorted(steps):
                raise ValueError('Unexpected cast-handler call ordering')
    return {'sha256': h, 'go_toolchain_verified_call_graph': checks, 'cast_path_order': [
        'learnedSkillLevel', 'combatSkillCatalog.definition', 'playerActor.beginSkillUse', 'stagePlayerSkillEffects'
    ]}


def audit(archive_path, exe_path, go='go'):
    with zipfile.ZipFile(archive_path) as archive:
        payloads = {path: read_one(archive, path) for path in (SKILL_NEW, SKILL_INIT, ROLE_DATA, TEMPLATE_DATA)}
    resources = inspect_resources(payloads)
    executable = inspect_exe(exe_path, go)
    return {
        'status': 'STATIC_CATALOG_KEY_MISMATCH_REQUIRES_RUNTIME_VALIDATION',
        'exe_modified': False, 'safe_to_apply_previous_patch': False,
        'resources': resources, 'server_exe': executable,
        'interpretation': 'The ordinary catalog is seeded from skill_new.ini keys. The JSON/init ID is not a skill_new.ini key for 5675. The normal cast handler consults learned levels then catalog.definition; runtime cast failure, alternate WuJi routing, official-client identity, and a safe repair are NOT proven.',
        'next_validation': 'Controlled Windows cast of this ID with isolated character data, then inspect catalog lookup and save identity before any binary or resource change.',
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('server_zip', type=Path)
    ap.add_argument('server_exe', type=Path)
    ap.add_argument('--go', default='go')
    ap.add_argument('--output', type=Path)
    args = ap.parse_args()
    result = audit(args.server_zip, args.server_exe, args.go)
    output = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        if args.output.resolve() in {args.server_zip.resolve(), args.server_exe.resolve()}:
            raise ValueError('Cannot overwrite the supplied archive or server EXE')
        args.output.write_text(output, encoding='utf-8')
    else:
        print(output, end='')


if __name__ == '__main__':
    main()
