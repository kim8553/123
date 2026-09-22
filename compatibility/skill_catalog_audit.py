#!/usr/bin/env python3
"""Compare two SERVER skill data schemas, without claiming client-side skill support."""
import argparse
import json
from collections import Counter
from pathlib import Path


def load_entries(entries, label):
    if not isinstance(entries, list):
        raise ValueError(f'{label}: expected skills list')
    result = {}
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f'{label}[{i}]: expected object')
        sid = entry.get('config_id')
        if not isinstance(sid, str) or not sid:
            raise ValueError(f'{label}[{i}]: invalid config_id')
        if sid in result:
            raise ValueError(f'{label}: duplicate config_id {sid!r}')
        result[sid] = entry
    return result


def load_catalog(path, roles=False):
    obj = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(obj, dict):
        raise ValueError(f'{path}: root must be object')
    if roles:
        raw = obj.get('roles')
        if not isinstance(raw, dict) or not raw:
            raise ValueError(f'{path}: missing roles object')
        return {str(role): load_entries(data.get('skills'), f'role {role}')
                for role, data in raw.items() if isinstance(data, dict)}
    return load_entries(obj.get('skills'), str(path))


def audit(roles_path, template_path, include_ids=False):
    roles = load_catalog(roles_path, roles=True)
    if not roles:
        raise ValueError('no usable role tables')
    template = load_catalog(template_path)
    first = next(iter(roles))
    common_role_ids = set(roles[first])
    role_mismatches = {role: sorted(set(data) ^ common_role_ids)
                       for role, data in roles.items() if set(data) != common_role_ids}
    role_value_mismatches = {role: sum(roles[first].get(sid) != row
                                       for sid, row in data.items() if sid in roles[first])
                             for role, data in roles.items() if role != first}
    all_ids = set().union(*(set(data) for data in roles.values()))
    only_roles = sorted(all_ids - set(template))
    only_template = sorted(set(template) - all_ids)
    differences = Counter()
    for sid in all_ids & set(template):
        row = next((table[sid] for table in roles.values() if sid in table), None)
        for field in row.keys() & template[sid].keys():
            if row[field] != template[sid][field]:
                differences[field] += 1
    report = {
        'role_skill_counts': {role: len(rows) for role, rows in sorted(roles.items())},
        'template_skill_count': len(template),
        'only_in_server_role_data_count': len(only_roles),
        'only_in_server_template_data_count': len(only_template),
        'role_id_disagreement_counts': {role: len(ids) for role, ids in sorted(role_mismatches.items())},
        'role_value_disagreement_counts': dict(sorted(role_value_mismatches.items())),
        'field_difference_counts': dict(sorted(differences.items())),
        'meaning': 'Both sources are SERVER data; absence here does not prove a missing official skill or a runtime bug.',
    }
    if include_ids:
        report['only_in_server_role_data_ids'] = only_roles
        report['only_in_server_template_data_ids'] = only_template
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('server_roles_json', type=Path)
    parser.add_argument('server_template_json', type=Path)
    parser.add_argument('--include-ids', action='store_true')
    args = parser.parse_args()
    print(json.dumps(audit(args.server_roles_json, args.server_template_json, args.include_ids),
                     ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
