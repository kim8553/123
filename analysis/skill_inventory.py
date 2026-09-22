#!/usr/bin/env python3
"""Offline inventory only: compare two JSON skill tables, never claim runtime support."""
import argparse
import json
from pathlib import Path


def load_ids(path: Path):
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or not isinstance(data.get('roles'), dict):
        raise ValueError(f'{path}: expected JSON object with a roles object')
    result = {}
    for role, obj in data['roles'].items():
        if not isinstance(obj, dict) or not isinstance(obj.get('skills'), list):
            raise ValueError(f'{path}: role {role} must contain a skills array')
        ids = []
        for index, skill in enumerate(obj['skills']):
            if not isinstance(skill, dict) or not isinstance(skill.get('config_id'), str) or not skill['config_id']:
                raise ValueError(f'{path}: role {role} skill {index} missing config_id')
            ids.append(skill['config_id'])
        result[str(role)] = set(ids)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('server_skills_json', type=Path)
    ap.add_argument('--client-skills-json', type=Path, help='Only supply after extracting/validating a comparable client JSON schema')
    args = ap.parse_args()
    server = load_ids(args.server_skills_json)
    report = {'server': {role: {'distinct_config_ids': len(ids)} for role, ids in sorted(server.items())}}
    if args.client_skills_json:
        client = load_ids(args.client_skills_json)
        report['comparison'] = {
            role: {
                'only_in_client_data': sorted(client.get(role, set()) - server.get(role, set())),
                'only_in_server_data': sorted(server.get(role, set()) - client.get(role, set())),
            }
            for role in sorted(server.keys() | client.keys())
        }
    else:
        report['comparison_status'] = 'NOT_PERFORMED: comparable validated client skill manifest is unavailable'
    report['caveat'] = 'Data presence/absence is not proof of runtime implementation or network compatibility.'
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
