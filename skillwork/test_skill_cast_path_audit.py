"""Synthetic skill-only fixtures. No captured packets, client data or player saves."""
import json
import unittest
from skill_cast_path_audit import (SKILL_NEW, SKILL_INIT, ROLE_DATA, TEMPLATE_DATA,
                                   sections, by_static, inspect_resources, inspect_exe)
from pathlib import Path
from tempfile import TemporaryDirectory


def fixture(new_name=b'\xc1\xd1\xcc\xec\xc8\xad', init_name=b'    \xc8\xad', json_id='ȭ'):
    row = {'config_id': json_id, 'static_data': 5675, 'item_type': 1000}
    return {
        SKILL_NEW: b'[' + new_name + b']\r\nStaticData=5675\r\nscript=SkillNormal\r\nItemType=1000\r\n',
        SKILL_INIT: b'[' + init_name + b']\nStaticData=5675\n',
        ROLE_DATA: json.dumps({'roles': {'2': {'skills': [row]}, '4': {'skills': [row]}}}).encode(),
        TEMPLATE_DATA: json.dumps({'skills': [row]}).encode(),
    }


class SkillCastAuditTests(unittest.TestCase):
    def test_raw_bytes_preserved_no_cross_encoding(self):
        report = inspect_resources(fixture())
        self.assertTrue(report['json_equals_skill_init_key'])
        self.assertFalse(report['json_equals_skill_new_key'])
        self.assertEqual(report['json_key_occurrences_in_skill_new'], 0)
        self.assertEqual(report['skill_new_raw_key_hex'], 'c1d1ccecc8ad')

    def test_matching_catalog_key_is_detected(self):
        report = inspect_resources(fixture(new_name=b'\xc8\xad'))
        self.assertTrue(report['json_equals_skill_new_key'])
        self.assertEqual(report['json_key_occurrences_in_skill_new'], 1)

    def test_duplicate_static_data_rejected(self):
        data = fixture()
        data[SKILL_NEW] += b'\n[other]\nStaticData=5675\n'
        with self.assertRaisesRegex(ValueError, 'not unique'):
            inspect_resources(data)

    def test_mismatched_json_ids_rejected(self):
        data = fixture()
        data[TEMPLATE_DATA] = json.dumps({'skills': [{'config_id': 'other', 'static_data': 5675}]}).encode()
        with self.assertRaisesRegex(ValueError, 'disagree'):
            inspect_resources(data)

    def test_duplicate_field_value_last_wins_in_parser(self):
        s = sections(b'[skill]\nStaticData=1\nstaticdata=5675\n')
        self.assertEqual(len(by_static(s, 5675)), 1)

    def test_missing_exe_rejected_before_disassembly(self):
        with TemporaryDirectory() as d:
            p = Path(d) / 'fake.exe'; p.write_bytes(b'not the supplied server')
            with self.assertRaisesRegex(ValueError, 'UNKNOWN_SERVER_EXE_SHA256'):
                inspect_exe(p)


if __name__ == '__main__':
    unittest.main()
