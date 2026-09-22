"""Synthetic input tests: never connect to a game server."""
import json
import unittest
from unittest.mock import patch
from skill_cast_path_audit import ROLE_DATA, SKILL_INIT, SKILL_NEW, TEMPLATE_DATA
from skill_5675_candidate import (FACULTY, NEW_HEADER, OLD_HEADER, make_candidate)


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.original = b'[other]\nStaticData=9\n\n' + OLD_HEADER + b'\nStaticData=5675\nscript=SkillNormal\nItemType=1000\n'
        self.payloads = {
            SKILL_NEW: self.original,
            SKILL_INIT: b'[    \xc8\xad]\nStaticData=5675\n',
            ROLE_DATA: json.dumps({'roles': {str(i): {'skills': [{'config_id': '\u022d', 'static_data': 5675}]} for i in (2, 4)}}).encode(),
            TEMPLATE_DATA: json.dumps({'skills': [{'config_id': '\u022d', 'static_data': 5675}]}).encode(),
            FACULTY: json.dumps({'roles': {str(i): {'taolu': [{'config_id': '\u022d'}]} for i in (2, 3, 4)}}).encode(),
        }
        self.patch_hash = patch('skill_5675_candidate.sha', return_value='4263a384d38b40f50289b4121949d6fb497a56f0b482e7560f478cb6929b8056')
        self.patch_sections = patch('skill_5675_candidate.sections', side_effect=self.fake_sections)

    def fake_sections(self, raw):
        # Real INI parser, synthetic fixture padded with other unique sections.
        from skill_cast_path_audit import sections
        result = sections(raw)
        result.extend({'key': ('synthetic%05d' % i).encode(), 'fields': {}} for i in range(17855-len(result)))
        return result

    def candidate(self):
        with self.patch_hash, self.patch_sections:
            return make_candidate(self.payloads)

    def test_single_reversible_header_change(self):
        new, report = self.candidate()
        self.assertEqual(new, self.original.replace(OLD_HEADER, NEW_HEADER))
        self.assertEqual(new.replace(NEW_HEADER, OLD_HEADER), self.original)
        self.assertEqual(report['changed_section_count'], 1)
        self.assertFalse(report['deployable_or_tested_in_game'])

    def test_refuse_header_collision(self):
        self.payloads[SKILL_NEW] += b'\n' + NEW_HEADER + b'\nStaticData=999\n'
        with self.assertRaisesRegex(ValueError, 'SKILL_ID_PRECONDITION|NONUNIQUE_HEADER'):
            self.candidate()

    def test_refuse_missing_faculty_id(self):
        obj = json.loads(self.payloads[FACULTY]); obj['roles']['3']['taolu'] = []
        self.payloads[FACULTY] = json.dumps(obj).encode()
        with self.assertRaisesRegex(ValueError, 'FACULTY'):
            self.candidate()

    def test_refuse_unrecognized_resource_hash(self):
        with self.assertRaisesRegex(ValueError, 'UNKNOWN_SKILL_NEW_VERSION'):
            make_candidate(self.payloads)

    def test_refuse_wrong_script(self):
        self.payloads[SKILL_NEW] = self.original.replace(b'SkillNormal', b'SkillLock')
        with self.patch_hash, self.patch_sections:
            with self.assertRaisesRegex(ValueError, 'SKILL_ID_PRECONDITION'):
                make_candidate(self.payloads)


if __name__ == '__main__':
    unittest.main()
