import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from skill_id_repair import INI, OLD, STATIC, TARGETS, patch_one, run, sections_by_static_data


class SkillIDRepairTest(unittest.TestCase):
    def row(self, config_id, static=STATIC):
        return {'config_id': config_id, 'static_data': static, 'level': 5, 'fill': 88}

    def inputs(self):
        roles = {'roles': {'2': {'skills': [self.row(OLD), self.row('other', 123)]},
                           '4': {'skills': [self.row(OLD)]}}}
        template = {'skills': [self.row(OLD), self.row('other', 123)]}
        return {p: json.dumps(roles if p == 'data/skills.json' else template, ensure_ascii=False, indent=2).encode()
                for p in TARGETS}

    def archive(self, path, ini=b'[new_name]\nStaticData=5675\n[other]\nStaticData=100\n'):
        with zipfile.ZipFile(path, 'w') as z:
            for name, data in self.inputs().items():
                z.writestr('folder/' + name, data)
            z.writestr('folder/' + INI, ini)

    def test_exact_resource_name(self):
        self.assertEqual(sections_by_static_data('[裂天拳]\nStaticData=5675\n'.encode('gb18030'), 5675), ['裂天拳'])

    def test_patch_changes_only_config_id(self):
        for path, data in self.inputs().items():
            output = patch_one(data, path, '裂天拳')
            self.assertEqual(output.count('"config_id": "裂天拳"'.encode()), TARGETS[path])
            self.assertNotIn('"config_id": "ȭ"'.encode(), output)
            self.assertIn(b'"fill": 88', output)

    def test_reject_collision(self):
        data = self.inputs()['data/技能数据.json'].replace(b'"other"', '"裂天拳"'.encode())
        with self.assertRaisesRegex(ValueError, 'destination ID exists'):
            patch_one(data, 'data/技能数据.json', '裂天拳')

    def test_reject_wrong_static_data(self):
        data = self.inputs()['data/技能数据.json'].replace(b'5675', b'5676')
        with self.assertRaisesRegex(ValueError, 'unexpected old ID'):
            patch_one(data, 'data/技能数据.json', '裂天拳')

    def test_dry_run_does_not_create_file(self):
        with tempfile.TemporaryDirectory() as d:
            original = Path(d) / 'server.zip'; self.archive(original)
            report = run(original)
            self.assertEqual(report['status'], 'AUDIT_ONLY')
            self.assertEqual(sorted(Path(d).iterdir()), [original])

    def test_output_and_source_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            original = Path(d) / 'server.zip'; patch = Path(d) / 'patch.zip'
            self.archive(original)
            before = original.read_bytes()
            report = run(original, patch)
            self.assertEqual(report['status'], 'DATA_PATCH_CREATED')
            self.assertEqual(original.read_bytes(), before)
            with zipfile.ZipFile(patch) as z:
                self.assertEqual(z.testzip(), None)
                self.assertEqual(set(z.namelist()), set(TARGETS) | {'SKILL_PATCH_README.txt', 'audit.json'})

    def test_ambiguous_resource_static_data_refused(self):
        with tempfile.TemporaryDirectory() as d:
            original = Path(d) / 'server.zip'
            self.archive(original, b'[one]\nStaticData=5675\n[two]\nStaticData=5675\n')
            with self.assertRaisesRegex(ValueError, 'unique distinct'):
                run(original)


if __name__ == '__main__':
    unittest.main()
