import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from skill_runtime_audit import INIT, NEW, ROLE, TEMPLATE, audit, member, parse_ini_bytes, summarize_duplicate


class SkillRuntimeAuditTests(unittest.TestCase):
    def fixture(self, path, *, new_name='裂天拳', init_name='    ȭ', extra_init=b''):
        role = {'roles': {str(r): {'skills': [{'config_id': 'ȭ', 'static_data': 5675}]}
                          for r in (2, 4)}}
        template = {'skills': [{'config_id': 'ȭ', 'static_data': 5675}]}
        with zipfile.ZipFile(path, 'w') as z:
            z.writestr('server/' + NEW, ('[' + new_name + ']\nStaticData=5675\n').encode('gb18030'))
            z.writestr('server/' + INIT, ('[' + init_name + ']\nStaticData=5675\nItemType=1000\n').encode('utf8') + extra_init)
            z.writestr('server/' + ROLE, json.dumps(role, ensure_ascii=False).encode('utf8'))
            z.writestr('server/' + TEMPLATE, json.dumps(template, ensure_ascii=False).encode('utf8'))

    def test_utf8_json_matches_init_but_not_gbk_new(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'src.zip'; self.fixture(src)
            report = audit(src)
            self.assertEqual(report['different_normalized_raw_ids'], [5675])
            self.assertTrue(report['target_5675']['json_matches_init_raw_key'])
            self.assertFalse(report['target_5675']['json_matches_new_raw_key'])
            self.assertEqual(report['target_5675']['skill_init']['raw_hex'], 'c8ad')
            self.assertFalse(report['safe_to_patch'])

    def test_same_ascii_name_produces_no_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'src.zip'; self.fixture(src, new_name='a', init_name='a')
            report = audit(src)
            self.assertEqual(report['different_normalized_raw_ids'], [])
            self.assertEqual(report['shared_static_ids'], 1)

    def test_duplicate_conflicting_fields_detected(self):
        src = b'[a]\nStaticData=8240\nitemType=1000\npauseTime=50\n[a]\nStaticData=8240\nitemType=1001\npauseTime=30000\n'
        merged, occurrences, by_static = parse_ini_bytes(src)
        self.assertEqual(merged[b'a'][b'itemtype'], b'1001')
        self.assertEqual(by_static[8240], [b'a'])
        self.assertEqual(summarize_duplicate(merged, occurrences)[0]['conflicting_fields']['itemtype'], ['1000', '1001'])

    def test_duplicate_identical_fields_not_conflicting(self):
        src = b'[a]\nStaticData=3\na=1\n[a]\nStaticData=3\na=1\n'
        merged, occurrences, _ = parse_ini_bytes(src)
        self.assertEqual(summarize_duplicate(merged, occurrences)[0]['conflicting_fields'], {})

    def test_ambiguous_archive_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'src.zip'; self.fixture(src, new_name='a', init_name='a')
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(src, 'a') as z:
                    z.writestr('server/' + NEW, b'[b]\nStaticData=5675\n')
            with self.assertRaisesRegex(ValueError, 'precisely one'):
                audit(src)

    def test_archive_stays_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'src.zip'; self.fixture(src)
            before = src.read_bytes()
            audit(src)
            self.assertEqual(src.read_bytes(), before)

    def test_missing_resource_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'test.zip'
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr('x/' + INIT, b'[a]\nStaticData=5675\n')
            with zipfile.ZipFile(path) as z:
                with self.assertRaisesRegex(ValueError, 'precisely one'):
                    member(z, NEW)

    def test_init_only_static_id_is_explicitly_reported(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'src.zip'
            self.fixture(src, extra_init=b'[extra]\nStaticData=9000\n')
            report = audit(src)
            self.assertEqual(report['only_in_skill_init_static_ids'], [9000])
            self.assertFalse(report['safe_to_patch'])

    def test_init_ascii_section_whitespace_trimmed_before_matching_json(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'src.zip'
            self.fixture(src, init_name='    ȭ    ')
            report = audit(src)
            self.assertTrue(report['target_5675']['json_matches_init_raw_key'])
            self.assertEqual(report['target_5675']['skill_init']['raw_hex'], 'c8ad')

    def test_bad_static_data_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Invalid StaticData'):
            parse_ini_bytes(b'[a]\nStaticData=invalid\n')


if __name__ == '__main__':
    unittest.main()
