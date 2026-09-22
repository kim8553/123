import json
import tempfile
import unittest
from pathlib import Path
from skill_inventory import load_ids


class SkillInventoryTests(unittest.TestCase):
    def test_distinct_ids_and_roles(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'skills.json'
            path.write_text(json.dumps({'roles': {'2': {'skills': [
                {'config_id': 'a'}, {'config_id': 'a'}, {'config_id': 'b'}
            ]}, '4': {'skills': []}}}), encoding='utf-8')
            self.assertEqual(load_ids(path), {'2': {'a', 'b'}, '4': set()})

    def test_invalid_missing_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'skills.json'
            path.write_text(json.dumps({'roles': {'2': {'skills': [{}]}}}), encoding='utf-8')
            with self.assertRaises(ValueError):
                load_ids(path)


if __name__ == '__main__':
    unittest.main()
