"""Synthetic fixtures only; never publish captured auth or character data."""
import json
import struct
import tempfile
import unittest
from pathlib import Path

from pcapng_audit import audit as audit_capture, tcp_payload_size
from server_log_gap_audit import audit as audit_log
from skill_catalog_audit import audit as audit_skills, load_entries


def block(kind, body):
    n = len(body) + 12
    assert not n % 4
    return struct.pack('<II', kind, n) + body + struct.pack('<I', n)


def ip_tcp(payload=b'abc'):
    ip = bytearray(20)
    ip[0] = 0x45
    struct.pack_into('!H', ip, 2, 40 + len(payload))
    ip[9] = 6
    tcp = bytearray(20)
    tcp[12] = 0x50
    return bytes(ip) + tcp + payload


def capture(link, wire):
    shb = block(0x0a0d0d0a, b'\x4d\x3c\x2b\x1a' + struct.pack('<HHq', 1, 0, -1))
    idb = block(1, struct.pack('<HHI', link, 0, 65535))
    aligned = wire + b'\0' * (-len(wire) % 4)
    epb = block(6, struct.pack('<IIIII', 0, 0, 0, len(wire), len(wire)) + aligned)
    return shb + idb + epb


class CompatibilityTests(unittest.TestCase):
    def test_capture_linktypes(self):
        for link, wire in ((1, b'\0' * 12 + b'\x08\x00' + ip_tcp()),
                           (0, b'\x02\0\0\0' + ip_tcp()), (101, ip_tcp())):
            with self.subTest(link=link), tempfile.TemporaryDirectory() as d:
                path = Path(d) / 'synthetic.pcapng'
                path.write_bytes(capture(link, wire))
                result = audit_capture(path)
                self.assertEqual(result['counts']['packets'], 1)
                self.assertEqual(result['counts']['tcp_payload_bytes'], 3)
                self.assertNotIn('abc', str(result))

    def test_capture_rejects_truncation(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'truncated.pcapng'
            path.write_bytes(capture(101, ip_tcp())[:-1])
            with self.assertRaises(ValueError):
                audit_capture(path)

    def test_fragment_does_not_become_a_false_packet(self):
        ip = bytearray(ip_tcp())
        ip[6:8] = b'\x20\x00'
        self.assertIsNone(tcp_payload_size(bytes(ip), 101))
        self.assertIsNone(tcp_payload_size(b'\x00', 101))

    def test_role_template_comparison_does_not_claim_client_skills(self):
        with tempfile.TemporaryDirectory() as d:
            roles, template = Path(d) / 'roles.json', Path(d) / 'template.json'
            items = [{'config_id': 'skill_1', 'level': 1}, {'config_id': 'skill_2', 'level': 1}]
            roles.write_text(json.dumps({'roles': {'2': {'skills': items}, '4': {'skills': items}}}))
            template.write_text(json.dumps({'skills': [{'config_id': 'skill_1', 'level': 5}]}))
            result = audit_skills(roles, template, include_ids=True)
            self.assertEqual(result['only_in_server_role_data_ids'], ['skill_2'])
            self.assertEqual(result['field_difference_counts'], {'level': 1})
            self.assertEqual(result['role_value_disagreement_counts'], {'4': 0})

    def test_duplicate_skill_ids_fail(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            load_entries([{'config_id': 'x'}, {'config_id': 'x'}], 'test')

    def test_unhandled_log_aggregation_redacts_arguments(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'synthetic.log'
            path.write_text('2026/09/04 01:00:25 127.0.0.1:57607: fashion_suit unhandled sub=1 args=[string:"private"]\n'
                            '2026/09/04 01:00:26 127.0.0.1:57607: fashion_suit unhandled sub=1 args=[string:"private2"]\n')
            result = audit_log(path)
            self.assertEqual(result['route_counts'], {'fashion_suit / sub=1': 2})
            self.assertNotIn('private', str(result))
            self.assertNotIn('57607', str(result))


if __name__ == '__main__':
    unittest.main()
