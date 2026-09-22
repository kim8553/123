"""Only fabricated wire data; no real login/session data in tests."""
import struct
import tempfile
import unittest
from pathlib import Path
from frame_opcode_audit import audit, custom_message_id, unescape, KEY


def block(kind, body):
    n = len(body) + 12
    return struct.pack('<II', kind, n) + body + struct.pack('<I', n)


def capture(frame, server_port=7061, cut=None):
    wire = bytes(b ^ KEY[i & 3] for i, b in enumerate(frame))
    wire = wire.replace(b'\xee', b'\xee\x00') + b'\xee\xee'
    shb = block(0x0a0d0d0a, b'\x4d\x3c\x2b\x1a' + struct.pack('<HHq', 1, 0, -1))
    idb = block(1, struct.pack('<HHI', 1, 0, 65535))
    def epb(seq, payload):
        ip = bytearray(20)
        ip[0] = 0x45
        ip[12:16] = b'\x01\x02\x03\x04'
        ip[16:20] = b'\x05\x06\x07\x08'
        ip[9] = 6
        struct.pack_into('!H', ip, 2, 40 + len(payload))
        tcp = bytearray(20)
        struct.pack_into('!HHI', tcp, 0, server_port, 50000, seq)
        tcp[12] = 0x50
        body = b'\x00' * 12 + b'\x08\x00' + ip + tcp + payload
        aligned = body + b'\0' * (-len(body) % 4)
        return block(6, struct.pack('<IIIII', 0, 0, 0, len(body), len(body)) + aligned)
    if cut is None:
        return shb + idb + epb(100, wire)
    return shb + idb + epb(100, wire[:cut]) + epb(100 + cut, wire[cut:])


class FrameAuditTests(unittest.TestCase):
    def test_two_tcp_segments_one_complete_custom_message(self):
        frame = b'\x1e\x01\x00\x02' + struct.pack('<i', 188)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'fake.pcapng'
            path.write_bytes(capture(frame, cut=3))
            report = audit(path, [7061])
            self.assertEqual(report['counts']['candidate_game_frames'], 1)
            self.assertEqual(report['opcode_histograms']['server_to_client'], {'0x1e': 1})
            self.assertEqual(report['candidate_custom_message_ids']['server_to_client'], {'188': 1})
            self.assertNotIn('1.2.3.4', str(report))

    def test_reject_invalid_custom_layout(self):
        self.assertIsNone(custom_message_id(b'\x1e\x01\x00\x06' + b'\x00' * 4))
        self.assertIsNone(custom_message_id(b'\x1e\x01'))

    def test_escaped_ee_and_partial(self):
        frames, invalid = unescape(b'\x00\xee\x00\x01\xee\xee\x02')
        self.assertEqual(frames, [b'\x00\xee\x01'])
        self.assertEqual(invalid, 0)


if __name__ == '__main__':
    unittest.main()
