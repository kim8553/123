"""Synthetic-only tests; never send traffic to a game server."""
import struct
import unittest
from skill_msg20_schema_audit import (compare_variant_sets, decode_three_arg_cast, inspect_disassembly, parse_tvar_message, scan_frames)


def frame(msgid=20, skill='CS_demo01'):
    key = skill.encode('ascii') + b'\0'
    return (b'\x1e\x04\x00\x02' + struct.pack('<I', msgid) +
            b'\x08' + b'A'*8 + b'\x06' + struct.pack('<I', len(key)) + key + b'\x08' + b'B'*8)

SENDER = '\n'.join(['runtime.rodata+527808(SB)', 'runtime.rodata+272992(SB)',
                    'runtime.rodata+527808(SB)', 'runtime.rodata+273312(SB)',
                    'runtime.rodata+273888(SB)',
                    'MOVL $0x1e, AX', 'MOVL $0x14, BX', 'LEAQ 0x140(SP), CX',
                    'MOVL $0x5, DI', 'CALL main.serverCustomIntMessageWithOpcode(SB)'])
WRAPPER = 'LEAQ 0x1(DI), CX\nCALL main.encodeServerCustomValuesWithOpcode(SB)'
ENCODER = 'MOVW CX, 0(R8)(R9*1)'


class SkillMsg20SchemaTests(unittest.TestCase):
    def test_official_three_args(self):
        result = decode_three_arg_cast(frame(), 20)
        self.assertEqual(result['types'], ['int32', 'object8', 'string', 'object8'])
        self.assertEqual(result['length'], 32 + len('CS_demo01'))

    def test_reject_wrong_msg_id(self):
        self.assertIsNone(decode_three_arg_cast(frame(205), 20))

    def test_reject_bad_nul_termination(self):
        bad = bytearray(frame()); bad[-10] = ord('X')
        self.assertIsNone(decode_three_arg_cast(bytes(bad), 20))

    def test_scan_filters_direction(self):
        f = frame(); line = b'op=0x1E len=' + str(len(f)).encode() + b' body=' + f.hex().encode()
        data = b'12:00:00 [S2C] ' + line + b'\n12:00:01 [C2S] ' + line
        result = scan_frames(data, origin='synthetic')
        self.assertEqual(result['id20_frames'], 1)
        self.assertEqual(result['id20_observed_three_arg_cast'], 1)
        self.assertEqual(result['id20_tvar_counts'], {'4': 1})

    def test_sender_signature_count(self):
        out = inspect_disassembly(SENDER, WRAPPER, ENCODER)
        self.assertEqual(out['predicted_tvar_count_if_executed'], 6)
        self.assertEqual(out['inferred_tvar_types_from_build_pinned_constructor_signatures'],
                         ['int32','object8','string','object8','int32','float32'])

    def test_six_variant_decoder(self):
        base = frame()
        new = base[:1] + b'\x06' + base[2:] + b'\x02\x00\x00\x00\x00' + b'\x04\x00\x00\x00\x00'
        parsed = parse_tvar_message(new)
        self.assertEqual(parsed['types'], ['int32','object8','string','object8','int32','float32'])

    def test_extra_unknown_type_rejected(self):
        base = frame()
        self.assertIsNone(parse_tvar_message(base[:1]+b'\x05'+base[2:]+b'\xfe'))

    def test_local_six_variant_recognized_not_claimed_parity(self):
        reference = [{'id20_schemas': {'int32,object8,string,object8,int32,float32': 10}}]
        local = {'id20_unrecognized': 0, 'unsupported_skill_frames': 0,
                 'id20_schemas': {'int32,object8,string,object8,int32,float32': 1}}
        self.assertEqual(compare_variant_sets(local, reference),
                         'LOCAL_ID20_SCHEMAS_ALL_SEEN_IN_OFFICIAL_NOT_PAIRED_PARITY')

    def test_new_local_variant_reported(self):
        reference = [{'id20_schemas': {'int32,object8,string,object8': 10}}]
        local = {'id20_unrecognized': 0, 'unsupported_skill_frames': 0,
                 'id20_schemas': {'int32,object8,string': 1}}
        self.assertEqual(compare_variant_sets(local, reference),
                         'LOCAL_ID20_HAS_SCHEMA_NOT_SEEN_IN_OFFICIAL_REFERENCE')

    def test_missing_wrapper_rejected(self):
        with self.assertRaises(ValueError):
            inspect_disassembly(SENDER, '', ENCODER)

    def test_changed_build_sender_rejected(self):
        with self.assertRaises(ValueError):
            inspect_disassembly(SENDER.replace('$0x5', '$0x3'), WRAPPER, ENCODER)

    def test_scattered_instruction_rejected(self):
        with self.assertRaises(ValueError):
            inspect_disassembly(SENDER.replace('MOVL $0x14, BX', 'MOVL $0x14, BX' + 'N'*1000), WRAPPER, ENCODER)

if __name__ == '__main__':
    unittest.main()
