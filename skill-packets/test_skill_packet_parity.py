"""Synthetic regression tests: no personal capture, no live networking."""
import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from skill_packet_parity import (parse_tvar_frame, local_pcap_payload_stats,
    audit, read_archive_entry, scan_official, scan_local_log, OFFICIAL, LOCAL_LOG, LOCAL_PCAP)


def make_205(skill=b'CS_jh_chz04'):
    wire=skill+b'\x00'
    return (b'\x1e\x04\x00\x02'+struct.pack('<I',205)+b'\x08'+b'1'*8+
            b'\x06'+struct.pack('<I',len(wire))+wire+b'\x08'+b'2'*8)


def pcapng(tcp_payload):
    # Little-endian SHB, DLT_NULL IDB, one enhanced packet block
    shb=struct.pack('<IIIHHqI',0x0a0d0d0a,28,0x1a2b3c4d,1,0,-1,28)
    idb=struct.pack('<IIHHII',1,20,0,0,65535,20)
    tcp=struct.pack('!HHIIHHHH',1234,19061,0,0,0x5018,65535,0,0)+tcp_payload
    ip=(b'\x45\x00'+struct.pack('!H',20+len(tcp))+b'\x00\x00\x00\x00\x40\x06\x00\x00'+b'\x7f\x00\x00\x01'*2)
    pkt=b'\x02\x00\x00\x00'+ip+tcp
    pad=b'\x00'*((-len(pkt))%4)
    size=32+len(pkt)+len(pad)
    epb=struct.pack('<IIIIIII',6,size,0,0,0,len(pkt),len(pkt))+pkt+pad+struct.pack('<I',size)
    return shb+idb+epb


class SkillPacketParityTests(unittest.TestCase):
    def test_parse_exact_id205_frame(self):
        blob=make_205()
        self.assertEqual(len(blob),43)
        self.assertEqual(parse_tvar_frame(blob),{'msg_id':205,'skill':'CS_jh_chz04',
           'tvar_count':4,'argument_types':['object8','string','object8'],
           'payload_length':43,'skill_ascii_length':11})

    def test_reject_wrong_message_id(self):
        b=bytearray(make_205());b[4]=204
        self.assertIsNone(parse_tvar_frame(bytes(b)))

    def test_reject_wrong_type_and_length(self):
        b=bytearray(make_205());b[8]=2
        self.assertIsNone(parse_tvar_frame(bytes(b)))
        self.assertIsNone(parse_tvar_frame(make_205()[:-1]))

    def test_reject_nonterminated_and_nonascii(self):
        b=bytearray(make_205());b[-10]=0x58  # replace NUL after ID
        self.assertIsNone(parse_tvar_frame(bytes(b)))
        self.assertIsNone(parse_tvar_frame(make_205(b'bad\xff')))

    def test_pcap_without_payload_is_not_wire_evidence(self):
        result=local_pcap_payload_stats(pcapng(b''))
        self.assertEqual(result['tcp_segments'],1)
        self.assertEqual(result['tcp_payload_segments'],0)
        self.assertEqual(result['tcp_payload_bytes'],0)

    def test_pcap_with_payload(self):
        result=local_pcap_payload_stats(pcapng(b'abc'))
        self.assertEqual(result['tcp_payload_segments'],1)
        self.assertEqual(result['tcp_payload_bytes'],3)

    def test_unique_root_entry_rejects_shadow(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'f.zip'
            with zipfile.ZipFile(path,'w') as z:
                z.writestr('root/'+LOCAL_LOG,b'a')
                z.writestr('root/artifacts/local/'+LOCAL_LOG,b'b')
            with zipfile.ZipFile(path) as z:
                self.assertEqual(read_archive_entry(z,LOCAL_LOG),'root/'+LOCAL_LOG)

    def test_audit_never_concludes_parity_from_log(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'f.zip'
            b=make_205();line=b'12:34:56.000 [S2C x] op=0x1E len=43 body='+b.hex().encode()+b'\n'
            with zipfile.ZipFile(path,'w') as z:
                for src in OFFICIAL:z.writestr('root/'+src,line)
                z.writestr('root/'+LOCAL_LOG,
                    b'accepted skill id=CS_jh_chz04 damage=3\n'+
                    b'client activity CustomSend opcode=0x0A msg_id=211 args=[string:"CS_jh_chz04", float:1]\n')
                z.writestr('root/'+LOCAL_PCAP,pcapng(b''))
            result=audit(path)
            self.assertEqual(result['cross_source_skill_id_overlap']['shared_distinct_skill_ids'],1)
            self.assertEqual(result['example_skill']['official'][0]['official_id205_count'],1)
            self.assertEqual(result['verdict'],'FULL_PACKET_PARITY_NOT_VERIFIED')
            self.assertFalse(result['local_pcap']['can_compare_outbound_skill_frames'])
            self.assertFalse(result['example_skill']['current_server_205_wire_bytes_available'])
            self.assertNotIn('127.0.0.1',json.dumps(result))

if __name__=='__main__':unittest.main()
