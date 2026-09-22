#!/usr/bin/env python3
"""Read-only comparison of observable official skill packets and local server skill logs.

Inputs are existing decoded official frame logs, server process logs, and a local PCAPNG.
An accepted skill log is NEVER treated as a captured server->client packet.
No endpoints, object IDs, raw captures, account data, or character names in output.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import re
import struct
import zipfile

OFFICIAL = (
    'artifacts/capture-players/out2/frames.log',
    'artifacts/capture-fxgame-op2/decoded/frames.log',
)
LOCAL_LOG = 'logs/protocol-probe-live.log'
LOCAL_PCAP = 'artifacts/capture-localsrv/cap.pcapng'
FRAME_RE = re.compile(rb'\[S2C [^\]]+\] op=0x1E len=(\d+) body=([0-9a-fA-F]+)')
ACCEPT_RE = re.compile(rb'accepted skill id=([^\s]+)')
C2S_RE = re.compile(rb'client activity CustomSend opcode=0x([0-9A-Fa-f]+) msg_id=(\d+) args=\[string:"([^"\r\n]+)"')


def read_archive_entry(z, suffix):
    matches = [name for name in z.namelist() if name == suffix or (name.count('/') > 0 and name.split('/',1)[1] == suffix)]
    if len(matches) != 1:
        raise ValueError(f'Expected unique {suffix}, got {len(matches)}')
    return matches[0]


def parse_tvar_frame(blob):
    """Return typed custom message metadata when the frame is fully valid.

    We implement the observed 205 (int32, object8, string, object8) schema only.
    Anything else remains unparsed, rather than guessed.
    """
    if len(blob) < 9 or blob[:4] != b'\x1e\x04\x00\x02':
        return None
    msgid = struct.unpack_from('<I', blob, 4)[0]
    if msgid != 205:
        return None
    i=8
    if blob[i] != 8 or i+9 > len(blob):return None
    i+=9
    if i>=len(blob) or blob[i]!=6 or i+5>len(blob):return None
    n=struct.unpack_from('<I',blob,i+1)[0]
    if n>512 or i+5+n+9 != len(blob):return None
    key=blob[i+5:i+5+n]
    if not key.endswith(b'\x00'):return None
    try:skill=key[:-1].decode('ascii','strict')
    except UnicodeDecodeError:return None
    i+=5+n
    if blob[i] != 8 or i+9 != len(blob):return None
    return {'msg_id':205,'skill':skill,'tvar_count':4,
            'argument_types':['object8','string','object8'],
            'payload_length':len(blob), 'skill_ascii_length':n-1}


def scan_official(z, path):
    rows=Counter();lengths=defaultdict(set);bad=0;raw205=0;total_custom=0;digest=hashlib.sha256()
    name=read_archive_entry(z,path)
    with z.open(name) as f:
        for line in f:
            digest.update(line)
            m=FRAME_RE.search(line)
            if not m:continue
            total_custom+=1
            b=bytes.fromhex(m.group(2).decode('ascii'))
            if len(b)!=int(m.group(1)):
                bad+=1;continue
            if len(b)<8 or b[:4]!=b'\x1e\x04\x00\x02' or struct.unpack_from('<I',b,4)[0]!=205:
                continue
            raw205+=1
            hit=parse_tvar_frame(b)
            if hit is None:bad+=1;continue
            rows[hit['skill']]+=1
            lengths[hit['skill']].add(hit['payload_length'])
    return {'source':path,'source_sha256':digest.hexdigest(),'total_s2c_custom_frames':total_custom,
            'id205_frames':raw205,'id205_decoded':sum(rows.values()),
            'id205_malformed_or_unrecognized':bad,
            'skill_counts':rows,'lengths':lengths}


def scan_local_log(z):
    accepted=Counter();client211=Counter();client211_opcode=Counter();name=read_archive_entry(z,LOCAL_LOG)
    with z.open(name) as f:
        for line in f:
            m=ACCEPT_RE.search(line)
            if m:
                try:accepted[m.group(1).decode('utf8','strict')]+=1
                except UnicodeDecodeError:pass
            c=C2S_RE.search(line)
            if c and int(c.group(2))==211:
                try:skill=c.group(3).decode('utf8','strict')
                except UnicodeDecodeError:continue
                client211[skill]+=1;client211_opcode[int(c.group(1),16)]+=1
    return accepted,client211,client211_opcode


def local_pcap_payload_stats(data):
    """Conservative PCAPNG parser: count TCP payload bytes without recording addresses."""
    p=0;endian=None;links={};interface=0;tcp_segments=0;payload_segments=0;payload_bytes=0
    while p+12<=len(data):
        if data[p:p+4]==b'\x0a\x0d\x0d\x0a':
            marker=data[p+8:p+12]
            endian='<' if marker==b'\x4d\x3c\x2b\x1a' else '>' if marker==b'\x1a\x2b\x3c\x4d' else None
            links={};interface=0
        if endian is None:raise ValueError('PCAPNG byte order unknown')
        t,size=struct.unpack_from(endian+'II',data,p)
        if size<12 or p+size>len(data) or struct.unpack_from(endian+'I',data,p+size-4)[0]!=size:
            raise ValueError('Corrupt PCAPNG block')
        if t==1:
            links[interface]=struct.unpack_from(endian+'H',data,p+8)[0];interface+=1
        elif t==6 and size>=32:
            interface_id,_,_,cap,_=struct.unpack_from(endian+'IIIII',data,p+8)
            pkt=data[p+28:p+28+cap];link=links.get(interface_id)
            if link==0 and len(pkt)>=4:ip=pkt[4:]
            elif link==1 and len(pkt)>=14 and pkt[12:14]==b'\x08\x00':ip=pkt[14:]
            elif link==101:ip=pkt
            else:ip=b''
            if len(ip)>=20 and ip[0]>>4==4 and ip[9]==6:
                ihl=(ip[0]&15)*4;total=struct.unpack_from('!H',ip,2)[0]
                if ihl>=20 and len(ip)>=ihl+20:
                    tcp=ip[ihl:];offset=(tcp[12]>>4)*4
                    if offset>=20 and len(tcp)>=offset:
                        tcp_segments+=1
                        available=max(0,min(total,len(ip))-ihl-offset)
                        if available:
                            payload_segments+=1;payload_bytes+=available
        p+=size
    if p!=len(data):raise ValueError('Partial PCAPNG data')
    return {'tcp_segments':tcp_segments,'tcp_payload_segments':payload_segments,'tcp_payload_bytes':payload_bytes}


def audit(source):
    with zipfile.ZipFile(source) as z:
        off=[scan_official(z,path) for path in OFFICIAL]
        acc,client,client_op=scan_local_log(z)
        capture=z.read(read_archive_entry(z,LOCAL_PCAP))
        local_capture=local_pcap_payload_stats(capture)
    merged=Counter()
    for item in off:merged.update(item['skill_counts'])
    overlap=sorted(set(merged)&set(acc))
    focus='CS_jh_chz04'
    official_focus=[{'capture':item['source'],'official_id205_count':item['skill_counts'][focus],
                     'official_id205_frame_lengths':sorted(item['lengths'][focus])} for item in off]
    return {
      'scope':'SKILL_PACKET_EVIDENCE_ONLY',
      'verdict':'FULL_PACKET_PARITY_NOT_VERIFIED',
      'official_s2c_id205_schema':{'outer_opcode':'0x1e','custom_message_id':205,
          'tvar_count':4,'argument_types':['object8','string','object8'],
          'frame_length_rule':'32 + ASCII skill ID byte length (NUL-terminated wire string)'},
      'official_capture_summaries':[
          {'capture':o['source'],'sha256':o['source_sha256'],'s2c_custom_frames':o['total_s2c_custom_frames'],
           'id205_frames':o['id205_frames'],'recognized_id205_frames':o['id205_decoded'],
           'malformed_or_unrecognized_205_related':o['id205_malformed_or_unrecognized'],
           'unique_id205_skill_ids':len(o['skill_counts'])} for o in off],
      'current_server_log':{'accepted_skill_events':sum(acc.values()),'accepted_unique_skill_ids':len(acc),
         'client_customsend_211_events':sum(client.values()),
         'client_customsend_211_opcodes':[f'0x{k:02x}' for k in sorted(client_op)]},
      'cross_source_skill_id_overlap':{'shared_distinct_skill_ids':len(overlap),
           'meaning':'A name overlap is not a paired cast, nor proof of packet compatibility.'},
      'example_skill':{'skill_id':focus,'official':official_focus,
            'current_server_accepted_count':acc[focus],
            'current_server_decoded_client_211_count':client[focus],
            'official_205_packet_schema_confirmed':any(o['skill_counts'][focus] for o in off),
            'current_server_205_wire_bytes_available':False},
      'local_pcap':{'source':LOCAL_PCAP,'sha256':hashlib.sha256(capture).hexdigest(),**local_capture,
         'can_compare_outbound_skill_frames':local_capture['tcp_payload_segments']>0},
      'comparisons':[
          {'claim':'Official S2C custom 205 structure','status':'CONFIRMED_IN_OFFICIAL_CAPTURE'},
          {'claim':'Current server accepts some of the same skill IDs','status':'CONFIRMED_IN_PROCESS_LOG_ONLY'},
          {'claim':'Official vs current server S2C 205 byte/field parity','status':'UNVERIFIED_NO_LOCAL_OUTBOUND_CAPTURE'},
          {'claim':'Official vs current C2S 211 packet parity','status':'UNVERIFIED_NO_MATCHED_OFFICIAL_C2S_211_DECODE'},
          {'claim':'All game packet parity','status':'UNVERIFIED_OUT_OF_SCOPE'}],
      'limitations':['Different capture sessions and characters; no paired, same-condition cast.',
           'Server skill accept log does not show S2C 205 bytes or prove that a matching message was sent.',
           'No official/client-to-server 211 field-level comparison established.',
           'Server EXE and skill data were not modified; no live connection attempted.']
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('server_zip');parser.add_argument('--output')
    args=parser.parse_args();result=audit(args.server_zip)
    text=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(text,encoding='utf8')
    print(text)
if __name__=='__main__':main()
