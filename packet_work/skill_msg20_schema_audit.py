#!/usr/bin/env python3
"""Read-only packet-schema comparison: observed official skill msg 20 versus a SHA-pinned server PE.

Disassembly identifies ONE sender's possible output, not an observed current-server packet.
Optional local decoded frames are summarized but never implicitly treated as a paired cast.
Original EXE/ZIP/logs/captures are not changed, and raw payloads/addresses are not emitted.
"""
import argparse
from collections import Counter
import hashlib
import json
import re
import struct
import subprocess
import zipfile
from pathlib import Path

EXE_SHA256 = 'c18538e2d32ff31c332b187d57af875d5fc226285ff4d96b46d8c61b4204639c'
OFFICIAL_LOGS = ('artifacts/capture-players/out1/frames.log',
                 'artifacts/capture-players/out2/frames.log')
LOCAL_EXISTING_PCAP = 'artifacts/capture-localsrv/cap.pcapng'
FRAME = re.compile(rb'\[(S2C|C2S)(?: [^\]]*)?\]\s+op=0x1E\s+len=(\d+)\s+body=([0-9a-fA-F]+)')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def archive_entry(z, suffix):
    hits = [n for n in z.namelist() if n == suffix or n.endswith('/' + suffix)]
    if len(hits) != 1:
        raise ValueError(f'Expected one archived file with suffix {suffix}, got {len(hits)}')
    return hits[0]


def decode_three_arg_cast(blob, msgid):
    """Strictly recognize observed op 1e: int32 ID + object8 + NUL string + object8."""
    if len(blob) < 32 or blob[:4] != b'\x1e\x04\x00\x02' or struct.unpack_from('<I', blob, 4)[0] != msgid:
        return None
    if blob[8] != 8 or blob[17] != 6 or len(blob) < 23:
        return None
    length = struct.unpack_from('<I', blob, 18)[0]
    if not (1 <= length <= 512) or 22 + length + 9 != len(blob):
        return None
    key = blob[22:22 + length]
    if not key.endswith(b'\0') or blob[22 + length] != 8:
        return None
    try:
        skill = key[:-1].decode('ascii')
    except UnicodeDecodeError:
        return None
    if not skill or '\0' in skill:
        return None
    return {'skill': skill, 'length': len(blob), 'types': ['int32', 'object8', 'string', 'object8']}


def parse_tvar_message(raw):
    """Decode the small type set actually present in archived skill messages.

    Unsupported type tags remain unrecognized, never guessed or coerced.
    """
    if len(raw) < 8 or raw[0] != 0x1e or raw[2:4] != b'\x00\x02' or not 1 <= raw[1] <= 64:
        return None
    pos = 3
    types = []
    skills = []
    for _ in range(raw[1]):
        if pos >= len(raw):
            return None
        tag = raw[pos]
        pos += 1
        if tag in (2, 4):
            if pos + 4 > len(raw):
                return None
            pos += 4
            types.append('int32' if tag == 2 else 'float32')
        elif tag == 8:
            if pos + 8 > len(raw):
                return None
            pos += 8
            types.append('object8')
        elif tag == 6:
            if pos + 4 > len(raw):
                return None
            n = struct.unpack_from('<I', raw, pos)[0]
            pos += 4
            if not 1 <= n <= 512 or pos + n > len(raw):
                return None
            value = raw[pos:pos + n]
            pos += n
            if not value.endswith(b'\0'):
                return None
            try:
                skill = value[:-1].decode('ascii')
            except UnicodeDecodeError:
                skill = None
            if skill and '\0' not in skill:
                skills.append(skill)
            types.append('string')
        else:
            return None
    if pos != len(raw) or types[0] != 'int32':
        return None
    return {'msg_id': struct.unpack_from('<I', raw, 4)[0],
            'tvar_count': len(types), 'types': types, 'ascii_strings': skills}


def scan_frames(data, *, origin, focus=20):
    tally = Counter(); counts = Counter(); schemas = Counter(); skills = set()
    three_arg = 0; malformed_focus = 0; invalid_length = 0; unsupported = 0
    for line in data.splitlines():
        m = FRAME.search(line)
        if not m or m.group(1) != b'S2C':
            continue
        raw = bytes.fromhex(m.group(3).decode('ascii'))
        if len(raw) != int(m.group(2)) or len(raw) < 8:
            invalid_length += 1
            continue
        if raw[0] != 0x1e or raw[2:4] != b'\x00\x02':
            continue
        msg = struct.unpack_from('<I', raw, 4)[0]
        if msg not in (20, 205):
            continue
        tally[msg] += 1
        counts[(msg, raw[1])] += 1
        hit = parse_tvar_message(raw)
        if hit is None:
            unsupported += 1
            if msg == focus:
                malformed_focus += 1
            continue
        schemas[(msg, ','.join(hit['types']))] += 1
        if msg == focus:
            skills.update(hit['ascii_strings'])
            if decode_three_arg_cast(raw, focus):
                three_arg += 1
    return {'origin': origin, 'sha256': sha256(data),
            'id20_frames': tally[20],
            'id20_tvar_counts': {str(n): num for (mid, n), num in sorted(counts.items()) if mid == 20},
            'id20_schemas': {key: num for (mid, key), num in sorted(schemas.items()) if mid == 20},
            'id20_observed_three_arg_cast': three_arg,
            'id20_unrecognized': malformed_focus, 'id20_distinct_skill_ids': len(skills),
            'id205_frames': tally[205],
            'id205_tvar_counts': {str(n): num for (mid, n), num in sorted(counts.items()) if mid == 205},
            'id205_schemas': {key: num for (mid, key), num in sorted(schemas.items()) if mid == 205},
            'unsupported_skill_frames': unsupported, 'invalid_frame_lengths': invalid_length}


def inspect_disassembly(sender, wrapper, encoder):
    """Guard against inferring a frame shape from unrelated instructions/symbols."""
    # These four setup instructions immediately precede the call and prove
    # opcode 0x1e, message ID 0x14, five extra interface values.
    required = [r'MOVL \$0x1e, AX', r'MOVL \$0x14, BX', r'LEAQ 0x140\(SP\), CX',
                r'MOVL \$0x5, DI', r'CALL main\.serverCustomIntMessageWithOpcode\(SB\)']
    locations = []
    for pat in required:
        m = re.search(pat, sender)
        if not m:
            raise ValueError(f'Build not verified: sender lacks expected instruction {pat}')
        locations.append(m.start())
    if locations != sorted(locations) or locations[-1] - locations[0] > 800:
        raise ValueError('Build not verified: sender call arguments are not adjacent/in order')
    expected_type_allocations = {'object8': ('runtime.rodata+527808(SB)', 2),
                                 'string': ('runtime.rodata+272992(SB)', 1),
                                 'int32': ('runtime.rodata+273312(SB)', 1),
                                 'float32': ('runtime.rodata+273888(SB)', 1)}
    if any(sender.count(tag) < count for tag, count in expected_type_allocations.values()):
        raise ValueError('Build not verified: sender argument constructors differ')
    if not re.search(r'LEAQ 0x1\(DI\), CX', wrapper) or not re.search(r'CALL main\.encodeServerCustomValuesWithOpcode\(SB\)', wrapper):
        raise ValueError('Build not verified: wrapper does not append the ID element')
    if not re.search(r'MOVW CX, 0\(R8\)\(R9\*1\)', encoder):
        raise ValueError('Build not verified: encoder argument count serialization unknown')
    return {'sender_symbol': 'main.nativeSkillActionFrameCaster',
            'opcode': '0x1e', 'message_id': 20,
            'extra_arguments_at_call': 5, 'wrapper_appends_message_id': 1,
            'predicted_tvar_count_if_executed': 6,
            'inferred_tvar_types_from_build_pinned_constructor_signatures':
                ['int32', 'object8', 'string', 'object8', 'int32', 'float32'],
            'disassembly_proof_addresses': ['0x917a48', '0x917a4d', '0x917a52', '0x917a5a', '0x917a62',
                                            '0x85706f', '0x857252', '0x8573e3']}


def objdump(go_binary, exe, symbol):
    expr = '^' + re.escape(symbol) + '$'
    p = subprocess.run([go_binary, 'tool', 'objdump', '-s', expr, str(exe)],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, check=True)
    text = p.stdout.decode('utf-8', errors='replace')
    if 'TEXT ' + symbol + '(SB)' not in text:
        raise ValueError(f'Missing disassembly for {symbol}')
    return text


def inspect_exe(exe, go_binary='go'):
    exe = Path(exe)
    if not exe.is_file() or sha256(exe.read_bytes()) != EXE_SHA256:
        raise ValueError('Unknown server EXE SHA256: refusing to extrapolate from a different build')
    names = ('main.nativeSkillActionFrameCaster', 'main.serverCustomIntMessageWithOpcode',
             'main.encodeServerCustomValuesWithOpcode')
    return inspect_disassembly(*(objdump(go_binary, exe, sym) for sym in names))


def compare_variant_sets(local, official_summaries):
    """Compare only observed type sequences; never claim matching casts/values."""
    if local['id20_unrecognized'] or local['unsupported_skill_frames']:
        return 'UNVERIFIED_UNRECOGNIZED_LOCAL_SKILL_FRAME'
    official = {key for summary in official_summaries for key, count in summary['id20_schemas'].items() if count}
    local_variants = {key for key, count in local['id20_schemas'].items() if count}
    if not local_variants:
        return 'UNVERIFIED_NO_LOCAL_ID20_SCHEMA'
    if not local_variants.issubset(official):
        return 'LOCAL_ID20_HAS_SCHEMA_NOT_SEEN_IN_OFFICIAL_REFERENCE'
    return 'LOCAL_ID20_SCHEMAS_ALL_SEEN_IN_OFFICIAL_NOT_PAIRED_PARITY'


def audit(archive, exe, *, local_frames=None, local_capture_confirmed=False, go_binary='go'):
    with zipfile.ZipFile(archive) as z:
        official = [scan_frames(z.read(archive_entry(z, name)), origin=name) for name in OFFICIAL_LOGS]
        local = z.read(archive_entry(z, LOCAL_EXISTING_PCAP))
    # A local capture known to carry no TCP application payload cannot be used as a counterpart.
    from skill_packet_parity import local_pcap_payload_stats
    stats = local_pcap_payload_stats(local)
    sender = inspect_exe(exe, go_binary=go_binary)
    reference = sum(x['id20_frames'] for x in official)
    count6 = sum(x['id20_tvar_counts'].get('6', 0) for x in official)
    id205_total = sum(x['id205_frames'] for x in official)
    matching_six_signature = 'int32,object8,string,object8,int32,float32'
    if any(x['id20_schemas'].get(matching_six_signature, 0) != x['id20_tvar_counts'].get('6', 0) for x in official):
        raise ValueError('Official count-six subtype is not uniform; schema inference requires review')
    if not count6:
        raise ValueError('Official reference contains no message-20 six-element variant; cannot compare')
    output = {'scope': 'SKILL_MESSAGES_20_AND_205_SCHEMA_ONLY',
              'verdict': 'STATIC_SENDER_SCHEMA_MATCHES_ONE_OFFICIAL_VARIANT_WIRE_PARITY_UNVERIFIED',
              'official': {'source_files': official, 'msg20_total': reference,
                           'msg20_count6_frames': count6,
                           'msg20_count6_observed_types': matching_six_signature.split(','),
                           'msg20_observed_tvar_counts': dict(sorted(Counter({n: sum(x['id20_tvar_counts'].get(n, 0) for x in official) for n in ('3','4','5','6','7','8','9')}).items())),
                           'msg205_total': id205_total,
                           'msg205_observed_tvar_counts': {n: sum(x['id205_tvar_counts'].get(n, 0) for x in official) for n in ('4','5','6','7')}},
              'current_server_static_sender': {'exe_sha256': EXE_SHA256, **sender,
                  'count6_exists_in_official': True,
                  'inferred_type_sequence_matches_official_six_element_variant': True,
                  'sender_not_observed_on_wire': True},
              'current_server_existing_capture': {'source': LOCAL_EXISTING_PCAP,
                  'sha256': sha256(local), **stats, 'outbound_skill_payload_available': False},
              'pairwise_byte_parity': 'UNVERIFIED_NO_PAIRED_CURRENT_SERVER_OUTBOUND_PAYLOAD',
              'not_proven': ['Sender function actually executed for the same cast or same session',
                             'Actual transmitted server frame bytes and dynamic field values match official samples',
                             'Skill failure caused by a packet difference',
                             'Equality or inequality of all game packets']}
    if local_frames:
        data = Path(local_frames).read_bytes()
        if sha256(data) in [a['sha256'] for a in official]:
            raise ValueError('Local frames exactly duplicate an official source; refusing false comparison')
        out = scan_frames(data, origin='USER_SUPPLIED_LOCAL_FRAMES')
        out['provenance'] = 'USER_ATTESTED_LOCAL' if local_capture_confirmed else 'UNVERIFIED_LOCAL_PROVENANCE'
        output['optional_local_frames'] = out
        if local_capture_confirmed and out['id20_frames']:
            output['local_vs_official_id20_schema_comparison'] = compare_variant_sets(out, official)
    return output


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('nested_server_zip')
    p.add_argument('server_exe')
    p.add_argument('--local-frames', help='Optional locally decoded CURRENT SERVER frames.log, never an official capture')
    p.add_argument('--local-capture-confirmed', action='store_true', help='You personally verified --local-frames came from your current server')
    p.add_argument('--go-binary', default='go')
    p.add_argument('--output')
    a = p.parse_args()
    if a.local_capture_confirmed and not a.local_frames:
        p.error('--local-capture-confirmed requires --local-frames')
    result = audit(a.nested_server_zip, a.server_exe,
                   local_frames=a.local_frames, local_capture_confirmed=a.local_capture_confirmed,
                   go_binary=a.go_binary)
    text = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if a.output:
        Path(a.output).write_text(text, encoding='utf8')
    print(text)

if __name__ == '__main__':
    main()
