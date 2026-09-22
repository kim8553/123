#!/usr/bin/env python3
"""Offline candidate game-frame inventory from PCAPNG; no raw payload output.

The fixed XOR key and EE-stuffing hypothesis come from the supplied server
archive's artifacts/official_decode.py. Candidate framing is NOT validation of
server behavior, skill support, or equivalence across unrelated captures.
"""
import argparse
import hashlib
import json
import struct
from collections import Counter, defaultdict
from pathlib import Path

from pcapng_audit import SHB

KEY = struct.pack('<I', 0xFA6D3BCC)


def segments(path: Path):
    """Yield (src address bytes, source port, dst address bytes, dest port, TCP seq, payload)."""
    data = path.read_bytes()
    pos, endian, linktypes = 0, None, []
    while pos < len(data):
        if len(data) - pos < 12:
            raise ValueError('truncated PCAPNG block')
        if data[pos:pos + 4] == SHB:
            bom = data[pos + 8:pos + 12]
            if bom not in (b'\x4d\x3c\x2b\x1a', b'\x1a\x2b\x3c\x4d'):
                raise ValueError('bad PCAPNG byte order')
            endian = '<' if bom[0] == 0x4d else '>'
            linktypes = []
        if endian is None:
            raise ValueError('missing PCAPNG section')
        kind, length = struct.unpack_from(endian + 'II', data, pos)
        if length < 12 or length % 4 or length > len(data) - pos:
            raise ValueError('invalid PCAPNG block length')
        if struct.unpack_from(endian + 'I', data, pos + length - 4)[0] != length:
            raise ValueError('invalid PCAPNG block trailer')
        if kind == 1:
            if length < 20:
                raise ValueError('truncated interface description')
            linktypes.append(struct.unpack_from(endian + 'H', data, pos + 8)[0])
        elif kind == 6:
            if length < 32:
                raise ValueError('truncated enhanced packet')
            iface, _, _, cap, _ = struct.unpack_from(endian + 'IIIII', data, pos + 8)
            if iface >= len(linktypes) or cap > length - 32:
                raise ValueError('invalid captured length or interface')
            wire = data[pos + 28:pos + 28 + cap]
            link = linktypes[iface]
            if link == 1:
                if len(wire) < 14:
                    pos += length
                    continue
                ether = struct.unpack_from('!H', wire, 12)[0]
                wire = wire[14:]
                for _ in range(2):
                    if ether not in (0x8100, 0x88a8):
                        break
                    if len(wire) < 4:
                        break
                    ether = struct.unpack_from('!H', wire, 2)[0]
                    wire = wire[4:]
                if ether != 0x0800:
                    pos += length
                    continue
            elif link == 0:
                if len(wire) < 4 or wire[:4] not in (b'\x02\0\0\0', b'\0\0\0\x02'):
                    pos += length
                    continue
                wire = wire[4:]
            elif link != 101:
                pos += length
                continue
            if len(wire) >= 20 and wire[0] >> 4 == 4:
                ihl = (wire[0] & 15) * 4
                total = struct.unpack_from('!H', wire, 2)[0]
                frag = struct.unpack_from('!H', wire, 6)[0]
                if ihl >= 20 and total >= ihl + 20 and len(wire) >= total and wire[9] == 6 and not frag & 0x3fff:
                    tcp = wire[ihl:total]
                    h = (tcp[12] >> 4) * 4
                    if 20 <= h <= len(tcp) and len(tcp) > h:
                        source, dest, seq = struct.unpack_from('!HHI', tcp)
                        yield wire[12:16], source, wire[16:20], dest, seq, tcp[h:]
        pos += length


def unescape(chunk: bytes):
    """Return complete wire frames plus invalid-escape count; ignore trailing partial frame."""
    frames, cur, invalid = [], bytearray(), 0
    i = 0
    while i < len(chunk):
        if chunk[i] != 0xee:
            cur.append(chunk[i])
            i += 1
        elif i + 1 == len(chunk):
            break
        elif chunk[i + 1] == 0:
            cur.append(0xee)
            i += 2
        elif chunk[i + 1] == 0xee:
            if cur:
                frames.append(bytes(cur))
            cur.clear()
            i += 2
        else:
            invalid += 1
            cur.append(chunk[i])
            i += 1
    return frames, invalid


def custom_message_id(plain: bytes):
    # Candidate S2C 0x1E: opcode | u16 count | type2 | little-endian i32 ID
    if len(plain) < 8 or plain[0] != 0x1e or struct.unpack_from('<H', plain, 1)[0] < 1 or plain[3] != 2:
        return None
    return struct.unpack_from('<i', plain, 4)[0]


def audit(path: Path, server_ports=()):
    by_flow = defaultdict(list)
    for src, sport, dst, dport, seq, payload in segments(path):
        by_flow[(src, sport, dst, dport)].append((seq, payload))
    ports = set(server_ports)
    direction_opcodes = defaultdict(Counter)
    direction_custom = defaultdict(Counter)
    totals = Counter()
    for (_, src_port, _, dst_port), packets in by_flow.items():
        if src_port in ports and dst_port not in ports:
            direction = 'server_to_client'
        elif dst_port in ports and src_port not in ports:
            direction = 'client_to_server'
        else:
            direction = 'unknown'
        packets.sort(key=lambda p: p[0])
        chunks, chunk, end = [], bytearray(), None
        for seq, payload in packets:
            if end is not None and seq > end:
                totals['tcp_gaps'] += 1
                chunks.append(bytes(chunk))
                chunk.clear()
                end = None
            if end is not None and seq < end:
                overlap = end - seq
                if overlap >= len(payload):
                    totals['retransmissions_skipped'] += 1
                    continue
                payload = payload[overlap:]
            chunk.extend(payload)
            end = seq + len(payload)
        if chunk:
            chunks.append(bytes(chunk))
        totals['tcp_directional_flows'] += 1
        for part in chunks:
            frames, errors = unescape(part)
            totals['invalid_ee_escapes'] += errors
            if not frames:
                totals['non_framed_stream_chunks'] += 1
            for frame in frames:
                decoded = bytes(b ^ KEY[i & 3] for i, b in enumerate(frame))
                op = decoded[0]
                direction_opcodes[direction][f'0x{op:02x}'] += 1
                totals['candidate_game_frames'] += 1
                msgid = custom_message_id(decoded)
                if msgid is not None:
                    direction_custom[direction][str(msgid)] += 1
    return {
        'file': path.name,
        'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'counts': dict(sorted(totals.items())),
        'opcode_histograms': {direction: dict(sorted(hist.items())) for direction, hist in sorted(direction_opcodes.items())},
        'candidate_custom_message_ids': {direction: dict(sorted(ids.items(), key=lambda x: int(x[0])))
                                          for direction, ids in sorted(direction_custom.items())},
        'status': 'CANDIDATE_FIXED_XOR_FRAMES_ONLY; NOT A VERIFIED PACKET MISMATCH OR SKILL IMPLEMENTATION',
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('captures', nargs='+', type=Path)
    p.add_argument('--server-port', type=int, action='append', default=[],
                   help='Repeat for known server-side game ports; otherwise direction is unknown')
    args = p.parse_args()
    print(json.dumps([audit(path, args.server_port) for path in args.captures], ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
