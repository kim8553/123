#!/usr/bin/env python3
"""Read-only PCAPNG transport inventory; never interpret encrypted payload as opcodes.

Supported link types: Ethernet (1), BSD loopback/NULL (0), raw IPv4 (101).
No payloads, addresses, or credentials are included in the report.
"""
import argparse
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

SHB = b'\x0a\x0d\x0d\x0a'


def tcp_payload_size(packet: bytes, linktype: int):
    if linktype == 1:
        if len(packet) < 14:
            return None
        kind = struct.unpack_from('!H', packet, 12)[0]
        packet = packet[14:]
        for _ in range(2):
            if kind not in (0x8100, 0x88a8):
                break
            if len(packet) < 4:
                return None
            kind = struct.unpack_from('!H', packet, 2)[0]
            packet = packet[4:]
        if kind != 0x0800:
            return None
    elif linktype == 0:
        if len(packet) < 4 or packet[:4] not in (b'\x02\x00\x00\x00', b'\x00\x00\x00\x02'):
            return None
        packet = packet[4:]
    elif linktype != 101:
        return None
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 15) * 4
    if ihl < 20 or len(packet) < ihl:
        return None
    total = struct.unpack_from('!H', packet, 2)[0]
    if total < ihl or len(packet) < total or packet[9] != 6:
        return None
    fragment = struct.unpack_from('!H', packet, 6)[0]
    if fragment & 0x3fff:
        return None
    tcp = packet[ihl:total]
    if len(tcp) < 20:
        return None
    header = (tcp[12] >> 4) * 4
    if header < 20 or header > len(tcp):
        return None
    return len(tcp) - header


def audit(path: Path):
    data = path.read_bytes()
    pos, endian, interfaces = 0, None, []
    totals = Counter()
    links = Counter()
    while pos < len(data):
        if len(data) - pos < 12:
            raise ValueError(f'truncated block header at offset {pos}')
        if data[pos:pos + 4] == SHB:
            bom = data[pos + 8:pos + 12]
            if bom == b'\x4d\x3c\x2b\x1a':
                endian = '<'
            elif bom == b'\x1a\x2b\x3c\x4d':
                endian = '>'
            else:
                raise ValueError(f'invalid section byte-order magic at offset {pos}')
            interfaces = []
            totals['sections'] += 1
        if endian is None:
            raise ValueError('PCAPNG must start with a section header')
        kind, length = struct.unpack_from(endian + 'II', data, pos)
        if length < 12 or length % 4 or length > len(data) - pos:
            raise ValueError(f'invalid block length at offset {pos}')
        if struct.unpack_from(endian + 'I', data, pos + length - 4)[0] != length:
            raise ValueError(f'block trailer mismatch at offset {pos}')
        totals['blocks'] += 1
        if kind == 1:
            if length < 20:
                raise ValueError('truncated interface description block')
            interfaces.append(struct.unpack_from(endian + 'H', data, pos + 8)[0])
        elif kind == 6:
            if length < 32:
                raise ValueError('truncated enhanced packet block')
            iface, _, _, captured, _ = struct.unpack_from(endian + 'IIIII', data, pos + 8)
            if iface >= len(interfaces) or captured > length - 32:
                raise ValueError(f'invalid packet interface/length at offset {pos}')
            link = interfaces[iface]
            links[str(link)] += 1
            totals['packets'] += 1
            size = tcp_payload_size(data[pos + 28:pos + 28 + captured], link)
            if size is not None:
                totals['tcp_packets'] += 1
                if size:
                    totals['tcp_payload_packets'] += 1
                    totals['tcp_payload_bytes'] += size
        pos += length
    if not totals['sections']:
        raise ValueError('no PCAPNG section header')
    return {
        'file': path.name,
        'sha256': hashlib.sha256(data).hexdigest(),
        'counts': dict(sorted(totals.items())),
        'linktype_packet_counts': dict(sorted(links.items())),
        'interpretation': 'TRANSPORT_ONLY; no application packet IDs or skill support inferred',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('captures', nargs='+', type=Path)
    args = parser.parse_args()
    print(json.dumps([audit(path) for path in args.captures], indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
