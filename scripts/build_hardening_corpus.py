#!/usr/bin/env python3
"""Generate deterministic synthetic fuzz seeds; no traffic capture or downloads.

Every input has a construction note and SHA-256. Expected properties are authored
expectations, NOT assertions that the candidate Rust implementation passed them.
Default writes are create-only/idempotent: conflicting existing bytes are refused.
"""
from __future__ import annotations
import argparse
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import ipaddress
import json
from pathlib import Path
import struct

TARGETS = ('capture', 'engine', 'capture_parity', 'wire', 'tcp', 'protocols', 'provenance', 'index')

@dataclass(frozen=True)
class Seed:
    name: str
    data: bytes
    targets: tuple[str, ...]
    expectation: str
    container_valid: bool | None = None
    packet_count: int | None = None


def checksum(data: bytes) -> int:
    padded = data + (b'\0' if len(data) % 2 else b'')
    total = sum(struct.unpack('!' + 'H' * (len(padded) // 2), padded)) if padded else 0
    while total > 0xffff:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def dnp_crc(data: bytes) -> int:
    # MSB polynomial with reflected operands, independent of the Rust LSB loop.
    crc = 0
    for byte in data:
        crc ^= int(f'{byte:08b}'[::-1], 2) << 8
        for _ in range(8):
            crc = ((crc << 1) ^ (0x3d65 if crc & 0x8000 else 0)) & 0xffff
    return int(f'{(~crc) & 0xffff:016b}'[::-1], 2)


def dnp_frame(user: bytes, source: int = 1, destination: int = 2) -> bytes:
    if len(user) > 250:
        raise ValueError('DNP3 user data exceeds one link frame')
    head = bytes([5, 0x64, len(user) + 5, 0xc4]) + struct.pack('<HH', destination, source)
    return head + struct.pack('<H', dnp_crc(head)) + b''.join(
        user[i:i + 16] + struct.pack('<H', dnp_crc(user[i:i + 16])) for i in range(0, len(user), 16))


def modbus(pdu: bytes, transaction: int = 42, unit: int = 1) -> bytes:
    return struct.pack('!HHHB', transaction, 0, len(pdu) + 1, unit) + pdu


def ipv4(payload: bytes, protocol: int, *, identification: int = 1, offset: int = 0, more: bool = False) -> bytes:
    if offset % 8 or len(payload) + 20 > 65535:
        raise ValueError('invalid IPv4 construction operands')
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), identification,
                                  offset // 8 | (0x2000 if more else 0), 64, protocol, 0,
                                  bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])))
    struct.pack_into('!H', header, 10, checksum(header))
    return bytes(header) + payload


def udp(payload: bytes, destination: int = 20000, *, ipv6: bool = False) -> bytes:
    packet = bytearray(struct.pack('!HHHH', 12000, destination, len(payload) + 8, 0) + payload)
    if ipv6:
        pseudo = ipaddress.IPv6Address('2001:db8::1').packed + ipaddress.IPv6Address('2001:db8::2').packed
        pseudo += struct.pack('!I', len(packet)) + b'\0\0\0\x11'
    else:
        pseudo = bytes([10, 0, 0, 1, 10, 0, 0, 2, 0, 17]) + struct.pack('!H', len(packet))
    struct.pack_into('!H', packet, 6, checksum(pseudo + packet) or 0xffff)
    return bytes(packet)


def ipv6_fragment(payload: bytes, *, offset: int, more: bool, next_header: int = 17) -> bytes:
    if offset % 8:
        raise ValueError('unaligned fragment offset')
    header = struct.pack('!IHBB', 6 << 28, len(payload) + 8, 44, 64)
    header += ipaddress.IPv6Address('2001:db8::1').packed + ipaddress.IPv6Address('2001:db8::2').packed
    return header + struct.pack('!BBHI', next_header, 0, offset | int(more), 123) + payload


def pcap(packets: list[bytes], *, endian: str = '<', nanos: bool = False, link: int = 228) -> bytes:
    output = struct.pack(endian + 'IHHIIII', 0xa1b23c4d if nanos else 0xa1b2c3d4, 2, 4, 0, 0, 65535, link)
    for i, packet in enumerate(packets):
        output += struct.pack(endian + 'IIII', 123 + i, 456, len(packet), len(packet)) + packet
    return output


def block(kind: int, body: bytes, endian: str = '<') -> bytes:
    body += b'\0' * (-len(body) % 4)
    size = len(body) + 12
    return struct.pack(endian + 'II', kind, size) + body + struct.pack(endian + 'I', size)


def option(kind: int, value: bytes, endian: str = '<') -> bytes:
    return struct.pack(endian + 'HH', kind, len(value)) + value + b'\0' * (-len(value) % 4)


def shb(endian: str = '<', declared: int = -1) -> bytes:
    return block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, declared), endian)


def pcapng(packet: bytes, *, endian: str = '<', resolution: int = 6, offset: int = 0,
           ticks: int = 123000456, unknown: bool = False, simple: bool = False) -> bytes:
    idb = struct.pack(endian + 'HHI', 228, 0, 65535)
    idb += option(9, bytes([resolution]), endian) + option(14, struct.pack(endian + 'q', offset), endian) + option(0, b'', endian)
    if simple:
        record = block(3, struct.pack(endian + 'I', len(packet)) + packet, endian)
    else:
        record = block(6, struct.pack(endian + 'IIIII', 0, ticks >> 32, ticks & 0xffffffff, len(packet), len(packet)) + packet, endian)
    return shb(endian) + block(1, idb, endian) + (block(0x12345678, b'opaque', endian) if unknown else b'') + record


def timestamp_ns(ticks: int, resolution: int, offset: int) -> int | None:
    base = 2 if resolution & 0x80 else 10
    seconds = Fraction(ticks, base ** (resolution & 0x7f)) + offset
    ns = seconds * 1_000_000_000
    return ns.numerator if ns.denominator == 1 else None


def seeds() -> list[Seed]:
    output: list[Seed] = []
    capture_targets = ('capture', 'engine', 'capture_parity')
    def capture(name: str, data: bytes, valid: bool, packets: int | None, note: str) -> None:
        output.append(Seed(name, data, capture_targets, note, valid, packets))
    dnp = dnp_frame(bytes([0xc0, 0xc0, 1, 0x3c, 2, 6]))
    packet = ipv4(udp(dnp), 17)
    for endian, label in [('<', 'le'), ('>', 'be')]:
        for nanos in [False, True]:
            raw = pcap([packet], endian=endian, nanos=nanos)
            name = f'pcap_{label}_{"ns" if nanos else "us"}'
            capture(name, raw, True, 1, 'one raw-IPv4 DNP3 UDP packet, exact packet preservation')
            for cut in [0, 1, 3, 4, 12, 23, 25, 39, len(raw) - 1]:
                capture(f'{name}_truncated_{cut}', raw[:cut], False, None, 'structural truncation must reject')
            capture(f'{name}_header_only', raw[:24], True, 0, 'valid empty legacy capture')
        for resolution in [0, 6, 9, 10, 18, 19, 127, 128, 129, 137, 138, 191, 255]:
            capture(f'ng_{label}_res_{resolution}', pcapng(packet, endian=endian, resolution=resolution, offset=-2), True, 1,
                    f'preserve raw clock; exact ns projection is {timestamp_ns(123000456, resolution, -2)!r}')
        capture(f'ng_{label}_spb', pcapng(packet, endian=endian, simple=True), True, 1, 'SPB time remains absent')
        capture(f'ng_{label}_unknown', pcapng(packet, endian=endian, unknown=True), True, 1, 'unknown block preserved, not guessed')
        for declared in [1, 2, 3, 5, -2]:
            capture(f'ng_{label}_bad_section_{declared}', shb(endian, declared), False, None, 'invalid finite alignment or negative section length')
        capture(f'ng_{label}_empty_finite_section', shb(endian, 0), True, 0, 'aligned empty finite section is valid')
    capture('mixed_endian_sections', pcapng(packet) + pcapng(packet, endian='>'), True, 2, 'section-local clocks and interfaces restart')
    bad_trailer = bytearray(pcapng(packet)); bad_trailer[-1] ^= 0x80
    capture('ng_bad_trailer', bytes(bad_trailer), False, None, 'leading/trailing block sizes disagree')
    bad_interface = bytearray(pcapng(packet)); struct.pack_into('<I', bad_interface, 28 + 44 + 8, 3)
    capture('ng_undeclared_interface', bytes(bad_interface), False, None, 'packet references a missing interface')
    # Container-valid packet-semantic edge cases remain observations.
    datagram = udp(b'abcdefghijklmnop', destination=12001, ipv6=True)
    first = ipv6_fragment(datagram[:16], offset=0, more=True)
    last = ipv6_fragment(datagram[16:], offset=16, more=False, next_header=6)
    capture('ipv6_next_header_variation', pcap([last, first], link=229), True, 2, 'one reassembly; offset-zero Next Header wins')
    overlap = ipv6_fragment(b'XXXXXXXX', offset=8, more=True, next_header=6)
    capture('ipv6_overlap_changed_next_header', pcap([first, overlap, last], link=229), True, 3, 'one quarantined set, not independent protocol-keyed sets')
    gap = dnp_frame(bytes([0xc0, 0x8f, 0x81, 0, 0, 65]), 2, 1)
    gap += dnp_frame(bytes([0x41, 0x40, 0x81]), 2, 1) + dnp_frame(bytes([0x83, 0, 0, 88]), 2, 1)
    gap += dnp_frame(bytes([0xc4, 0x40, 0x81, 0, 0, 66]), 2, 1)
    for name, payload in [('dnp_valid', dnp), ('dnp_transport_application_gap', gap)]:
        output.append(Seed(name, payload, ('protocols', 'provenance', 'index'), 'DNP3 state/CRC boundaries; do not bridge interrupted state'))
        capture(name + '_udp', pcap([ipv4(udp(payload), 17)]), True, 1, 'configured UDP DNP3 reaches datagram-local analysis')
    for length in [0, 1, 2, 15, 16, 17, 31, 32, 249, 250]:
        frame = dnp_frame(bytes([0xc0]) + bytes(range(length - 1)) if length else b'')
        output.append(Seed(f'dnp_block_length_{length}', frame, ('protocols',), 'link CRC block boundaries, including link-only frames'))
        if len(frame) > 10:
            bad = bytearray(frame); bad[-1] ^= 1
            output.append(Seed(f'dnp_bad_crc_{length}', bytes(bad), ('protocols',), 'CRC failure must not authorize application reconstruction'))
    pdus = {
        'read_valid': bytes([3, 0, 0, 0, 2]), 'read_zero': bytes([3, 0, 0, 0, 0]),
        'read_max': bytes([3, 0, 0, 0, 125]), 'read_too_many': bytes([3, 0, 0, 0, 126]),
        'address_wrap': bytes([3, 255, 255, 0, 2]), 'coil_bad_value': bytes([5, 0, 0, 18, 52]),
        'coil_valid_value': bytes([5, 0, 0, 255, 0]), 'write_coils_bad_count': bytes([15, 0, 0, 0, 9, 1, 255]),
        'write_regs_bad_count': bytes([16, 0, 0, 0, 2, 2, 0, 0]),
        'read_odd_response': bytes([3, 3, 0, 1, 2]), 'read_valid_response': bytes([3, 4, 0, 1, 0, 2]),
        'exception_valid': bytes([0x83, 2]), 'exception_zero': bytes([0x83, 0]), 'unknown': bytes([0x41]),
    }
    for name, pdu in pdus.items():
        output.append(Seed('modbus_' + name, modbus(pdu), ('protocols', 'provenance', 'index'), 'common-function constraints; unknown functions remain opaque'))
    # Wire fuzzer consumes a link-selector byte followed by actual packet bytes.
    ethernet = bytes(12) + b'\x08\x00' + packet
    sll = bytes(14) + b'\x08\x00' + packet
    sll2 = b'\x08\x00\x00\x00' + struct.pack('!I', 7) + bytes(12) + packet
    for selector, name, raw in [(0, 'ethernet', ethernet), (1, 'null', struct.pack('<I', 2) + packet),
                                (2, 'loop', struct.pack('!I', 2) + packet), (3, 'raw', packet),
                                (4, 'ipv4', packet), (5, 'ipv6_fragment', first), (6, 'sll', sll), (7, 'sll2', sll2)]:
        output.append(Seed('wire_' + name, bytes([selector]) + raw, ('wire',), 'selector-specific link offsets and source provenance'))
    for length in [0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 1024]:
        payload = bytes((i * 31 + 7) % 256 for i in range(length))
        output.append(Seed(f'bytes_{length}', payload, ('protocols', 'provenance', 'index'), 'boundary-length hostile bytes'))
    # TCP target: anchor u32 LE, then (delta i16, length u8, flags u8, bytes).
    def segment(delta: int, raw: bytes, flags: int = 0) -> bytes:
        return struct.pack('<hBB', delta, len(raw), flags) + raw
    for name, body in [
        ('reordered', segment(3, b'def') + segment(0, b'abc')),
        ('duplicate', segment(0, b'abc') * 2), ('conflict', segment(0, b'abc') + segment(1, b'XX')),
        ('gap', segment(0, b'abc') + segment(6, b'ghi')),
        ('fin_then_payload', segment(0, b'', 1) + segment(1, b'X')),
    ]:
        output.append(Seed('tcp_' + name, struct.pack('<I', 1001 if name == 'fin_then_payload' else 1000) + body, ('tcp',), 'reconstruction policy/provenance invariants'))
    return output


def write_new_or_same(path: Path, data: bytes) -> None:
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError(f'refusing symlink: {component}')
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError(f'refusing different existing content: {path}')
        return
    with path.open('xb') as stream:
        stream.write(data)


def generate(output: Path) -> dict:
    records = []
    for seed in seeds():
        sha = hashlib.sha256(seed.data).hexdigest()
        for target in seed.targets:
            if target not in TARGETS:
                raise ValueError(f'unknown target: {target}')
            write_new_or_same(output / target / (seed.name + '.bin'), seed.data)
        records.append({'name': seed.name, 'sha256': sha, 'bytes': len(seed.data), 'targets': seed.targets,
                        'expectation': seed.expectation, 'container_valid': seed.container_valid, 'packet_count': seed.packet_count})
    manifest = {'schema': 'pcap-evidence.synthetic-corpus.v1', 'real_world_captures': False,
                'candidate_rust_executed': False, 'seed_count': len(records),
                'target_copies': sum(len(x['targets']) for x in records), 'seeds': records}
    write_new_or_same(output / 'MANIFEST.json', (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode())
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = generate(args.output)
    print(json.dumps({k: v for k, v in manifest.items() if k != 'seeds'}, indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
