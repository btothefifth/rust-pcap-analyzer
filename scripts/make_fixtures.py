#!/usr/bin/env python3
"""Deterministic, synthetic, non-sensitive fixtures. No Rust implementation imports.
A separate TRUTH.json contains hand-authored semantic expectations, not regenerated
by this script. CRC uses the forward polynomial plus bit reflection, unlike Rust.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def checksum(data: bytes) -> int:
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f">{len(data)//2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


def reflect(value: int, width: int) -> int:
    return int(f"{value:0{width}b}"[::-1], 2)


def dnp_crc(data: bytes) -> int:
    reg = 0
    for byte in data:
        reg ^= reflect(byte, 8) << 8
        for _ in range(8):
            reg = ((reg << 1) ^ (0x3D65 if reg & 0x8000 else 0)) & 65535
    return reflect(reg, 16) ^ 65535


A = bytes([10, 0, 0, 1])
B = bytes([10, 0, 0, 2])


def eth(payload: bytes, ether_type: int = 0x0800) -> bytes:
    return bytes.fromhex("020000000002020000000001") + struct.pack(">H", ether_type) + payload


def ipv4(payload: bytes, proto: int, src: bytes = A, dst: bytes = B,
         ident: int = 1, frag: int = 0) -> bytes:
    h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, frag, 64, proto, 0, src, dst)
    return h[:10] + struct.pack(">H", checksum(h)) + h[12:] + payload


def udp(data: bytes, src: bytes = A, dst: bytes = B) -> bytes:
    h = struct.pack(">HHHH", 12000, 12001, 8 + len(data), 0)
    c = checksum(src + dst + struct.pack(">BBH", 0, 17, len(h + data)) + h + data)
    return h[:6] + struct.pack(">H", c or 65535) + data


def tcp(data: bytes, seq: int, ack: int, flags: int, source_port: int, destination_port: int,
        src: bytes = A, dst: bytes = B) -> bytes:
    h = struct.pack(">HHIIBBHHH", source_port, destination_port, seq & 0xFFFFFFFF,
                    ack & 0xFFFFFFFF, 0x50, flags, 65535, 0, 0)
    c = checksum(src + dst + struct.pack(">BBH", 0, 6, len(h + data)) + h + data)
    return eth(ipv4(h[:16] + struct.pack(">H", c) + h[18:] + data, 6, src, dst))


def pcap(packets: list[bytes], endian: str = "<", nano: bool = False, link: int = 1) -> bytes:
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, link)
    fraction = 123456789 if nano else 123456
    for i, data in enumerate(packets):
        out += struct.pack(endian + "IIII", 1700000000 + i, fraction, len(data), len(data)) + data
    return out


def padded(data: bytes) -> bytes:
    return data + b"\0" * (-len(data) % 4)


def block(kind: int, body: bytes, e: str = "<") -> bytes:
    body = padded(body)
    length = 12 + len(body)
    return struct.pack(e + "II", kind, length) + body + struct.pack(e + "I", length)


def opt(code: int, data: bytes, e: str = "<") -> bytes:
    return struct.pack(e + "HH", code, len(data)) + padded(data)


def shb(e: str = "<") -> bytes:
    return block(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1), e)


def idb(link: int, snap: int, res: int = 6, offset: int = 0, e: str = "<") -> bytes:
    options = opt(9, bytes([res]), e) + opt(14, struct.pack(e + "q", offset), e)
    return block(1, struct.pack(e + "HHI", link, 0, snap) + options + opt(0, b"", e), e)


def epb(interface: int, ticks: int, data: bytes, e: str = "<") -> bytes:
    return block(6, struct.pack(e + "IIIII", interface, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data))
                 + padded(data) + opt(0, b"", e), e)


def dnp(user: bytes, src: int = 1024, dst: int = 1, control: int = 0xC4) -> bytes:
    h = bytes([5, 0x64, len(user) + 5, control]) + struct.pack("<HH", dst, src)
    out = h + struct.pack("<H", dnp_crc(h))
    for i in range(0, len(user), 16):
        part = user[i:i + 16]
        out += part + struct.pack("<H", dnp_crc(part))
    return out


def mb(tx: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", tx, 0, len(pdu) + 1, 1) + pdu


def fixtures() -> dict[str, bytes]:
    assert dnp_crc(b"123456789") == 0xEA82
    raw_ip = ipv4(udp(b"evidence"), 17)
    packet = eth(raw_ip)
    out = {}
    for e, name in [("<", "le"), (">", "be")]:
        for nano, precision in [(False, "us"), (True, "ns")]:
            out[f"ethernet_udp_{name}_{precision}.pcap"] = pcap([packet], e, nano)
    mixed = shb() + idb(1, 65535, 9, -2) + epb(0, 2000000007, packet)
    mixed += idb(101, 0, 0x8A) + epb(1, 1536, raw_ip)
    mixed += block(3, struct.pack("<I", len(packet)) + padded(packet))
    secret = b"private-test-key-material"
    mixed += block(10, struct.pack("<II", 0x544C534B, len(secret)) + padded(secret))
    mixed += block(0x40000BAD, struct.pack("<I", 32473) + b"preserve")
    mixed += block(0xABCDEF01, b"unknown!")
    mixed += block(4, opt(1, A + b"controller\0") + opt(0, b"") + opt(1, b"fixture comment") + opt(0, b""))
    mixed += block(5, struct.pack("<III", 1, 0, 1536))
    mixed += shb(">") + idb(101, 65535, e=">") + epb(0, 3000004, raw_ip, ">")
    out["mixed_sections.pcapng"] = mixed
    out["binary_inexact.pcapng"] = shb() + idb(1, 0, 0x8A) + epb(0, 1025, packet)
    out["timestamp_absent.pcapng"] = shb() + idb(1, 0) + block(3, struct.pack("<I", len(packet)) + padded(packet))
    out["unknown_link.pcap"] = pcap([b"\1\2\3"], link=65000)
    flagged = bytearray(out["ethernet_udp_le_us.pcap"])
    struct.pack_into("<I", flagged, 20, 0x24000001)
    out["pcap_link_flags.pcap"] = bytes(flagged)
    # DNP3 request split across TCP segments, delivered out of order and duplicated.
    request = dnp(bytes.fromhex("c0c1013c0206"))
    response = dnp(bytes.fromhex("c0c18100000102010101"), 1, 1024, 0x44)
    unsolicited = dnp(bytes.fromhex("c1d2820000020100"), 1, 1024, 0x44)
    server = response + unsolicited
    client_port, server_port = 40000, 20000
    c = lambda data, seq, ack, flags: tcp(data, seq, ack, flags, client_port, server_port)
    s = lambda data, seq, ack, flags: tcp(data, seq, ack, flags, server_port, client_port, B, A)
    dnppackets = [c(b"", 1000, 0, 2), s(b"", 5000, 1001, 0x12), c(b"", 1001, 5001, 0x10),
                  c(request[10:], 1011, 5001, 0x18), c(request[:10], 1001, 5001, 0x18),
                  c(request[:10], 1001, 5001, 0x18), s(server, 5001, 1001 + len(request), 0x18),
                  c(b"", 1001 + len(request), 5001 + len(server), 0x11),
                  s(b"", 5001 + len(server), 1002 + len(request), 0x11),
                  c(b"", 1002 + len(request), 5002 + len(server), 0x10)]
    out["dnp3_tcp.pcap"] = pcap(dnppackets)
    broken = bytearray(server); broken[10] ^= 1
    badpackets = dnppackets.copy(); badpackets[6] = s(bytes(broken), 5001, 1001 + len(request), 0x18)
    out["dnp3_bad_crc.pcap"] = pcap(badpackets)
    out["dnp3_transport_wrap.bin"] = dnp(bytes.fromhex("7fc1013c")) + dnp(bytes.fromhex("800206"))
    first_app = dnp(bytes.fromhex("c08f81000041"), 1, 1024, 0x44)
    last_app = dnp(bytes.fromhex("c14081000042"), 1, 1024, 0x44)
    out["dnp3_application_wrap.bin"] = first_app + last_app
    corrupt_link = bytearray(dnp(bytes.fromhex("c0c001"))); corrupt_link[8] ^= 1
    out["dnp3_interrupted.bin"] = first_app + bytes(corrupt_link) + last_app
    # Modbus service initiates TCP: endpoint role must not follow SYN direction.
    request_mb = mb(42, bytes.fromhex("0300000001"))
    response_mb = mb(42, bytes.fromhex("03021234"))
    c = lambda data, seq, ack, flags: tcp(data, seq, ack, flags, 40001, 502)
    s = lambda data, seq, ack, flags: tcp(data, seq, ack, flags, 502, 40001, B, A)
    modpackets = [s(b"", 5000, 0, 2), c(b"", 1000, 5001, 0x12), s(b"", 5001, 1001, 0x10),
                  c(request_mb[:7], 1001, 5001, 0x18), c(request_mb[7:], 1008, 5001, 0x18),
                  s(response_mb, 5001, 1001 + len(request_mb), 0x18),
                  c(b"", 1001 + len(request_mb), 5001 + len(response_mb), 0x11),
                  s(b"", 5001 + len(response_mb), 1002 + len(request_mb), 0x11),
                  c(b"", 1002 + len(request_mb), 5002 + len(response_mb), 0x10)]
    out["modbus_tcp.pcap"] = pcap(modpackets)
    out["modbus_messages.bin"] = request_mb + mb(43, bytes.fromhex("0600001234"))
    u = udp(b"ABCDEFGHIJKLMNOPQRSTUVWX")
    out["ipv4_fragments.pcap"] = pcap([eth(ipv4(u[16:], 17, ident=99, frag=2)), eth(ipv4(u[:16], 17, ident=99, frag=0x2000))])
    c = lambda data, seq, ack, flags: tcp(data, seq, ack, flags, 40002, 8080)
    s = lambda data, seq, ack, flags: tcp(data, seq, ack, flags, 8080, 40002, B, A)
    out["conflicting_tcp.pcap"] = pcap([c(b"", 1000, 0, 2), s(b"", 5000, 1001, 0x12),
        c(b"abcdef", 1001, 5001, 0x18), c(b"XYZ", 1004, 5001, 0x18),
        c(b"", 1007, 5001, 0x11), s(b"", 5001, 1008, 0x11)])
    out["truncated_record.pcap"] = out["ethernet_udp_le_us.pcap"][:-1]
    bad = bytearray(mixed); bad[24] ^= 4
    out["bad_block_trailer.pcapng"] = bytes(bad)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify exact generated bytes; do not modify")
    args = parser.parse_args()
    files = fixtures()
    manifest = {"schema": "pcap-evidence.synthetic-fixtures.v1", "files": {
        name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in sorted(files.items())}}
    files["MANIFEST.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    for name, data in files.items():
        path = FIX / name
        if args.check:
            if not path.exists() or path.read_bytes() != data:
                raise SystemExit(f"fixture drift: {name}")
        else:
            FIX.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    print(f"{'verified' if args.check else 'wrote'} {len(files)-1} deterministic synthetic fixtures")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
