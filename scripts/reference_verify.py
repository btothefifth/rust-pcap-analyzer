#!/usr/bin/env python3
"""Independent fixture oracle, NOT execution or verification of the Rust code.
Uses struct/Fraction/hashlib and hand-authored TRUTH.json. It intentionally does
not import the fixture generator, Rust sources, or Rust expected output.
"""
from __future__ import annotations
import hashlib
import json
import struct
from fractions import Fraction
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


class InvalidCapture(ValueError):
    pass


def need(data: bytes, size: int) -> None:
    if len(data) < size:
        raise InvalidCapture("truncated")


def options(body: bytes, endian: str) -> dict[int, list[bytes]]:
    out: dict[int, list[bytes]] = {}
    pos = 0
    while pos < len(body):
        need(body[pos:], 4)
        code, length = struct.unpack_from(endian + "HH", body, pos)
        pos += 4
        if code == 0:
            if length:
                raise InvalidCapture("end length")
            break
        need(body[pos:], (length + 3) // 4 * 4)
        out.setdefault(code, []).append(body[pos:pos + length])
        pos += (length + 3) // 4 * 4
    return out


def nanos(ticks: int, resolution: int, offset: int) -> str | None:
    base = 2 if resolution >= 128 else 10
    exponent = resolution % 128
    time = Fraction(ticks, base ** exponent) * 10**9 + offset * 10**9
    return str(time.numerator) if time.denominator == 1 else None


def parse(data: bytes) -> dict:
    need(data, 4)
    magic = {b"\xd4\xc3\xb2\xa1": ("<", 6), b"\xa1\xb2\xc3\xd4": (">", 6),
             b"\x4d\x3c\xb2\xa1": ("<", 9), b"\xa1\xb2\x3c\x4d": (">", 9)}
    packets = []
    if data[:4] in magic:
        endian, resolution = magic[data[:4]]
        need(data, 24)
        major, minor, _, _, snap, link = struct.unpack_from(endian + "HHIIII", data, 4)
        if (major, minor) != (2, 4) or snap == 0:
            raise InvalidCapture("header")
        pos = 24
        while pos < len(data):
            need(data[pos:], 16)
            sec, frac, cap, orig = struct.unpack_from(endian + "IIII", data, pos)
            if cap > orig or cap > snap or frac >= 10**resolution:
                raise InvalidCapture("packet invariants")
            need(data[pos + 16:], cap)
            packets.append(dict(offset=pos, data_offset=16, data=data[pos + 16:pos + 16 + cap],
                                link=link & 65535, original=orig, section=0, interface=0,
                                ns=str(sec * 10**9 + frac * 10**(9-resolution))))
            pos += 16 + cap
        return dict(records=1 + len(packets), packets=packets)
    if data[:4] != b"\x0a\x0d\x0d\x0a":
        raise InvalidCapture("magic")
    pos = 0
    endian = None
    section = -1
    interfaces = []
    records = 0
    while pos < len(data):
        need(data[pos:], 12)
        if data[pos:pos + 4] == b"\x0a\x0d\x0d\x0a":
            bom = data[pos + 8:pos + 12]
            if bom not in [b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"]:
                raise InvalidCapture("BOM")
            endian = "<" if bom[0] == 0x4D else ">"
            section += 1
            interfaces = []
        if endian is None:
            raise InvalidCapture("no section")
        kind, size = struct.unpack_from(endian + "II", data, pos)
        if size < 12 or size % 4:
            raise InvalidCapture("block size")
        need(data[pos:], size)
        if struct.unpack_from(endian + "I", data, pos + size - 4)[0] != size:
            raise InvalidCapture("block trailer")
        body = data[pos + 8:pos + size - 4]
        if kind == 0x0A0D0D0A:
            need(body, 16)
            if struct.unpack_from(endian + "HH", body, 4) != (1, 0):
                raise InvalidCapture("section version")
        elif kind == 1:
            need(body, 8)
            link, _, snap = struct.unpack_from(endian + "HHI", body)
            opts = options(body[8:], endian)
            res = opts.get(9, [b"\x06"])[0][0]
            offset = struct.unpack(endian + "q", opts.get(14, [b"\0" * 8])[0])[0]
            interfaces.append((link, snap, res, offset))
        elif kind in (2, 6):
            need(body, 20)
            interface, hi, lo, cap, orig = struct.unpack_from(endian + "IIIII", body)
            if kind == 2:
                interface = struct.unpack_from(endian + "H", body)[0]
            if interface >= len(interfaces):
                raise InvalidCapture("interface scope")
            link, snap, res, off = interfaces[interface]
            if cap > orig or (snap and cap > snap):
                raise InvalidCapture("lengths")
            need(body[20:], (cap + 3) // 4 * 4)
            packets.append(dict(offset=pos, data_offset=28, data=body[20:20 + cap], link=link,
                                original=orig, section=section, interface=interface, ns=nanos((hi << 32) | lo, res, off)))
        elif kind == 3:
            need(body, 4)
            if not interfaces:
                raise InvalidCapture("SPB without interface")
            orig = struct.unpack_from(endian + "I", body)[0]
            link, snap, _, _ = interfaces[0]
            cap = min(orig, snap) if snap else orig
            if len(body) != 4 + (cap + 3) // 4 * 4:
                raise InvalidCapture("SPB length")
            packets.append(dict(offset=pos, data_offset=12, data=body[4:4 + cap], link=link, original=orig,
                                section=section, interface=0, ns=None))
        pos += size
        records += 1
    return dict(records=records, packets=packets)


def tcp_streams(packets: list[dict]) -> dict[tuple, bytes]:
    observations: dict[tuple, dict[int, int]] = {}
    for packet in packets:
        data = packet["data"]
        if packet["link"] != 1 or data[12:14] != b"\x08\x00":
            continue
        ip = data[14:]
        if ip[9] != 6:
            continue
        ip_header = (ip[0] & 15) * 4
        total = struct.unpack_from(">H", ip, 2)[0]
        tcp = ip[ip_header:total]
        src_port, dst_port, seq = struct.unpack_from(">HHI", tcp)
        key = (bytes(ip[12:16]), src_port, bytes(ip[16:20]), dst_port)
        payload = tcp[(tcp[12] >> 4) * 4:]
        seq += bool(tcp[13] & 2)
        positions = observations.setdefault(key, {})
        for i, b in enumerate(payload):
            old = positions.get(seq + i)
            if old is not None and old != b:
                raise InvalidCapture("conflicting TCP observations")
            positions[seq + i] = b
    output = {}
    for key, positions in observations.items():
        if not positions:
            continue
        lo, hi = min(positions), max(positions)
        if len(positions) != hi - lo + 1:
            raise InvalidCapture("TCP gap in oracle fixture")
        output[key] = bytes(positions[pos] for pos in range(lo, hi + 1))
    return output


def crc(data: bytes) -> int:
    value = 0
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = value // 2 ^ (0xA6BC if value % 2 else 0)
    return value ^ 65535


def dnp_applications(stream: bytes) -> list[bytes]:
    result = []
    pos = 0
    while pos < len(stream):
        header = stream[pos:pos + 10]
        assert len(header) == 10 and header[:2] == b"\x05\x64"
        assert crc(header[:8]) == int.from_bytes(header[8:], "little")
        length = header[2] - 5
        pos += 10
        parts = []
        while length:
            n = min(16, length)
            part = stream[pos:pos + n]
            assert crc(part) == int.from_bytes(stream[pos + n:pos + n + 2], "little")
            parts.append(part)
            pos += n + 2
            length -= n
        body = b"".join(parts)
        assert body[0] & 0xC0 == 0xC0  # This oracle targets single-transport fixture messages.
        result.append(body[1:])
    return result


def verify() -> dict:
    truth = json.loads((FIX / "TRUTH.json").read_text())["cases"]
    manifest = json.loads((FIX / "MANIFEST.json").read_text())["files"]
    for name, receipt in manifest.items():
        data = (FIX / name).read_bytes()
        assert len(data) == receipt["bytes"], name
        assert hashlib.sha256(data).hexdigest() == receipt["sha256"], name
    summary = {"fixture_hashes_verified": len(manifest), "container_cases_verified": 0,
               "rejected_fixture_cases": 0, "native_rust_executed": False,
               "scope": "Python fixture/oracle validation only; not a Rust build or test result"}
    for name, expected in truth.items():
        try:
            actual = parse((FIX / name).read_bytes())
        except InvalidCapture:
            assert expected.get("reject"), name
            summary["rejected_fixture_cases"] += 1
            continue
        assert not expected.get("reject"), name
        assert len(actual["packets"]) == expected["packets"], name
        if "records" in expected:
            assert actual["records"] == expected["records"], (name, actual["records"])
        for expected_key, key in [("times_ns", "ns"), ("interfaces", "interface"), ("sections", "section")]:
            if expected_key in expected:
                assert [p[key] for p in actual["packets"]] == expected[expected_key], (name, expected_key)
        if "lengths" in expected:
            assert [len(p["data"]) for p in actual["packets"]] == expected["lengths"]
        summary["container_cases_verified"] += 1
    assert crc(b"123456789") == 0xEA82
    streams = tcp_streams(parse((FIX / "dnp3_tcp.pcap").read_bytes())["packets"])
    applications = [app for data in streams.values() for app in dnp_applications(data)]
    assert len(applications) == 3
    assert sorted(app[1] for app in applications) == [1, 0x81, 0x82]
    assert next(app[2:] for app in applications if app[1] == 1).hex() == "3c0206"
    streams = tcp_streams(parse((FIX / "modbus_tcp.pcap").read_bytes())["packets"])
    assert len(streams) == 2
    for key, data in streams.items():
        tx, protocol, length, unit = struct.unpack_from(">HHHB", data)
        assert (tx, protocol, unit) == (42, 0, 1) and length == len(data) - 6
        assert data[7:] == (bytes.fromhex("03021234") if key[1] == 502 else bytes.fromhex("0300000001"))
    summary["independent_protocol_fixture_checks"] = ["DNP3 CRC known vector", "TCP reordering/dedup fixture",
                                                    "DNP3 request/response/unsolicited", "Modbus role independent of SYN initiator"]
    return summary

if __name__ == "__main__":
    print(json.dumps(verify(), indent=2, sort_keys=True))
