"""Independent streaming container oracle and bounded capture reducer support.

This implementation does NOT call the Rust parser. Its comparison surface is
packet boundaries, lengths, link type, raw clocks and exact packet-byte SHA-256.
Unsupported semantic metadata is not treated as decoded network traffic.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import struct
from typing import BinaryIO, Iterator
from .common import InvalidEvidence

MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 6), b"\xa1\xb2\xc3\xd4": (">", 6),
    b"\x4d\x3c\xb2\xa1": ("<", 9), b"\xa1\xb2\x3c\x4d": (">", 9),
}
SHB = b"\x0a\x0d\x0d\x0a"

@dataclass(frozen=True)
class Interface:
    link: int
    snaplen: int
    resolution: int = 6
    offset: int = 0

@dataclass(frozen=True)
class Packet:
    frame: int
    record_offset: int
    data_offset: int
    data: bytes
    original_length: int
    section: int
    interface: int
    link: int
    ticks: int | None
    resolution: int
    offset: int

    def row(self) -> dict:
        ns = None
        if self.ticks is not None:
            denominator = (2 ** (self.resolution & 127) if self.resolution & 128
                           else 10 ** self.resolution)
            numerator = self.ticks * 1_000_000_000
            if numerator % denominator == 0:
                ns = str(numerator // denominator + self.offset * 1_000_000_000)
        return dict(frame=str(self.frame), record_offset=str(self.record_offset),
                    data_offset=str(self.data_offset), captured_length=len(self.data),
                    original_length=self.original_length, section=self.section,
                    interface=self.interface, link_type=self.link,
                    timestamp_ns=ns, ticks=None if self.ticks is None else str(self.ticks),
                    resolution=self.resolution, offset_seconds=str(self.offset),
                    packet_sha256=hashlib.sha256(self.data).hexdigest())

@dataclass(frozen=True)
class Record:
    offset: int
    raw: bytes
    kind: int | str
    endian: str
    packet: Packet | None = None

class Reader:
    def __init__(self, file: BinaryIO, *, block_limit: int = 16 * 1024 * 1024,
                 packet_limit: int = 1024 * 1024, evidence: bool = False):
        self.file, self.block_limit, self.packet_limit = file, block_limit, packet_limit
        self.position = 0
        self.evidence = evidence
        self.finished = False

    def exact(self, count: int, *, eof: bool = False) -> bytes:
        if not 0 <= count <= self.block_limit:
            raise InvalidEvidence("record budget exceeded")
        chunks = bytearray()
        while len(chunks) < count:
            data = self.file.read(count - len(chunks))
            if not data:
                if eof and not chunks:
                    return b""
                raise InvalidEvidence(f"truncated record at {self.position}")
            self.position += len(data)
            chunks.extend(data)
        return bytes(chunks)

    def records(self) -> Iterator[Record]:
        if self.finished:
            raise InvalidEvidence("Reader is single-pass")
        self.finished = True
        first = self.exact(4)
        if first in MAGICS:
            endian, exponent = MAGICS[first]
            raw = first + self.exact(20)
            major, minor, _zone, _sigfig, snaplen, link_word = struct.unpack(endian + "HHIIII", raw[4:])
            if (major, minor) != (2, 4) or snaplen == 0:
                raise InvalidEvidence("unsupported classic PCAP header")
            yield Record(0, raw, "pcap_header", endian)
            frame = 0
            while True:
                at = self.position
                header = self.exact(16, eof=True)
                if not header:
                    return
                seconds, fraction, cap, original = struct.unpack(endian + "IIII", header)
                if cap > self.packet_limit:
                    raise InvalidEvidence("packet byte budget exceeded")
                if not self.evidence and (cap > original or cap > snaplen or fraction >= 10 ** exponent):
                    raise InvalidEvidence("contradictory PCAP record")
                data = self.exact(cap)
                frame += 1
                ticks = seconds * 10 ** exponent + fraction if fraction < 10 ** exponent else None
                packet = Packet(frame, at, at + 16, data, original, 0, 0,
                                link_word & 0xffff, ticks, exponent, 0)
                yield Record(at, header + data, "packet", endian, packet)
        elif first != SHB:
            raise InvalidEvidence("unsupported capture magic")
        else:
            endian, interfaces, section, frame = "<", [], -1, 0
            expected_end: int | None = None
            pending: bytes | None = first
            while True:
                at = 0 if pending is not None else self.position
                kind_bytes = pending if pending is not None else self.exact(4, eof=True)
                pending = None
                if not kind_bytes:
                    if expected_end is not None and self.position != expected_end:
                        raise InvalidEvidence("finite section ends outside source")
                    return
                prefix = kind_bytes + self.exact(8)
                is_section = kind_bytes == SHB
                if is_section:
                    bom = prefix[8:12]
                    if bom == b"\x4d\x3c\x2b\x1a":
                        endian = "<"
                    elif bom == b"\x1a\x2b\x3c\x4d":
                        endian = ">"
                    else:
                        raise InvalidEvidence("bad PCAPNG byte order")
                kind, length = struct.unpack(endian + "II", prefix[:8])
                if length < (28 if is_section else 12) or length % 4 or length > self.block_limit:
                    raise InvalidEvidence("invalid PCAPNG block size")
                raw = prefix + self.exact(length - 12)
                if struct.unpack_from(endian + "I", raw, length - 4)[0] != length:
                    raise InvalidEvidence("block length trailer mismatch")
                if expected_end is not None and ((is_section and at != expected_end) or (not is_section and at + length > expected_end)):
                    raise InvalidEvidence("declared section boundary violated")
                packet = None
                if is_section:
                    major, minor, declared = struct.unpack_from(endian + "HHq", raw, 12)
                    if (major, minor) != (1, 0) or declared < -1 or (declared >= 0 and declared % 4):
                        raise InvalidEvidence("unsupported PCAPNG section")
                    expected_end = None if declared == -1 else at + length + declared
                    section += 1
                    interfaces = []
                    self.options(raw, 24, length - 4, endian)
                elif kind == 1:
                    if length < 20 or len(interfaces) >= 1024:
                        raise InvalidEvidence("invalid/excessive interface descriptors")
                    link, _reserved, snaplen = struct.unpack_from(endian + "HHI", raw, 8)
                    opts = self.options(raw, 16, length - 4, endian)
                    resolution, offset = 6, 0
                    for code, value in opts:
                        if code == 9:
                            if len(value) != 1:
                                raise InvalidEvidence("bad if_tsresol")
                            resolution = value[0]
                        elif code == 14:
                            if len(value) != 8:
                                raise InvalidEvidence("bad if_tsoffset")
                            offset = struct.unpack(endian + "q", value)[0]
                    interfaces.append(Interface(link, snaplen, resolution, offset))
                elif kind in (2, 3, 6):
                    if kind in (2, 6):
                        if length < 32:
                            raise InvalidEvidence("short packet block")
                        if kind == 6:
                            iface, high, low, cap, original = struct.unpack_from(endian + "IIIII", raw, 8)
                        else:
                            iface, _drops, high, low, cap, original = struct.unpack_from(endian + "HHIIII", raw, 8)
                        ticks = (high << 32) | low
                        local = 28
                    else:
                        if length < 16 or not interfaces:
                            raise InvalidEvidence("short/simple packet without interface")
                        iface, ticks, local = 0, None, 12
                        original = struct.unpack_from(endian + "I", raw, 8)[0]
                        cap = min(original, interfaces[0].snaplen) if interfaces[0].snaplen else original
                    if iface >= len(interfaces):
                        raise InvalidEvidence("missing interface")
                    interface = interfaces[iface]
                    if cap > self.packet_limit or local + ((cap + 3) & ~3) > length - 4:
                        raise InvalidEvidence("captured bytes exceed block/budget")
                    if not self.evidence and (cap > original or (interface.snaplen and cap > interface.snaplen)):
                        raise InvalidEvidence("contradictory packet length")
                    if kind == 3 and local + ((cap + 3) & ~3) != length - 4:
                        raise InvalidEvidence("simple packet has unexplained bytes")
                    if kind != 3:
                        self.options(raw, local + ((cap + 3) & ~3), length - 4, endian)
                    frame += 1
                    packet = Packet(frame, at, at + local, raw[local:local + cap], original,
                                    section, iface, interface.link, ticks, interface.resolution, interface.offset)
                yield Record(at, raw, kind, endian, packet)

    @staticmethod
    def options(raw: bytes, start: int, end: int, endian: str) -> list[tuple[int, bytes]]:
        result = []
        p = start
        while p < end:
            if end - p < 4 or len(result) >= 4096:
                raise InvalidEvidence("invalid/excessive options")
            code, length = struct.unpack_from(endian + "HH", raw, p)
            p += 4
            if code == 0:
                if length != 0 or any(raw[p:end]):
                    raise InvalidEvidence("bad end-of-options")
                return result
            if p + ((length + 3) & ~3) > end:
                raise InvalidEvidence("option extends outside block")
            result.append((code, raw[p:p + length]))
            p += (length + 3) & ~3
        return result

    def packets(self) -> Iterator[Packet]:
        for record in self.records():
            if record.packet is not None:
                yield record.packet
