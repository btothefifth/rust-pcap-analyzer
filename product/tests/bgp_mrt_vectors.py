"""Independent RFC 6396 byte-arithmetic oracle; imports no Rust implementation."""
import hashlib
import unittest


def u16(n):
    return n.to_bytes(2, "big")


def u32(n):
    return n.to_bytes(4, "big")


def record(second, kind, subtype, body):
    return u32(second) + u16(kind) + u16(subtype) + u32(len(body)) + body


def table():
    peer = bytes([2]) + bytes([192, 0, 2, 2]) + bytes([203, 0, 113, 9]) + u32(65551)
    body = bytes([192, 0, 2, 1]) + u16(1) + b"v" + u16(1) + peer
    assert len(peer) == 1 + 4 + 4 + 4
    return record(11, 13, 1, body)


def attrs():
    return b"\x40\x01\x01\x00" + b"\x40\x02\x06\x02\x01" + u32(65551) + b"\x40\x03\x04\xc0\x00\x02\x09"


def rib(peer_index=0, attributes=None):
    a = attrs() if attributes is None else attributes
    body = u32(7) + b"\x08\x0a" + u16(1) + u16(peer_index) + u32(10) + u16(len(a)) + a
    return record(12, 13, 2, body)


def generic(afi=2, safi=1):
    body = u32(8) + u16(afi) + bytes([safi, 32, 0x20, 1, 0x0d, 0xb8]) + u16(1) + u16(0) + u32(10) + u16(0)
    return record(13, 13, 6, body)


def bgp4mp(subtype=4, et=False, state=False):
    outer = (u16(64512) + u16(64513) if subtype in (0, 1) else u32(65551) + u32(65552))
    outer += u16(2) + u16(1) + bytes([203, 0, 113, 9, 192, 0, 2, 1])
    outer += u16(1) + u16(6) if state else b"\xff" * 16 + u16(19) + b"\x04"
    return record(21, 17 if et else 16, subtype, (u32(345678) if et else b"") + outer)


def frames(data, max_input=None, max_records=None):
    """Independent common-header reference; no semantic Rust code reused."""
    if max_input is not None and len(data) > max_input:
        raise ValueError("input")
    out = []
    pos = 0
    while pos < len(data):
        if len(data) - pos < 12:
            raise ValueError("header")
        second = int.from_bytes(data[pos:pos+4], "big")
        kind = int.from_bytes(data[pos+4:pos+6], "big")
        subtype = int.from_bytes(data[pos+6:pos+8], "big")
        length = int.from_bytes(data[pos+8:pos+12], "big")
        end = pos + 12 + length
        if end > len(data):
            raise ValueError("body")
        if max_records is not None and len(out) >= max_records:
            raise ValueError("records")
        body = data[pos+12:end]
        us = None
        if kind == 17:
            if len(body) < 4:
                raise ValueError("ET")
            us = int.from_bytes(body[:4], "big")
            if us >= 1_000_000:
                raise ValueError("ET value")
            body = body[4:]
        out.append((pos, end, second, kind, subtype, us, body, hashlib.sha256(data[pos:end]).hexdigest()))
        pos = end
    return out


class MrtVectors(unittest.TestCase):
    def test_known_layout_offsets_and_hashes(self):
        t, r, g = table(), rib(), generic()
        self.assertEqual((len(t), len(r), len(g)), (34, 48, 34))
        rows = frames(t + r + g)
        self.assertEqual([(x[0], x[1]) for x in rows], [(0, 34), (34, 82), (82, 116)])
        self.assertEqual([x[2:5] for x in rows], [(11, 13, 1), (12, 13, 2), (13, 13, 6)])
        self.assertEqual(rows[0][6][6:9], b"v\x00\x01")
        self.assertEqual(rows[0][6][9], 2)  # four-byte ASN peer type
        self.assertEqual(int.from_bytes(rows[0][6][-4:], "big"), 65551)
        self.assertEqual(rows[1][6][4:8], b"\x08\x0a\x00\x01")
        self.assertEqual(rows[1][6][8:16], b"\x00\x00" + u32(10) + u16(len(attrs())))
        self.assertEqual(len(rows[1][6][16:]), len(attrs()))
        self.assertEqual(rows[2][6][4:8], b"\x00\x02\x01\x20")
        self.assertEqual(len(rows[0][7]), 64)
        self.assertNotEqual(rows[0][7], rows[1][7])
        self.assertEqual(len(hashlib.sha256(t+r+g).digest()), 32)

    def test_every_partial_record_and_trailing_header(self):
        for full in (table(), rib(), generic(), bgp4mp(0, state=True), bgp4mp(et=True), record(1, 999, 7, b"abc")):
            for cut in range(1, len(full)):
                with self.subTest(length=len(full), cut=cut), self.assertRaises(ValueError):
                    frames(full[:cut])
        with self.assertRaises(ValueError):
            frames(table() + b"\x00")

    def test_unknown_and_generic_family_are_bounded_opaque(self):
        unknown = record(1, 999, 7, b"abc")
        self.assertEqual(frames(unknown)[0][6], b"abc")
        unsupported = generic(25, 99)
        row = frames(unsupported)[0]
        self.assertEqual((row[3], row[4]), (13, 6))
        self.assertEqual(row[6][4:7], b"\x00\x19\x63")
        # Unknown family NLRI has no safe entry-count offset.
        self.assertEqual(len(row[6]), len(unsupported)-12)

    def test_peer_index_rib_attribute_and_bgp4mp_arithmetic(self):
        t, r = table(), rib()
        peer_count = int.from_bytes(t[12+7:12+9], "big")
        peer_index = int.from_bytes(r[12+8:12+10], "big")
        self.assertEqual((peer_count, peer_index), (1, 0))
        self.assertFalse(peer_index >= peer_count)
        self.assertTrue(int.from_bytes(rib(1)[20:22], "big") >= peer_count)
        self.assertEqual(len(attrs()), 20)
        self.assertEqual(attrs()[4:9], b"\x40\x02\x06\x02\x01")
        state = frames(bgp4mp(0, state=True))[0]
        self.assertEqual(len(state[6]), 4+2+2+8+4)
        msg = frames(bgp4mp(4))[0]
        self.assertEqual(len(msg[6]), 8+2+2+8+19)
        self.assertEqual(msg[6][-19:], b"\xff"*16 + u16(19) + b"\x04")
        et = frames(bgp4mp(4, et=True))[0]
        self.assertEqual(et[5], 345678)
        self.assertEqual(et[1]-et[0], 12+4+len(msg[6]))

    def test_exact_limit_and_one_below(self):
        data = table()+rib()
        self.assertEqual(len(frames(data, max_input=len(data), max_records=2)), 2)
        for kwargs in ({"max_input": len(data)-1}, {"max_records": 1}):
            with self.assertRaises(ValueError):
                frames(data, **kwargs)
        self.assertEqual(len(frames(table(), max_input=len(table()), max_records=1)), 1)
        with self.assertRaises(ValueError):
            frames(table(), max_input=len(table())-1)


if __name__ == "__main__":
    unittest.main()
