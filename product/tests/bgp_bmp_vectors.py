"""Tiny primary-spec BMP arithmetic oracle; no Rust fixture/decoder import."""
import hashlib
import struct
import unittest


def common(kind, payload):
    return struct.pack("!BIB", 3, len(payload) + 6, kind) + payload


def open_pdu(asn, identifier):
    return b"\xff" * 16 + struct.pack("!HB BHHIB", 29, 1, 4, asn, 90, identifier, 0)


class BmpNormativeVectors(unittest.TestCase):
    def test_rfc7854_common_per_peer_and_two_open_ranges(self):
        peer = struct.pack(
            "!BBQ16sIIII", 1, 0x20, 0x0102030405060708,
            b"\0" * 12 + bytes([192, 0, 2, 1]), 65001, 0x0A000001, 100, 7,
        )
        self.assertEqual(len(peer), 42)
        local = b"\0" * 12 + bytes([192, 0, 2, 254])
        sent = open_pdu(65000, 0x0A0000FE)
        received = open_pdu(65001, 0x0A000001)
        raw = common(3, peer + local + struct.pack("!HH", 179, 40000) + sent + received)
        self.assertEqual(len(raw), 126)
        self.assertEqual(struct.unpack("!I", raw[1:5])[0], 126)
        self.assertEqual(raw[68:97], sent)
        self.assertEqual(raw[97:126], received)
        self.assertEqual(raw[8:16].hex(), "0102030405060708")
        self.assertEqual(raw[40:44], struct.pack("!I", 100))
        self.assertEqual(raw[44:48], struct.pack("!I", 7))
        # Independent literal transcription: marker, length=29, OPEN/BGP4,
        # AS=65000, hold=90, ID=10.0.0.254, no optional parameters.
        literal = bytes.fromhex("ffffffffffffffffffffffffffffffff001d0104fde8005a0a0000fe00")
        self.assertEqual(sent, literal)
        self.assertEqual(hashlib.sha256(raw[68:97]).digest(), hashlib.sha256(literal).digest())

    def test_rfc8671_bit_positions_keep_a_and_o_distinct(self):
        for flags, expected in [(0, (False, False, 4, False)),
                                (0xF0, (True, True, 2, True)),
                                (0x30, (False, False, 2, True))]:
            decoded = (bool(flags & 0x80), bool(flags & 0x40),
                       2 if flags & 0x20 else 4, bool(flags & 0x10))
            self.assertEqual(decoded, expected)

    def test_rfc9736_tlv_namespace_and_order(self):
        raw = (struct.pack("!HH", 0, 1) + b"a" + struct.pack("!HH", 0, 1) + b"b"
               + struct.pack("!HH", 3, 3) + b"vrf" + struct.pack("!HH", 4, 5) + b"label")
        rows = []
        offset = 0
        while offset < len(raw):
            kind, length = struct.unpack("!HH", raw[offset:offset + 4])
            start = offset + 4
            end = start + length
            rows.append((kind, start, end, raw[start:end]))
            offset = end
        self.assertEqual(rows, [(0, 4, 5, b"a"), (0, 9, 10, b"b"),
                                (3, 14, 17, b"vrf"), (4, 21, 26, b"label")])
        self.assertEqual({0, 3, 4} & {1, 2}, set())

    def test_peer_down_reason_is_one_octet_and_reason_two_has_two_bytes(self):
        raw = common(2, b"\0" * 42 + b"\x02\x00\x01")
        self.assertEqual(len(raw), 51)
        self.assertEqual(raw[48], 2)
        self.assertEqual(struct.unpack("!H", raw[49:51])[0], 1)
        self.assertEqual(len(common(2, b"\0" * 42 + b"\x05")), 49)


if __name__ == "__main__":
    unittest.main()
