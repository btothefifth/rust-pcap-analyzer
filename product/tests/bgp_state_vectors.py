"""Independent fixture arithmetic only; this does not execute the Rust reducer."""
from pathlib import Path
import hashlib
import struct
import unittest

FIXTURE = Path(__file__).with_name("fixtures") / "bgp_state.hex"


def vectors():
    result = {}
    for line in FIXTURE.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        name, value = line.split()
        if name in result:
            raise ValueError("duplicate vector name")
        result[name] = bytes.fromhex(value)
    return result


def frame(value):
    if len(value) < 19 or value[:16] != b"\xff" * 16:
        raise ValueError("incomplete/invalid header")
    length, kind = struct.unpack_from(">HB", value, 16)
    if not 19 <= length <= 4096 or length != len(value):
        raise ValueError("declared extent not exactly present")
    return kind


class WireArithmetic(unittest.TestCase):
    def setUp(self):
        self.v = vectors()

    def test_fixed_extents(self):
        expected = {"announce": (45, 2), "withdraw": (27, 2),
                    "notification": (23, 3), "keepalive": (19, 4),
                    "duplicate_origin": (49, 2)}
        self.assertEqual(set(self.v), set(expected))
        for name, (length, kind) in expected.items():
            self.assertEqual(len(self.v[name]), length)
            self.assertEqual(frame(self.v[name]), kind)

    def test_announcement_fields_and_exact_ranges(self):
        value = self.v["announce"]
        self.assertEqual(value[19:23], b"\x00\x00\x00\x12")
        self.assertEqual(value[23:27], bytes.fromhex("40010100"))
        self.assertEqual(value[27:34], bytes.fromhex("4002040201fde8"))
        self.assertEqual(struct.unpack_from(">H", value, 32)[0], 65000)
        self.assertEqual(value[34:41], bytes.fromhex("400304c0000201"))
        self.assertEqual(value[41:45], bytes([24, 203, 0, 113]))
        # Splitting at message offset 42 leaves one and three prefix bytes;
        # source packet offsets are 54 + 41 = 95 and 70 + 0 = 70.
        first, second = value[:42], value[42:]
        self.assertEqual(first[41:] + second, value[41:45])
        self.assertEqual((len(first[41:]), len(second)), (1, 3))

    def test_withdrawal_and_empty_attribute_section(self):
        value = self.v["withdraw"]
        self.assertEqual(struct.unpack_from(">H", value, 19)[0], 4)
        self.assertEqual(value[21:25], bytes([24, 203, 0, 113]))
        self.assertEqual(value[25:], b"\0\0")

    def test_notification_payload_is_not_a_digest(self):
        value = self.v["notification"]
        self.assertEqual(value[19:21], b"\6\2")
        self.assertEqual(value[21:], b"\xde\xad")
        # Characterizes why hex(payload) must not be called SHA-256.
        self.assertEqual(len(value[21:].hex()), 4)
        self.assertEqual(len(hashlib.sha256(value[21:]).hexdigest()), 64)
        self.assertNotEqual(value[21:].hex(), hashlib.sha256(value[21:]).hexdigest())

    def test_duplicate_origin_preserves_both_contradictory_bytes(self):
        value = self.v["duplicate_origin"]
        self.assertEqual(struct.unpack_from(">H", value, 21)[0], 22)
        self.assertEqual(value[23:27], bytes.fromhex("40010100"))
        self.assertEqual(value[27:31], bytes.fromhex("40010101"))
        self.assertEqual(value[45:], bytes([24, 203, 0, 113]))

    def test_all_truncated_extents_and_contradictory_lengths_fail_reference_boundary(self):
        for value in self.v.values():
            for end in range(len(value)):
                with self.assertRaises(ValueError):
                    frame(value[:end])
            for length in [0, 18, len(value) - 1, len(value) + 1, 4097]:
                changed = value[:16] + struct.pack(">H", length) + value[18:]
                with self.assertRaises(ValueError):
                    frame(changed)


if __name__ == "__main__":
    unittest.main()
