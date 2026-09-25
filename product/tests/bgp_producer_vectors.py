"""Independent fixed-layout arithmetic; not Rust execution or BGP conformance."""
from pathlib import Path
import hashlib
import struct
import unittest

HERE = Path(__file__).resolve().parent
VECTORS = {
    row.split()[0]: bytes.fromhex(row.split()[1])
    for row in (HERE / "fixtures" / "bgp_producer.hex").read_text().splitlines()
    if row and not row.startswith("#")
}

class ProducerVectors(unittest.TestCase):
    def test_lengths_and_marker(self):
        expected = {
            "keepalive":19, "open_two":29, "open_four_a":37, "open_four_b":37,
            "open_four_large":37, "open_unknown":35, "open_duplicate":43,
            "open_conflict":43, "open_bad_cap_length":36, "open_cap_crosses_parameter":32,
            "announce_two":45, "announce_four":47, "announce_dual_width":51,
            "duplicate_origin":49, "unknown_no_routes":28, "notification":23, "refresh":23,
        }
        self.assertEqual(set(VECTORS), set(expected))
        for name, size in expected.items():
            raw = VECTORS[name]
            self.assertEqual(len(raw), size, name)
            self.assertEqual(raw[:16], b"\xff" * 16)
            self.assertEqual(int.from_bytes(raw[16:18], "big"), size)

    def test_open_scalar_and_capability_offsets(self):
        for name, as16, advertised in [("open_four_a",65000,65000), ("open_four_b",65001,65001), ("open_four_large",23456,65636)]:
            raw = VECTORS[name]
            self.assertEqual(struct.unpack_from(">HH", raw, 20), (as16, 90))
            self.assertEqual(raw[28:33], bytes([8,2,6,65,4]))
            self.assertEqual(int.from_bytes(raw[33:37], "big"), advertised)
        self.assertEqual(VECTORS["open_unknown"][31:35], bytes.fromhex("c802aabb"))

    def test_duplicate_and_conflicting_occurrences_have_distinct_ranges(self):
        duplicate, conflict = VECTORS["open_duplicate"], VECTORS["open_conflict"]
        self.assertEqual(duplicate[31:37], duplicate[37:43])
        self.assertNotEqual(conflict[31:37], conflict[37:43])
        raw = VECTORS["duplicate_origin"]
        self.assertEqual(raw[23:27], bytes.fromhex("40010100"))
        self.assertEqual(raw[27:31], bytes.fromhex("40010101"))
        self.assertEqual(raw[45:49], bytes.fromhex("18cb0071"))

    def test_update_fields_are_independently_expected(self):
        raw = VECTORS["announce_two"]
        self.assertEqual(raw[19:23], bytes.fromhex("00000012"))
        self.assertEqual(raw[23:27], bytes.fromhex("40010100"))
        self.assertEqual(raw[27:34], bytes.fromhex("4002040201fde8"))
        self.assertEqual(raw[34:41], bytes.fromhex("400304c0000201"))
        self.assertEqual(raw[41:45], bytes.fromhex("18cb0071"))
        self.assertEqual(int.from_bytes(VECTORS["announce_four"][32:36], "big"), 65636)

    def test_dual_width_is_not_a_negotiation_or_a_vote(self):
        data = VECTORS["announce_dual_width"][30:40]
        self.assertEqual(data, bytes.fromhex("02020001020102010002"))
        self.assertEqual((data[0], data[1], struct.unpack(">HH", data[2:6])), (2,2,(1,513)))
        self.assertEqual((data[6], data[7], int.from_bytes(data[8:10], "big")), (2,1,2))
        self.assertEqual(struct.unpack(">II", data[2:10]), (66049,33619970))

    def test_malformed_envelopes_are_local_boundary_failures(self):
        bad = VECTORS["open_bad_cap_length"]
        self.assertEqual(bad[31:33], bytes([65,3]))
        crossed = VECTORS["open_cap_crosses_parameter"]
        self.assertEqual(crossed[29:32], bytes([2,1,65]))
        self.assertEqual(len(crossed), 32) # no length byte inside parameter

    def test_sha256_is_not_payload_hex(self):
        self.assertEqual(hashlib.sha256(b"\0").hexdigest(), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
        data = VECTORS["unknown_no_routes"][26:28]
        self.assertEqual(data, bytes.fromhex("dead"))
        self.assertEqual(len(hashlib.sha256(data).hexdigest()),64)
        self.assertNotEqual(hashlib.sha256(data).hexdigest(), data.hex())

    def test_two_packet_field_ranges_conserve_the_source(self):
        raw = VECTORS["announce_four"]
        # A value [32,36) split at APDU offset 34 spans two packet slices.
        packet_a, packet_b = b"x"*54 + raw[:34], b"y"*70 + raw[34:]
        value = packet_a[86:88] + packet_b[70:72]
        self.assertEqual(value, bytes.fromhex("00010064"))
        self.assertEqual(value, raw[32:36])

if __name__ == "__main__":
    unittest.main()
