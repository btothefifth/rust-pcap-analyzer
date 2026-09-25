"""Independent Phase 1 BGP wire arithmetic, without calling the Rust decoder.

The expected values are hand derived from RFC 4271, 4724, 6793, 7313, 7911,
8654, 9234 and 9494. This is a fixture oracle, not endpoint-state evidence.
"""

import hashlib
import struct
import unittest


def message(kind, body=b""):
    result = b"\xff" * 16 + struct.pack(">HB", 19 + len(body), kind) + body
    assert len(result) == int.from_bytes(result[16:18], "big")
    return result


def capability(code, value=b""):
    assert len(value) <= 255
    return bytes((code, len(value))) + value


def opened(as16, capabilities):
    contents = b"".join(capabilities)
    parameter = bytes((2, len(contents))) + contents
    body = struct.pack(">BHHI", 4, as16, 90, 0xC0000201)
    return message(1, body + bytes((len(parameter),)) + parameter)


def attribute(flags, code, value):
    length = struct.pack(">H", len(value)) if flags & 0x10 else bytes((len(value),))
    return bytes((flags, code)) + length + value


def update(attributes, nlri=b"", withdrawn=b""):
    return message(2, struct.pack(">H", len(withdrawn)) + withdrawn
                   + struct.pack(">H", len(attributes)) + attributes + nlri)


def segment(kind, values, width):
    return bytes((kind, len(values))) + b"".join(number.to_bytes(width, "big") for number in values)


AS_TRANS = 23456
ORIGIN = attribute(0x40, 1, b"\0")
NEXT_HOP = attribute(0x40, 3, bytes((192, 0, 2, 9)))


class Phase1WireVectors(unittest.TestCase):
    def test_declared_capability_code_and_length_arithmetic(self):
        cases = [
            (1, b"\0\2\0\1"),  # IPv6 unicast AFI/SAFI
            (2, b""), (70, b""),
            (65, struct.pack(">I", 70000)),
            (64, b"\x8f\xff\0\2\1\x80"),  # restart flags/time + family
            (71, b"\0\2\1\x80\0\0\x3c"),  # LLGR family + 60 s
            (69, b"\0\2\1\3"),  # IPv6 unicast, send+receive
            (6, b""), (9, b"\4"),
            (200, b"\xde\xad"),
        ]
        raw = opened(AS_TRANS, [capability(code, value) for code, value in cases])
        self.assertEqual(raw[:19], b"\xff" * 16 + len(raw).to_bytes(2, "big") + b"\1")
        self.assertEqual(raw[19:29], bytes.fromhex("045ba0005ac0000201") + bytes((raw[28],)))
        self.assertEqual(raw[29], 2)
        self.assertEqual(raw[30], sum(2 + len(value) for _, value in cases))
        cursor = 31
        for code, value in cases:
            self.assertEqual(raw[cursor:cursor + 2], bytes((code, len(value))))
            self.assertEqual(raw[cursor + 2:cursor + 2 + len(value)], value)
            cursor += 2 + len(value)
        self.assertEqual(cursor, len(raw))
        self.assertEqual(hashlib.sha256(b"\xde\xad").hexdigest(),
                         "59ca84fb79f2a7447b9e82c7412df58c688910cba202b7d4e9bf329ce07f931c")

    def test_duplicate_conflicting_and_truncated_capabilities(self):
        first = capability(69, b"\0\2\1\2")
        same = capability(69, b"\0\2\1\2")
        conflict = capability(69, b"\0\2\1\1")
        self.assertEqual(first, same)
        self.assertNotEqual(first, conflict)
        for second in (same, conflict):
            raw = opened(64512, [first, second])
            self.assertEqual(raw[31:37], first)
            self.assertEqual(raw[37:43], second)
        valid = opened(64512, [first])
        for cut in (18, 19, 29, 30, 31, 32, 36):
            self.assertLess(len(valid[:cut]), int.from_bytes(valid[16:18], "big") if cut >= 18 else len(valid))
        malformed = bytearray(valid)
        malformed[32] = 5
        self.assertEqual(malformed[32], 5)
        self.assertEqual(len(malformed[33:]), 4)

    def test_as4_reconstruction_counting_and_transition_cases(self):
        two = segment(2, [65000, AS_TRANS, 64512], 2)
        four = segment(2, [70000, 64512], 4)
        attr = ORIGIN + attribute(0x40, 2, two) + NEXT_HOP + attribute(0xC0, 17, four)
        raw = update(attr, bytes.fromhex("18cb0071"))
        self.assertEqual(raw[19:23], b"\0\0" + len(attr).to_bytes(2, "big"))
        self.assertEqual(raw[23:27], ORIGIN)
        self.assertEqual(two[0:2], b"\2\3")
        self.assertEqual([int.from_bytes(two[i:i + 2], "big") for i in (2, 4, 6)],
                         [65000, AS_TRANS, 64512])
        self.assertEqual([int.from_bytes(four[i:i + 4], "big") for i in (2, 6)], [70000, 64512])
        # RFC 6793 section 4.2.3: prepend the first N-M old ASNs, here 3-2=1.
        self.assertEqual([65000] + [70000, 64512], [65000, 70000, 64512])
        self.assertEqual(raw[-4:], bytes.fromhex("18cb0071"))
        longer = segment(2, [70000, 80000, 90000, 100000], 4)
        self.assertGreater(longer[1], two[1])  # longer AS4_PATH must be discarded
        self.assertEqual(len(longer), 18)
        # Confederation members do not count toward N when replacing right suffix.
        confed = segment(3, [65001], 2) + two
        self.assertEqual(confed[:4], bytes.fromhex("0301fde9"))
        self.assertEqual(len(confed), 12)
        self.assertEqual(len(segment(4, [65001], 4)), 6)

    def test_as4_aggregator_new_old_arithmetic(self):
        address = bytes((192, 0, 2, 7))
        legacy = attribute(0xC0, 7, AS_TRANS.to_bytes(2, "big") + address)
        alternate = attribute(0xC0, 18, (70000).to_bytes(4, "big") + address)
        self.assertEqual(legacy[3:5], bytes.fromhex("5ba0"))
        self.assertEqual(alternate[3:7], bytes.fromhex("00011170"))
        self.assertEqual(legacy[5:9], alternate[7:11])
        self.assertEqual(len(legacy), 9)
        self.assertEqual(len(alternate), 11)
        self.assertNotEqual((65000).to_bytes(2, "big"), legacy[3:5])

    def test_add_path_direction_and_nlri_layout(self):
        identifier = 0x01020304
        prefix = bytes.fromhex("18cb0071")
        nlri = identifier.to_bytes(4, "big") + prefix
        raw = update(ORIGIN + NEXT_HOP, nlri)
        self.assertEqual(raw[-8:], bytes.fromhex("0102030418cb0071"))
        self.assertEqual(int.from_bytes(raw[-8:-4], "big"), identifier)
        self.assertEqual(raw[-4], 24)
        self.assertEqual(raw[-3:], bytes((203, 0, 113)))
        send, receive = 2, 1
        self.assertTrue(send & 2 and receive & 1)
        self.assertFalse((send & 1) and (receive & 2))

    def test_attribute_flag_and_length_boundaries(self):
        origin = attribute(0x40, 1, b"\0")
        bad_optional = attribute(0x80, 1, b"\0")
        extended = attribute(0x50, 5, (9).to_bytes(4, "big"))
        self.assertEqual(origin, bytes.fromhex("40010100"))
        self.assertEqual(bad_optional[0] & 0x80, 0x80)
        self.assertEqual(extended, bytes.fromhex("5005000400000009"))
        self.assertEqual(extended[2:4], len(extended[4:]).to_bytes(2, "big"))
        raw = update(origin + origin, bytes.fromhex("18cb0071"))
        self.assertEqual(raw[23:27], raw[27:31])
        self.assertEqual(raw[21:23], (8).to_bytes(2, "big"))
        self.assertEqual(raw[31:35], bytes.fromhex("18cb0071"))

    def test_split_and_coalesced_source_arithmetic(self):
        as_path = attribute(0x40, 2, segment(2, [70000], 4))
        raw = update(ORIGIN + as_path + NEXT_HOP, bytes.fromhex("18cb0071"))
        split = 34
        left, right = raw[:split], raw[split:]
        self.assertEqual(left + right, raw)
        self.assertEqual(raw[32:36], left[32:34] + right[:2])
        self.assertEqual(int.from_bytes(raw[32:36], "big"), 70000)
        coalesced = raw + message(4)
        self.assertEqual(coalesced[len(raw):], b"\xff" * 16 + b"\0\x13\4")
        self.assertEqual(int.from_bytes(coalesced[16:18], "big"), len(raw))

    def test_declared_extension_tuple_widths_and_otc_boundary(self):
        community = bytes.fromhex("0002000000000001")
        aigp = bytes.fromhex("01000b0000000000000009")
        large = bytes.fromhex("000000010000000200000003")
        otc = bytes.fromhex("00010064")
        self.assertEqual((len(community), len(aigp), len(large), len(otc)), (8, 11, 12, 4))
        self.assertEqual((community[0], community[1]), (0, 2))
        self.assertEqual(int.from_bytes(aigp[1:3], "big"), len(aigp))
        self.assertEqual(int.from_bytes(aigp[3:], "big"), 9)
        self.assertEqual(tuple(int.from_bytes(large[i:i+4], "big") for i in (0, 4, 8)), (1, 2, 3))
        self.assertEqual(int.from_bytes(otc, "big"), 65636)

    def test_extended_message_and_coalesced_header_arithmetic(self):
        payload = b"\0" * 4070
        attribute_bytes = bytes((0xd0, 200)) + len(payload).to_bytes(2, "big") + payload
        large = update(attribute_bytes, b"")
        self.assertEqual(len(attribute_bytes), 4074)
        self.assertEqual(len(large), 4097)
        self.assertEqual(int.from_bytes(large[16:18], "big"), 4097)
        coalesced = large + message(4)
        self.assertEqual(coalesced[4097:4116], b"\xff" * 16 + b"\0\x13\4")

    def test_eor_and_protocol_reset_wire_neighbors(self):
        conventional = update(b"")
        self.assertEqual(len(conventional), 23)
        self.assertEqual(conventional[19:23], b"\0\0\0\0")

        mp_unreach = attribute(0x80, 15, b"\0\2\1")
        multiprotocol = update(mp_unreach)
        self.assertEqual(mp_unreach, bytes.fromhex("800f03000201"))
        self.assertEqual(multiprotocol[19:23], b"\0\0\0\6")
        self.assertEqual(multiprotocol[23:], mp_unreach)

        malformed_mp_reach = attribute(0x80, 14, b"")
        malformed = update(malformed_mp_reach, bytes.fromhex("18cb0071"))
        self.assertEqual(malformed_mp_reach, bytes.fromhex("800e00"))
        self.assertEqual(malformed[21:23], b"\0\3")
        self.assertEqual(malformed[-4:], bytes.fromhex("18cb0071"))

        notification = message(3, b"\6\0")
        self.assertEqual(len(notification), 21)
        self.assertEqual(notification[18:], b"\3\6\0")


if __name__ == "__main__":
    unittest.main()
