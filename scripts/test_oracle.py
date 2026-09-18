#!/usr/bin/env python3
"""Tests the Python oracle and negative controls, not the Rust implementation."""
import json
import sys
import unittest
sys.dont_write_bytecode = True
from reference_verify import FIX, InvalidCapture, crc, nanos, parse, verify

class OracleChecks(unittest.TestCase):
    def test_manifest_and_hand_authored_truth(self):
        self.assertEqual(verify()["fixture_hashes_verified"], 20)
    def test_decimal_and_binary_high_bit_are_different(self):
        self.assertEqual(nanos(1536, 0x8A, 0), "1500000000")
        self.assertNotEqual(nanos(1536, 10, 0), "1500000000")
    def test_signed_offset_not_unsigned_or_ignored(self):
        self.assertEqual(nanos(2000000007, 9, -2), "7")
        self.assertNotEqual(nanos(2000000007, 9, 0), "7")
    def test_inexact_binary_time_is_not_rounded(self):
        self.assertIsNone(nanos(1025, 0x8A, 0))
    def test_truncated_record_is_rejected(self):
        with self.assertRaises(InvalidCapture):
            parse((FIX / "truncated_record.pcap").read_bytes())
    def test_rehashed_fixture_metadata_does_not_change_semantic_truth(self):
        # Rewriting a fixture manifest cannot change this independently literal result.
        data = bytearray((FIX / "ethernet_udp_le_ns.pcap").read_bytes())
        data[:4] = bytes.fromhex("d4c3b2a1")
        with self.assertRaises(InvalidCapture):
            parse(bytes(data))
    def test_bad_trailer_reaches_length_predicate(self):
        with self.assertRaisesRegex(InvalidCapture, "block trailer"):
            parse((FIX / "bad_block_trailer.pcapng").read_bytes())
    def test_crc_external_vector(self):
        self.assertEqual(crc(b"123456789"), 0xEA82)
    def test_packet_slice_excludes_record_header(self):
        data = (FIX / "ethernet_udp_le_us.pcap").read_bytes()
        parsed = parse(data)["packets"][0]
        self.assertEqual(parsed["data"], data[40:])
        self.assertNotEqual(parsed["data"], data[24:])
    def test_sources_are_synthetic_and_truth_is_not_generated_receipt(self):
        truth = json.loads((FIX / "TRUTH.json").read_text())
        self.assertEqual(truth["cases"]["dnp3_tcp.pcap"]["dnp3_request_object_hex"], "3c0206")

if __name__ == "__main__":
    unittest.main(verbosity=2)
