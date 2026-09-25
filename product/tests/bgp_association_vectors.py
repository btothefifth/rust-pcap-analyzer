"""Small independent arithmetic vectors, not a Rust or protocol-conformance gate."""
from __future__ import annotations
import csv
import hashlib
import ipaddress
from pathlib import Path
import unittest

FIXTURES = Path(__file__).resolve().parent / "fixtures"

def rows(name: str) -> list[dict[str, str]]:
    lines = (FIXTURES / name).read_text(encoding="utf-8").splitlines()
    return list(csv.DictReader((line for line in lines if not line.startswith("#")), delimiter="\t"))

def optional(value: str) -> int | None:
    return None if value == "unknown" else int(value)

def relation(a: int | None, b: int | None, u: int | None, v: int | None, w: int) -> tuple:
    if a is None or b is None:
        return "unresolved", "missing_time", None, None, None
    distance = abs(a - b)
    if u is None or v is None:
        return "unresolved", "unknown_uncertainty", distance, None, None
    minimum = max(0, distance - u - v)
    maximum = distance + u + v
    if minimum > w:
        status, reason = "incompatible", "outside_window"
    elif maximum > w:
        status, reason = "unresolved", "uncertain_window"
    else:
        status, reason = "compatible_candidate", "-"
    return status, reason, distance, minimum, maximum

class AssociationVectors(unittest.TestCase):
    def test_fixed_time_cases_have_independent_expected_outcomes(self):
        values = rows("bgp_association_time.tsv")
        self.assertEqual(len(values), 9)
        for r in values:
            with self.subTest(r["id"]):
                expected = (r["status"], r["reason"], optional(r["distance_ns"]), optional(r["minimum_ns"]), optional(r["maximum_ns"]))
                self.assertEqual(relation(optional(r["route_ns"]), optional(r["internal_ns"]), optional(r["route_uncertainty_ns"]), optional(r["internal_uncertainty_ns"]), int(r["window_ns"])), expected)

    def test_reversing_time_arguments_preserves_symmetric_window(self):
        for r in rows("bgp_association_time.tsv"):
            a, b, u, v, w = (optional(r["route_ns"]), optional(r["internal_ns"]), optional(r["route_uncertainty_ns"]), optional(r["internal_uncertainty_ns"]), int(r["window_ns"]))
            self.assertEqual(relation(a,b,u,v,w), relation(b,a,v,u,w))

    def test_signed_extremes_are_exact_not_float_or_i64_subtraction(self):
        self.assertEqual(abs(-(2**63) - (2**63 - 1)), 18446744073709551615)
        self.assertEqual(3 * (2**64 - 1), 55340232221128654845)

    def test_unknown_is_different_from_explicit_zero(self):
        self.assertEqual(relation(None, 0, 0, 0, 0)[1], "missing_time")
        self.assertEqual(relation(0, 0, None, 0, 0)[1], "unknown_uncertainty")
        self.assertEqual(relation(0, 0, 0, 0, 0)[0], "compatible_candidate")

    def test_prefix_membership_vectors_preserve_address_family(self):
        values = rows("bgp_association_prefix.tsv")
        self.assertEqual(len(values), 7)
        for r in values:
            with self.subTest(r["id"]):
                prefix, endpoint = ipaddress.ip_network(r["prefix"], strict=True), ipaddress.ip_address(r["endpoint"])
                actual = prefix.version == endpoint.version and endpoint in prefix
                self.assertEqual(actual, r["contains"] == "true")

    def test_noncanonical_and_malformed_addresses_are_not_normalized_away(self):
        for value in ["203.0.113.1/24", "203.0.113.0/33", "2001:db8::1/32"]:
            with self.assertRaises(ValueError):
                ipaddress.ip_network(value, strict=True)
        with self.assertRaises(ValueError):
            ipaddress.ip_address("999.2.3.4")

    def test_source_identity_examples_are_distinct_without_preference(self):
        keys = [(kind, "source", "batch", checkpoint, "record")
                for kind in ("captured", "imported") for checkpoint in ("a", "b")]
        self.assertEqual(len(set(keys)), 4)
        self.assertNotEqual(hashlib.sha256(b"route fixture").digest(), hashlib.sha256(b"flow record").digest())

    def test_case_ids_are_unique_and_files_have_final_newlines(self):
        for name in ("bgp_association_time.tsv", "bgp_association_prefix.tsv"):
            data = (FIXTURES / name).read_bytes()
            self.assertTrue(data.endswith(b"\n"))
            ids = [row["id"] for row in rows(name)]
            self.assertEqual(len(ids), len(set(ids)))

if __name__ == "__main__":
    unittest.main()
