"""Independent canonical-identity arithmetic, not Rust replay or source proof."""
from __future__ import annotations
import copy
import csv
import hashlib
import json
from pathlib import Path
import unittest

FIXTURES = Path(__file__).resolve().parent / "fixtures"
DOMAIN = b"pcap-evidence/bgp/replay-prefix/v1\0"

def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def chain(previous: str, records: list[dict]) -> str:
    for record in records:
        previous = digest(DOMAIN + previous.encode("ascii") + canonical(record))
    return previous

class ReplayVectors(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads((FIXTURES / "bgp_replay_records.json").read_text(encoding="utf-8"))
        with (FIXTURES / "bgp_replay_hashes.tsv").open(encoding="utf-8", newline="") as source:
            self.expected = {r["name"]: r["sha256"] for r in csv.DictReader(source, delimiter="\t")}

    def test_fixed_declaration_and_prefix_commitments(self):
        feed = digest(canonical(self.fixture["declaration"]))
        self.assertEqual(feed, self.expected["feed"])
        start = digest(DOMAIN + feed.encode("ascii"))
        self.assertEqual(start, self.expected["prefix0"])
        for count in (1, 2):
            self.assertEqual(chain(start, self.fixture["records"][:count]), self.expected[f"prefix{count}"])

    def test_page_boundaries_do_not_change_record_sequence_commitment(self):
        records = self.fixture["records"]
        start = self.expected["prefix0"]
        self.assertEqual(chain(start, records), chain(chain(start, records[:1]), records[1:]))
        self.assertEqual(chain(start, []), start)

    def test_reversing_records_is_not_canonicalized_away(self):
        self.assertNotEqual(chain(self.expected["prefix0"], list(reversed(self.fixture["records"]))), self.expected["prefix2"])
        self.assertEqual([r["ordinal"] for r in self.fixture["records"]], ["0", "1"])

    def test_changed_immutable_record_content_and_coverage_have_different_commitments(self):
        record = self.fixture["records"][0]
        for field in ("med", "coverage", "record_id"):
            changed = copy.deepcopy(record)
            if field == "med":
                changed["observation"]["routes"][0]["attributes"]["med"] = 9
            elif field == "coverage":
                changed["coverage"] = "unknown"
            else:
                changed["observation"]["record_id"] = "different"
            self.assertNotEqual(chain(self.expected["prefix0"], [changed]), self.expected["prefix1"])

    def test_source_batch_and_checkpoint_changes_partition_the_declaration(self):
        for field in ("checkpoint_id", "batch_id", "sha256"):
            declaration = copy.deepcopy(self.fixture["declaration"])
            if field == "checkpoint_id":
                declaration["context"][field] = "checkpoint-b"
            elif field == "batch_id":
                declaration["context"]["batch"][field] = "batch-b"
            else:
                declaration["context"]["batch"][field] = digest(b"other batch")
            self.assertNotEqual(digest(canonical(declaration)), self.expected["feed"])

    def test_signed_time_labels_and_null_uncertainty_are_not_ordering(self):
        records = copy.deepcopy(self.fixture["records"])
        records[0]["observation"]["observed_at_ns"] = str(2**63 - 1)
        records[1]["observation"]["observed_at_ns"] = str(-(2**63))
        self.assertEqual([r["ordinal"] for r in records], ["0", "1"])
        self.assertNotEqual(chain(self.expected["prefix0"], records), chain(self.expected["prefix0"], list(reversed(records))))
        for record in records:
            self.assertIsNone(record["observation"]["import_context"]["clock"]["reported_uncertainty_ns"])
            self.assertIsNone(record["observation"]["evidence"])

    def test_exact_successor_requires_matching_predecessor_without_wrap(self):
        # Separately authored boundary table: (current, declared previous, next, allowed).
        for current, previous, next_generation, allowed in [(7, 7, 8, True), (7, 7, 9, False), (7, 6, 7, False), (7, 8, 9, False), (2**64 - 1, 2**64 - 1, 0, False)]:
            actual = previous == current and previous < 2**64 - 1 and next_generation == previous + 1
            self.assertEqual(actual, allowed)

    def test_canonical_object_keys_do_not_change_identity(self):
        declaration = self.fixture["declaration"]
        reordered = dict(reversed(list(declaration.items())))
        reordered["context"] = dict(reversed(list(declaration["context"].items())))
        self.assertEqual(canonical(reordered), canonical(declaration))

    def test_fixture_hashes_are_lowercase_and_names_unique(self):
        self.assertEqual(set(self.expected), {"feed", "prefix0", "prefix1", "prefix2"})
        for value in self.expected.values():
            self.assertEqual(len(value), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in value))
        self.assertFalse(self.fixture["declaration"]["context"]["wire_verified"])
        self.assertFalse(self.fixture["declaration"]["context"]["source_authenticated"])

if __name__ == "__main__":
    unittest.main()
