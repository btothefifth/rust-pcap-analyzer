"""Independent identity/transition arithmetic, not execution of the Rust code."""
import copy
import hashlib
import json
from pathlib import Path
import unittest

DATA = Path(__file__).with_name("fixtures") / "bgp_import_context.json"

def partition(c):
    b = c["batch"]
    return (c["source_id"], c["session"], c["source_schema"], c["source_version"],
            b["batch_id"], b["sha256"], b["byte_length"], c["checkpoint_id"], c["peer"], c["local"])

def exact_hash(s):
    return isinstance(s, str) and len(s) == 64 and all(x in "0123456789abcdef" for x in s)

class IdentityVectors(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(DATA.read_text(encoding="utf-8"))
        self.context = self.data["context"]

    def test_source_hash_known_answers(self):
        self.assertEqual(hashlib.sha256(b"abc").hexdigest(), self.context["batch"]["sha256"])
        self.assertEqual(hashlib.sha256(b"").hexdigest(), self.data["second_hash"])

    def test_exact_hash_shape_negative_neighbors(self):
        self.assertTrue(exact_hash(self.context["batch"]["sha256"]))
        for h in ["", "a"*63, "a"*65, "A"*64, "g"*64, "0x"+"a"*64]:
            self.assertFalse(exact_hash(h))

    def test_context_namespace_has_expected_independent_dimensions(self):
        c = self.context
        expected = ("synthetic-source", "session-a", "route-record", "1", "batch-a", c["batch"]["sha256"], "3", "checkpoint-a", "peer-label", None)
        self.assertEqual(partition(c), expected)
        for key in ["source_id", "session", "source_schema", "source_version", "checkpoint_id", "peer", "local"]:
            other = copy.deepcopy(c); other[key] = "changed"
            self.assertNotEqual(partition(other), expected)
        for key in ["batch_id", "sha256", "byte_length"]:
            other = copy.deepcopy(c); other["batch"][key] = "changed"
            self.assertNotEqual(partition(other), expected)

    def test_clock_not_partition_or_order(self):
        other = copy.deepcopy(self.context)
        other["clock"] = {"policy": "source_label", "clock_id": "clock", "reported_uncertainty_ns": "0", "ordering_established": False}
        self.assertEqual(partition(other), partition(self.context))
        self.assertNotEqual(other, self.context)  # changed immutable-record content is not replay
        self.assertIsNone(self.context["clock"]["reported_uncertainty_ns"])
        self.assertFalse(self.context["clock"]["ordering_established"])

    def test_exact_source_range_not_packet_coordinates(self):
        span = self.context["provenance"][0]
        self.assertEqual((int(span["start"]), int(span["end"])), (0, 3))
        self.assertEqual(int(span["end"]) - int(span["start"]), len(b"abc"))
        self.assertNotIn("frame", span)
        self.assertFalse(self.context["wire_verified"])

    def test_successor_arithmetic_does_not_wrap_or_invent_epochs(self):
        for previous, next_generation, expected in self.data["successor_vectors"]:
            p, n = int(previous), int(next_generation)
            self.assertEqual(p < 2**64-1 and n == p + 1, expected)

    def test_canonical_json_is_stable_but_preserves_array_order(self):
        reordered = dict(reversed(list(self.context.items())))
        encode = lambda x: json.dumps(x, sort_keys=True, separators=(",", ":"))
        self.assertEqual(encode(reordered), encode(self.context))
        self.assertNotEqual(encode([1,2,1]), encode([1,1,2]))

    def test_hand_authored_transition_trace(self):
        # Small independent transition oracle. No BGP parser or implementation import.
        generations, routes, seen = {}, {}, {}
        for row in self.data["transition_trace"]:
            c = copy.deepcopy(self.context); c["checkpoint_id"] = row["checkpoint"]
            key = partition(c); generation = int(row["generation"])
            identity = (key, row["record"])
            content = (row["operation"], generation, row.get("previous"))
            if identity in seen:
                status = "identical_replay" if seen[identity] == content else "conflict"
            elif row["operation"] == "boundary":
                previous = row["previous"]
                if generations.get(key) != previous or generation != previous+1:
                    status = "invalid_transition"
                else:
                    generations[key] = generation; routes.pop(key, None); seen[identity] = content; status = "reset"
            elif key in generations and generations[key] != generation:
                status = "invalid_transition"
            else:
                generations.setdefault(key, generation); seen[identity] = content
                if row["operation"] == "announce": routes[key] = generation; status = "applied"
                else: status = "withdrawn" if routes.pop(key, None) is not None else "absent"
            self.assertEqual(status, row["expected"])
            self.assertEqual(len(routes), row["active"])

if __name__ == "__main__":
    unittest.main()
