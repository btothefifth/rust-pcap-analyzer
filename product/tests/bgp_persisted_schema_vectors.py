"""Independent v1/v2 side/version consistency witnesses; no source authority."""
import json
from pathlib import Path
import unittest
import jsonschema

SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "docs/product/bgp-association.schema.json").read_text())


def report(version, input_version, side):
    value = {
        "schema": f"pcap-evidence.bgp.association.v{version}",
        "policy": {"policy_id": "fixture", "namespace": "require_equal", "session": "ignore", "generation": "ignore", "flow": "ignore", "direction": "ignore", "spatial": "equal_prefix", "time": {"mode": "ignore_labels", "reason": "explicit fixture"}},
        "candidate_snapshot_sha256": None,
        "endpoint_state_established": False, "rib_established": False,
        "best_path_selected": False, "reachability_established": False,
        "attack_established": False, "causality_established": False,
        "source_authority_established": False, "normative_conformance_certified": False,
        "issues": [], "route_evidence": [],
        "internal_evidence": [{"evidence": {"schema": f"pcap-evidence.association-input.v{input_version}", "side": side}, "input_sha256": "1" * 64, "occurrences": "1", "reasons": []}],
        "selection_notes": [],
        "associations": [{"route": None, "internal": "0", "status": "unresolved", "reasons": ["no_route_evidence"], "time": {"label_distance_ns": None, "minimum_distance_ns": None, "maximum_distance_ns": None, "uncertainty_used": False}}],
    }
    return value


class Versions(unittest.TestCase):
    def test_old_flow_security_remain_v1(self):
        for side in ("internal_flow", "internal_security"):
            jsonschema.validate(report(1, 1, side), SCHEMA)

    def test_route_projection_requires_v2(self):
        jsonschema.validate(report(2, 2, "route_evidence"), SCHEMA)
        typed = report(2, 2, "route_evidence")
        typed["internal_evidence"][0]["evidence"]["native_disposition"] = {"action": "announce", "current": False}
        jsonschema.validate(typed, SCHEMA)
        for disposition in ({"action": "reset", "current": False}, {"action": "announce", "current": "false"}):
            typed["internal_evidence"][0]["evidence"]["native_disposition"] = disposition
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(typed, SCHEMA)

    def test_mixed_versions_and_wrong_side_are_rejected(self):
        for version, input_version, side in ((1, 2, "route_evidence"), (2, 1, "route_evidence"), (2, 2, "internal_flow"), (2, 1, "internal_security")):
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(report(version, input_version, side), SCHEMA)
        bad = report(2, 2, "route_evidence")
        bad["source_authority_established"] = True
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(bad, SCHEMA)


if __name__ == "__main__":
    unittest.main()
