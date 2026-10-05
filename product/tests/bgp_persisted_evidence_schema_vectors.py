"""Named v3 structural migration; no runtime source or semantic proof."""
import copy
import json
from pathlib import Path
import unittest
import jsonschema
import bgp_persisted_schema_vectors as legacy

SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "docs/product/bgp-association-evidence.schema.json").read_text())

def full_report():
    value = legacy.report(2, 2, "route_evidence")
    value["schema"] = "pcap-evidence.bgp.association.v3"
    value["associations"][0]["semantic_relation"] = "unavailable"
    value["selection_notes"] = [{"reason": "metadata_only", "source_event_kind": "gap", "witness": {"note_plane": "source_container_event", "source_record_index": 1}}]
    return value

class EvidenceVersions(unittest.TestCase):
    def test_v3_and_route_free_shape_are_admitted(self):
        value = full_report()
        jsonschema.validate(value, SCHEMA)
        value["internal_evidence"] = []
        value["associations"][0]["internal"] = None
        jsonschema.validate(value, SCHEMA)

    def test_new_members_under_legacy_and_legacy_under_new_are_denied(self):
        value = full_report()
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(value, legacy.SCHEMA)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(legacy.report(2, 2, "route_evidence"), SCHEMA)
        for key in ("semantic_relation",):
            changed = copy.deepcopy(value)
            del changed["associations"][0][key]
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(changed, SCHEMA)
        for relation in ("incomparable", None, True):
            changed = copy.deepcopy(value)
            changed["associations"][0]["semantic_relation"] = relation
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(changed, SCHEMA)
        changed = copy.deepcopy(value)
        changed["selection_notes"][0]["source_event_kind"] = "withdraw"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(changed, SCHEMA)

OCCURRENCE_SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "docs/product/bgp-route-occurrence-reference.schema.json").read_text())

def occurrence(version):
    value = {
        "schema": f"pcap-evidence.bgp.route-occurrence-reference.v{version}",
        "record_id": "source-label", "source_occurrence_id": "journal:exact-ordinal",
        "normalized_observation_sha256": "ab" * 32, "route_index": 0,
        "route_key": {"source_id": "capture", "partition_id": "capture:life:1", "source_kind": "captured", "session": "1", "generation": 0, "direction": 0, "peer": None, "afi": 1, "safi": 1, "prefix": "203.0.113.0/24", "path_id": None},
        "original_namespace": "capture", "captured_lifecycle": 1, "source_record_index": 3,
        "source_start": 100, "source_end": 200, "journal_record_sha256": "cd" * 32,
        "checkpoint_id": None, "clock": {"policy": "source_label", "clock_id": "capture:source", "reported_uncertainty_ns": None},
        "observed_at_ns": "-1", "semantic_identity": None,
        "provenance": {"coordinate_system": "captured_packet", "import_context": None, "captured_evidence": {}},
        "normalized_observation": {},
    }
    if version == 2:
        value["native_origin"] = {"event_index": 2, "version_index": 0, "route_index": 0, "observation_sha256": "ab" * 32}
    return value

class OccurrenceVersions(unittest.TestCase):
    def test_explicit_versions_admit_exact_shapes(self):
        for version in (1, 2):
            jsonschema.validate(occurrence(version), OCCURRENCE_SCHEMA)

    def test_origin_requires_v2_and_v2_requires_complete_origin(self):
        value = occurrence(2)
        for change in ("v1", "missing", "extra", "bool", "uppercase"):
            bad = copy.deepcopy(value)
            if change == "v1": bad["schema"] = "pcap-evidence.bgp.route-occurrence-reference.v1"
            if change == "missing": del bad["native_origin"]
            if change == "extra": bad["native_origin"]["current"] = True
            if change == "bool": bad["native_origin"]["event_index"] = True
            if change == "uppercase": bad["native_origin"]["observation_sha256"] = "AB" * 32
            with self.assertRaises(jsonschema.ValidationError): jsonschema.validate(bad, OCCURRENCE_SCHEMA)
        for version in (1, 2):
            bad = occurrence(version)
            bad["unrecognized"] = None
            with self.assertRaises(jsonschema.ValidationError): jsonschema.validate(bad, OCCURRENCE_SCHEMA)
