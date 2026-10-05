"""Finite availability/schema controls; native producer join is a separate gate."""
import copy
import hashlib
import json
import unittest

from tools.research import bgp_compare as bgp
from tools.research.contract import InvalidResearch
from tools.tests.test_bgp_compare import native_export, rebind_rows


def fixture(*, action="withdraw", projection=True):
    row, _, manifest = native_export()
    route = row["observation"]["routes"][0]
    route["action"] = action
    route["prefix"] = {"afi": 1, "safi": 1, "length": 24, "address": "192.0.2.0"}
    route["semantic_identity"] = {"schema": bgp.NATIVE_PROFILE, "completeness": "incomplete"}
    row["observation"]["message_detail"] = {"route_projection_incomplete": not projection}
    row["event"] = {"parse_status": "decoded_update_candidate", "issues": []}
    row["field_availability"] = {
        "schema": "pcap-evidence.bgp.route-field-availability.v1",
        "source_reference": {key: row.get(key) for key in ("sequence_ordinal", "source_sha256", "store_seal", "record_ordinal", "record_offset", "record_sha256", "entry_index")},
        "route_projection_complete": projection,
        "status": "complete" if projection else "incomplete",
        "routes": [{"route_index": "0", "action": action, "prefix": copy.deepcopy(route["prefix"]), "path_id": None}]}
    row["schema"] = "pcap-evidence.bgp.evidence-row.v2"
    rebind_rows(row, manifest)
    manifest["schema"] = "pcap-evidence.bgp.evidence-manifest.v2"
    manifest["comparison_fields"] = "per-field-v2"
    manifest["field_availability_schema"] = "pcap-evidence.bgp.route-field-availability.v1"
    return row, manifest


def seal(row, manifest):
    raw = json.dumps(row, separators=(",", ":")).encode() + b"\n"
    manifest["rows_bytes"] = str(len(raw))
    manifest["rows_sha256"] = hashlib.sha256(raw).hexdigest()
    keys = ("schema", "complete", "rows", "rows_bytes", "rows_sha256", "rows_digest_scope", "sequence", "semantic_profile", "replay_relationship", "window", "coverage", "source_authenticated", "endpoint_state_claimed", "resume_cursor_supported", "comparison_fields", "field_availability_schema")
    payload = {key: manifest[key] for key in keys}
    seq = manifest["sequence"]
    payload["sequence"] = {key: seq[key] for key in ("schema", "ordering", "independent_checkpoints", "entries", "sequence_digest")}
    manifest["semantic_identity"] = hashlib.sha256(b"pcap-evidence/bgp-evidence-manifest/v2\0" + json.dumps(payload, separators=(",", ":")).encode()).hexdigest()
    return raw


def convert(row, manifest):
    return bgp.from_native(seal(row, manifest), manifest, comparison_fields="per-field-v2")


class PerFieldComparisonTests(unittest.TestCase):
    def test_incomplete_semantics_preserve_known_withdrawal_and_prefix(self):
        for action in ("withdraw", "announce"):
            row, manifest = fixture(action=action)
            document = convert(row, manifest)
            results = {r["field"]: r for r in bgp.compare(document, document)["rows"] if r["group"] == "nlri"}
            for field in ("route_actions", "route_prefixes"):
                self.assertEqual(results[field]["result"], "agreement")
            for field in ("routes", "semantic_identity"):
                self.assertEqual(results[field]["result"], "not_comparable")
            attributes = document["observations"][0]["fields"]["attributes"]["route_attributes"]
            self.assertEqual(attributes["status"], "incomplete")
            self.assertEqual(document["observations"][0]["coverage"]["nlri"], "partial")

    def test_hidden_nlri_retains_collection_uncertainty(self):
        row, manifest = fixture(projection=False)
        document = convert(row, manifest)
        results = [r for r in bgp.compare(document, document)["rows"] if r["group"] == "nlri"]
        self.assertTrue(results)
        self.assertTrue(all(r["result"] == "not_comparable" for r in results))
        row["field_availability"]["status"] = "complete"
        with self.assertRaisesRegex(InvalidResearch, "complete fields"):
            convert(row, manifest)

    def test_exact_declaration_closure_after_resealed_carriers(self):
        mutations = (
            lambda r, m: r["field_availability"].update(extra=None),
            lambda r, m: r["field_availability"]["source_reference"].update(record_sha256="0" * 64),
            lambda r, m: r["field_availability"]["routes"][0].update(action="announce"),
            lambda r, m: r["field_availability"]["routes"][0]["prefix"].update(address="192.0.3.0"),
            lambda r, m: r["field_availability"]["routes"][0].update(path_id=True),
            lambda r, m: r["field_availability"]["routes"][0].update(route_index="1"),
            lambda r, m: r["field_availability"]["routes"].clear(),
            lambda r, m: r["field_availability"]["routes"][0]["prefix"].update(extra=None),
            lambda r, m: r["observation"]["message_detail"].update(route_projection_incomplete=True),
            lambda r, m: m.update(field_availability_schema="unknown"),
        )
        for mutation in mutations:
            row, manifest = fixture()
            mutation(row, manifest)
            with self.subTest(mutation=mutation):
                with self.assertRaises(InvalidResearch):
                    convert(row, manifest)

    def test_raw_path_ids_require_exact_integer_type(self):
        for raw_id, declared_id in ((True, 1), (False, 0), (-1, 0), (1 << 32, 0), ("1", 1)):
            row, manifest = fixture()
            row["observation"]["routes"][0]["path_id"] = raw_id
            row["field_availability"]["routes"][0]["path_id"] = declared_id
            with self.assertRaisesRegex(InvalidResearch, "raw observation path id"):
                convert(row, manifest)
        for valid_id in (0, 1):
            row, manifest = fixture()
            row["observation"]["routes"][0]["path_id"] = valid_id
            row["field_availability"]["routes"][0]["path_id"] = valid_id
            document = convert(row, manifest)
            self.assertEqual(document["observations"][0]["fields"]["nlri"]["route_prefixes"]["value"][0]["path_id"], valid_id)
            self.assertEqual(bgp.validate(document), document)
            self.assertEqual(next(r for r in bgp.compare(document, document)["rows"] if r["field"] == "route_prefixes")["result"], "agreement")
            bad = copy.deepcopy(document)
            bad["observations"][0]["evidence"]["observation"]["routes"][0]["path_id"] = bool(valid_id)
            for consumer in (lambda: bgp.validate(bad), lambda: bgp.compare(bad, document)):
                with self.assertRaisesRegex(InvalidResearch, "raw observation path id"):
                    consumer()

    def test_reloaded_manifest_sequence_and_interpretation_versions_close(self):
        row, manifest = fixture()
        document = convert(row, manifest)
        mutations = (
            lambda m: m["sequence"].update(schema="unknown"),
            lambda m: m["sequence"].update(ordering="unknown"),
            lambda m: m["sequence"].update(independent_checkpoints=False),
            lambda m: m["sequence"].update(sequence_digest="0" * 64),
            lambda m: m["sequence"]["entries"][0].update(entry_digest="0" * 64),
            lambda m: m["sequence"]["entries"][0].update(predecessor_digest="0" * 64),
        )
        for mutation in mutations:
            bad = copy.deepcopy(document)
            mutation(bad["native_evidence"])
            # Rebuild the outer commitment so the sequence owner must reject.
            seal(row, bad["native_evidence"])
            with self.assertRaisesRegex(InvalidResearch, "native sequence"):
                bgp.validate(bad)
        legacy_row, legacy_raw, legacy_manifest = native_export()
        legacy = bgp.from_native(legacy_raw, legacy_manifest)
        for mode_key, value in (("comparison_fields", "per-field-v2"),
                                ("field_availability_schema", "pcap-evidence.bgp.route-field-availability.v1")):
            bad_legacy = copy.deepcopy(legacy)
            bad_legacy["native_evidence"][mode_key] = value
            with self.assertRaisesRegex(InvalidResearch, "retained legacy native manifest"):
                bgp.validate(bad_legacy)
        legacy["native_evidence"] = document["native_evidence"]
        with self.assertRaisesRegex(InvalidResearch, "schema mismatch"):
            bgp.validate(legacy)
        bad = copy.deepcopy(document)
        bad["native_evidence"] = legacy_manifest
        with self.assertRaisesRegex(InvalidResearch, "schema mismatch"):
            bgp.validate(bad)

    def test_producer_version_names_consumed_native_row_schema(self):
        row, manifest = fixture()
        self.assertEqual(convert(row, manifest)["producer"]["version"], "evidence-row.v2")
        _, raw, legacy_manifest = native_export()
        self.assertEqual(bgp.from_native(raw, legacy_manifest)["producer"]["version"], "evidence-row.v1")

    def test_native_prefix_shape_rejects_host_bits_and_ipv6_zone_alias(self):
        for prefix in ({"afi": 1, "safi": 1, "length": 24, "address": "192.0.2.1"},
                       {"afi": 2, "safi": 1, "length": 64, "address": "fe80::%eth0"}):
            row, manifest = fixture()
            row["observation"]["routes"][0]["prefix"] = copy.deepcopy(prefix)
            row["field_availability"]["routes"][0]["prefix"] = copy.deepcopy(prefix)
            with self.assertRaises(InvalidResearch):
                convert(row, manifest)

    def test_raw_and_manifest_tampering_without_reseal_reject(self):
        row, manifest = fixture()
        raw = seal(row, manifest)
        with self.assertRaisesRegex(InvalidResearch, "digest mismatch"):
            bgp.from_native(raw.replace(b'"withdraw"', b'"announce"'), manifest, comparison_fields="per-field-v2")
        manifest["field_availability_schema"] = "unknown"
        with self.assertRaises(InvalidResearch):
            bgp.from_native(raw, manifest, comparison_fields="per-field-v2")

    def test_schema_mode_cross_product_preserves_legacy(self):
        row, manifest = fixture()
        raw = seal(row, manifest)
        with self.assertRaises(InvalidResearch):
            bgp.from_native(raw, manifest)
        legacy_row, legacy_raw, legacy_manifest = native_export()
        with self.assertRaises(InvalidResearch):
            bgp.from_native(legacy_raw, legacy_manifest, comparison_fields="per-field-v2")
        legacy = bgp.from_native(legacy_raw, legacy_manifest)
        current = convert(row, manifest)
        with self.assertRaises(InvalidResearch):
            bgp.compare(current, legacy)
        self.assertNotIn("field_coverage", legacy["observations"][0])
        self.assertEqual(legacy["schema"], "pcap-evidence.bgp.interpretation.v1")
        row["schema"] = "pcap-evidence.bgp.evidence-row.v1"
        with self.assertRaises(InvalidResearch):
            convert(row, manifest)

    def test_reloaded_native_projection_must_match_declaration(self):
        row, manifest = fixture()
        document = convert(row, manifest)
        for mutation in (
            lambda d: d["observations"][0]["fields"]["nlri"]["route_actions"]["value"][0].update(action="announce"),
            lambda d: d["observations"][0]["field_coverage"]["nlri"].update(route_actions="partial"),
            lambda d: d["observations"][0]["evidence"]["field_availability"].update(extra=None),
            lambda d: d["native_evidence"].update(field_availability_schema="unknown"),
        ):
            bad = copy.deepcopy(document)
            mutation(bad)
            with self.assertRaises(InvalidResearch):
                bgp.compare(bad, document)

    def test_complete_group_cannot_override_partial_field_coverage(self):
        row, manifest = fixture()
        document = convert(row, manifest)
        document.pop("native_evidence")
        document.pop("native_coverage_verification")
        document["producer"]["origin"] = "independent_fixture"
        document["observations"][0].pop("evidence")
        document["observations"][0]["coverage"]["nlri"] = "complete"
        document["observations"][0]["field_coverage"]["nlri"]["route_actions"] = "partial"
        result = next(r for r in bgp.compare(document, document)["rows"] if r["field"] == "route_actions")
        self.assertEqual(result["result"], "not_comparable")
        self.assertEqual(result["reason"], "per_field_coverage_gap")

    def test_explicit_independent_external_availability_disagrees(self):
        row, manifest = fixture()
        native = convert(row, manifest)
        external = copy.deepcopy(native)
        external.pop("native_evidence")
        external.pop("native_coverage_verification")
        external["producer"]["origin"] = "independent_fixture"
        external["producer"]["id"] = "independent-fields"
        external["observations"][0].pop("evidence")
        external["observations"][0]["fields"]["nlri"]["route_actions"]["value"][0]["action"] = "announce"
        result = next(r for r in bgp.compare(native, external)["rows"] if r["field"] == "route_actions")
        self.assertEqual(result["result"], "disagreement")
        self.assertEqual(result["reason"], "normalized_value_differs")


if __name__ == "__main__":
    unittest.main()
