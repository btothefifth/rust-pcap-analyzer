"""Finite synthetic proofs for the offline BGP comparison boundary.

The external fixture is authored independently of native conversion. Inverse
cases alter one declared contract fact and reach its owning consumer. These
tests qualify no real corpus, endpoint behavior, or normative parser semantics.
"""
import contextlib
import copy
import hashlib
import io
import json
import struct
from pathlib import Path
import tempfile
import unittest

from tools.research import bgp_compare as bgp
from tools.research.contract import InvalidResearch, canonical, decode_json


def independent_external():
    return {
        "schema": "pcap-evidence.bgp.interpretation.v1",
        "source": {"sha256": hashlib.sha256(b"abcdefghijklmnop").hexdigest(), "bytes": "16"},
        "normalization": {"profile": "bgp-source-fields-v1", "config_sha256": "c" * 64},
        "producer": {"id": "independent-fixture", "version": "1", "adapter_version": "1",
                     "origin": "independent_fixture", "command": []},
        "observations": [{
            "record_offset": "2", "entry_index": "0",
            "source_range": {"kind": "source_range", "start": "2", "end": "10"},
            "disposition": "accepted",
            "coverage": {"disposition": "complete", "message": "complete", "attributes": "complete"},
            "fields": {
                "message": {"message_type": {"status": "observed", "value": 2}},
                "attributes": {"raw": {"status": "observed", "value": [
                    {"type": 8, "bytes": "00000001", "discarded": False},
                    {"type": 8, "bytes": "00000002", "discarded": True},
                    {"type": 8, "bytes": "00000001", "discarded": True}]}}}}]}


def native_export():
    # Native-shaped carrier fixture, separate from independent_external().
    source_hash = hashlib.sha256(b"abcdefghijklmnop").hexdigest()
    row = {"schema": "pcap-evidence.bgp.evidence-row.v1", "provisional": True,
           "sequence_ordinal": "0", "source_id": "fixture-source", "checkpoint_id": "fixture-checkpoint",
           "source_sha256": source_hash, "full_source_bytes": "16", "store_seal": "a" * 64,
           "record_ordinal": "0", "record_offset": "0", "record_bytes": "16", "record_type": 13, "subtype": 2, "record_sha256": source_hash,
           "entry_index": "0", "mrt_record_time": {"seconds": "1", "microseconds": None, "validity": "seconds", "precision": "seconds", "time_ns": "1000000000"},
           "rib_originated_time_ns": None, "observation_time_ns": None,
           "event": {"event_kind": "rib_entry", "parse_status": None, "issues": []},
           "observation": {"message_type": 2, "message_detail": None, "issues": [], "routes": [
               {"action": "announce", "prefix": {"afi": 1, "safi": 1, "length": 24, "bytes": "c00002"},
                "attributes": {"origin": 0}, "imported_attribute_occurrences": [
                    {"type": 8, "value_hex": "00000001", "discarded": False},
                    {"type": 8, "value_hex": "00000002", "discarded": True}]}]},
           "window_disposition": None, "asn_disposition": None,
           "selected": True, "certain_occurrence_time_claimed": False}
    entry = {"ordinal": "0", "source_id": "fixture-source", "checkpoint_id": "fixture-checkpoint",
             "source_sha256": source_hash, "source_bytes": "16", "record_count": "1", "final_chain": "b" * 64,
             "store_seal": "a" * 64, "predecessor_digest": "0" * 64, "entry_digest": "d" * 64}
    raw = json.dumps(row, separators=(",", ":")).encode() + b"\n"
    manifest = {"schema": "pcap-evidence.bgp.evidence-manifest.v1", "complete": True,
                "rows": "1", "rows_bytes": str(len(raw)), "rows_sha256": hashlib.sha256(raw).hexdigest(),
                "rows_digest_scope": "exact_ndjson_rows_including_newlines_excluding_manifest",
                "sequence": {"schema": "pcap-evidence.bgp.source-sequence.v1", "entries": [entry],
                             "sequence_digest": "e" * 64, "ordering": "caller_file_order", "independent_checkpoints": True},
                "semantic_profile": "pcap-evidence.bgp.semantic-route-identity.v2", "replay_relationship": "unknown", "window": None,
                "coverage": {"records": "1", "rows": "1", "observations": "1", "route_free": "0", "opaque": "0",
                             "rejected": "0", "unsupported": "0", "unknown_time": "0", "unknown_mrt_record_time": "0", "unknown_asn": "0", "selected": "1",
                             "timestamp_regressions": "0", "witnesses": [], "witnesses_truncated": "0",
                             "count_unit": "rows_except_records_unknown_mrt_record_time_and_timestamp_regressions"},
                "semantic_identity": "f" * 64, "endpoint_state_claimed": False,
                "source_authenticated": False, "resume_cursor_supported": False}
    seal_fixture_manifest(manifest)
    return row, raw, manifest


def seal_fixture_manifest(manifest):
    """Independent fixture DTO serialization in the native declared wire order."""
    def wire(value):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    def seal(domain, value):
        return hashlib.sha256(domain.encode() + b"\0" + value).hexdigest()
    prior = seal("pcap-evidence/bgp-source-sequence/v1", b"genesis")
    entry_keys = ("ordinal", "source_id", "checkpoint_id", "source_sha256", "source_bytes", "record_count",
                  "final_chain", "store_seal", "predecessor_digest")
    entries = []
    for entry in manifest["sequence"]["entries"]:
        entry["predecessor_digest"] = prior
        payload = {key: entry[key] for key in entry_keys}
        prior = seal("pcap-evidence/bgp-source-sequence/v1", wire(payload))
        entry["entry_digest"] = prior
        entries.append({**payload, "entry_digest": prior})
    manifest["sequence"]["sequence_digest"] = prior
    sequence = {"schema": manifest["sequence"]["schema"], "ordering": "caller_file_order", "independent_checkpoints": True,
                "entries": entries, "sequence_digest": prior}
    root_keys = ("schema", "complete", "rows", "rows_bytes", "rows_sha256", "rows_digest_scope", "sequence", "semantic_profile",
                 "replay_relationship", "window", "coverage", "source_authenticated", "endpoint_state_claimed", "resume_cursor_supported")
    coverage_keys = ("records", "rows", "observations", "route_free", "opaque", "rejected", "unsupported", "unknown_time", "unknown_mrt_record_time",
                     "unknown_asn", "selected", "timestamp_regressions", "witnesses", "witnesses_truncated", "count_unit")
    payload = {key: manifest[key] for key in root_keys}
    payload["sequence"] = sequence
    payload["coverage"] = {key: manifest["coverage"][key] for key in coverage_keys}
    manifest["semantic_identity"] = seal("pcap-evidence/bgp-evidence-manifest/v1", wire(payload))


def rebind_rows(row, manifest):
    raw = json.dumps(row, separators=(",", ":")).encode() + b"\n"
    manifest.update(rows="1", rows_bytes=str(len(raw)), rows_sha256=hashlib.sha256(raw).hexdigest())
    seal_fixture_manifest(manifest)
    return raw


def extended_timestamp_export(microseconds):
    """Real MRT header/ET bytes for missing, invalid, or precise labels."""
    row, _, manifest = native_export()
    body = b"" if microseconds is None else struct.pack("!I", microseconds)
    source = struct.pack("!IHHI", 1, 17, 1, len(body)) + body
    source_hash = hashlib.sha256(source).hexdigest()
    known = microseconds is not None and microseconds < 1_000_000
    validity = "microseconds" if known else "missing_microseconds" if microseconds is None else "invalid_microseconds"
    row.update(source_sha256=source_hash, full_source_bytes=str(len(source)), record_type=17, subtype=1,
               record_bytes=str(len(source)), record_sha256=source_hash, entry_index=None, observation=None,
               event={"event_kind": "malformed_record", "parse_status": "rejected", "issues": []})
    row["mrt_record_time"] = {"seconds": "1", "microseconds": None if microseconds is None else str(microseconds),
                              "validity": validity, "precision": "microseconds" if known else "unknown",
                              "time_ns": str(1_000_000_000 + microseconds * 1000) if known else None}
    manifest["sequence"]["entries"][0].update(source_sha256=source_hash, source_bytes=str(len(source)))
    manifest["coverage"].update(observations="0", route_free="1", rejected="1", unknown_mrt_record_time="0" if known else "1")
    return row, rebind_rows(row, manifest), manifest


class BgpComparisonTests(unittest.TestCase):
    def test_independent_fixture_agreement_is_inert(self):
        left, right = independent_external(), independent_external()
        right["producer"]["id"] = "second-fixture"
        result = bgp.compare(left, right)
        self.assertEqual(result["counts"], {"agreement": 3, "disagreement": 0, "not_comparable": 0})
        self.assertFalse(result["consensus_used"])
        self.assertFalse(result["state_admission"])
        self.assertFalse(result["semantic_correctness_proven"])
        self.assertEqual(result["producer_authentication"], "not_established")

    def test_wrong_source_digest_and_length_rejected(self):
        for key, value in (("sha256", "0" * 64), ("bytes", "17")):
            left, right = independent_external(), independent_external()
            right["source"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(InvalidResearch, "source identity mismatch"):
                bgp.compare(left, right)

    def test_wrong_profile_and_semantic_config_rejected(self):
        for key, value in (("profile", "other-profile"), ("config_sha256", "d" * 64)):
            left, right = independent_external(), independent_external()
            right["normalization"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                bgp.compare(left, right)

    def test_duplicates_and_discard_disposition_preserved(self):
        left, right = independent_external(), independent_external()
        value = right["observations"][0]["fields"]["attributes"]["raw"]["value"]
        value[1], value[2] = value[2], value[1]
        result = bgp.compare(left, right)
        self.assertEqual(result["counts"]["disagreement"], 1)
        self.assertEqual(len(result["rows"][2]["left"]["value"]), 3)
        right = independent_external()
        right["observations"][0]["fields"]["attributes"]["raw"]["value"][1]["discarded"] = False
        self.assertEqual(bgp.compare(left, right)["counts"]["disagreement"], 1)

    def test_offset_order_numeric_and_entry_zero_distinct(self):
        left, right = independent_external(), independent_external()
        for doc in (left, right):
            late = copy.deepcopy(doc["observations"][0])
            late.update(record_offset="10", source_range={"kind": "source_range", "start": "10", "end": "16"})
            earlier = copy.deepcopy(doc["observations"][0])
            earlier.pop("entry_index")
            doc["observations"] = [late, doc["observations"][0], earlier]
        for row in right["observations"]:
            row["disposition"] = "rejected"
        result = bgp.compare(left, right)
        divergent = [r for r in result["rows"] if r["result"] == "disagreement"]
        self.assertEqual([r["record_offset"] for r in divergent], ["2", "2", "10"])
        self.assertNotIn("entry_index", divergent[0])
        self.assertEqual(divergent[1]["entry_index"], "0")
        self.assertEqual(result["first_observed_disagreement"], 0)

    def test_missing_coverage_never_awards_agreement(self):
        left, right = independent_external(), independent_external()
        right["observations"][0]["coverage"].pop("attributes")
        result = bgp.compare(left, right)
        self.assertEqual(result["rows"][2]["result"], "not_comparable")
        self.assertIsNone(result["first_observed_disagreement"])

    def test_partial_group_and_unknown_field_do_not_vote(self):
        for group_coverage, field_status in (("partial", "observed"), ("complete", "unknown"),
                                              ("complete", "incomplete"), ("unsupported", "observed")):
            left, right = independent_external(), independent_external()
            row = right["observations"][0]
            row["coverage"]["message"] = group_coverage
            row["fields"]["message"]["message_type"]["status"] = field_status
            with self.subTest(coverage=group_coverage, status=field_status):
                result = bgp.compare(left, right)
                self.assertEqual(result["rows"][1]["result"], "not_comparable")

    def test_unknown_groups_and_missing_fields_remain_visible(self):
        left, right = independent_external(), independent_external()
        for doc in (left, right):
            row = doc["observations"][0]
            row["coverage"]["future_group"] = "complete"
            row["fields"]["future_group"] = {"x": {"status": "observed", "value": [1, 1, 2]}}
        right["observations"][0]["fields"]["message"].clear()
        result = bgp.compare(left, right)
        self.assertEqual(result["counts"]["not_comparable"], 2)
        self.assertEqual(result["rows"][-1]["reason"], "unknown_field_group")
        self.assertEqual(result["rows"][-1]["left"]["value"], [1, 1, 2])

    def test_accepted_vs_rejected_differs_with_common_coverage(self):
        left, right = independent_external(), independent_external()
        right["observations"][0]["disposition"] = "rejected"
        self.assertEqual(bgp.compare(left, right)["rows"][0]["reason"], "acceptance_differs")
        right["observations"][0]["coverage"].pop("disposition")
        self.assertEqual(bgp.compare(left, right)["rows"][0]["result"], "not_comparable")

    def test_missing_observation_is_unknown(self):
        left, right = independent_external(), independent_external()
        right["observations"] = []
        self.assertEqual(bgp.compare(left, right)["counts"], {"agreement": 0, "disagreement": 0, "not_comparable": 1})

    def test_integer_anchor_normalization_is_exact_and_nonmutating(self):
        left, right = independent_external(), independent_external()
        row = right["observations"][0]
        right["source"]["bytes"] = 16
        row.update(record_offset=2, entry_index=0)
        row["source_range"].update(start=2, end=10)
        original = copy.deepcopy(right)
        self.assertEqual(bgp.compare(left, right)["counts"]["agreement"], 3)
        self.assertEqual(right, original)
        row["fields"]["message"]["message_type"]["value"] = "2"
        self.assertEqual(bgp.compare(left, right)["counts"]["disagreement"], 1)

    def test_ambiguous_numeric_anchors_rejected(self):
        for value in (True, 2.0, "02", "+2", "2.0", -1, str(1 << 64)):
            doc = independent_external()
            doc["observations"][0]["record_offset"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                bgp.validate(doc)

    def test_duplicate_anchor_rejected_after_normalization(self):
        doc = independent_external()
        extra = copy.deepcopy(doc["observations"][0])
        extra["record_offset"] = 2
        doc["observations"].append(extra)
        with self.assertRaisesRegex(InvalidResearch, "duplicate BGP source anchor"):
            bgp.validate(doc)

    def test_strict_input_keys_and_hashes(self):
        for target in ("root", "source", "producer", "row", "range", "field"):
            doc = independent_external()
            row = doc["observations"][0]
            objects = {"root": doc, "source": doc["source"], "producer": doc["producer"], "row": row,
                       "range": row["source_range"], "field": row["fields"]["message"]["message_type"]}
            objects[target]["unexpected"] = True
            with self.subTest(target=target), self.assertRaisesRegex(InvalidResearch, "keys"):
                bgp.validate(doc)
        doc = independent_external()
        doc["source"]["sha256"] = "A" * 64
        with self.assertRaises(ValueError):
            bgp.validate(doc)

    def test_source_ranges_are_tagged_bounded_nonempty_record_ranges(self):
        for change in ({"kind": "packet_range"}, {"end": "17"}, {"start": "1"}, {"end": "2"}):
            doc = independent_external()
            doc["observations"][0]["source_range"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                bgp.validate(doc)

    def test_invalid_coverage_types_rejected(self):
        for value in ([], {}, None, 1):
            doc = independent_external()
            doc["observations"][0]["coverage"]["message"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                bgp.validate(doc)

    def test_bounded_rows_and_exact_output_limit(self):
        doc = independent_external()
        with self.assertRaisesRegex(InvalidResearch, "budget"):
            bgp.compare(doc, doc, maximum=1)
        result = bgp.compare(doc, doc)
        exact = len(canonical(result))
        self.assertEqual(bgp.compare(doc, doc, output_limit=exact), result)
        with self.assertRaisesRegex(InvalidResearch, "budget"):
            bgp.compare(doc, doc, output_limit=exact - 1)

    def test_document_duplicate_keys_depth_nonfinite_and_byte_limits(self):
        for raw in (b'{"schema":1,"schema":2}', b'[' * 25 + b'0' + b']' * 25, b'{"x":NaN}'):
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                decode_json(raw)
        with self.assertRaisesRegex(InvalidResearch, "byte budget"):
            bgp.from_native(b"x" * (bgp.MAX_DOCUMENT + 1))

    def test_commands_are_inert_through_cli_consumer(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            marker = root / "marker"
            doc = independent_external()
            doc["producer"]["command"] = ["sh", "-c", "touch " + str(marker)]
            path = root / "external.json"
            path.write_bytes(canonical(doc))
            before = set(root.iterdir())
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(bgp.main(["compare", str(path), str(path)]), 0)
            self.assertFalse(json.loads(stdout.getvalue())["state_admission"])
            self.assertEqual(set(root.iterdir()), before)
            self.assertFalse(marker.exists())


class NativeConversionTests(unittest.TestCase):
    def test_invalid_extended_time_suppresses_derived_clock_for_valid_bgp_bytes(self):
        for microseconds in (1_000_000, 999_999):
            row, _, manifest = extended_timestamp_export(microseconds)
            # A valid KEEPALIVE and AS4 BGP4MP outer payload: the timestamp
            # interpretation must not depend on malformed BGP message bytes.
            keepalive = b"\xff" * 16 + struct.pack("!HB", 19, 4)
            outer = struct.pack("!IIHH4s4s", 64512, 64513, 0, 1, b"\xc0\x00\x02\x01", b"\xc0\x00\x02\x02")
            body = struct.pack("!I", microseconds) + outer + keepalive
            source = struct.pack("!IHHI", 1, 17, 4, len(body)) + body
            source_hash = hashlib.sha256(source).hexdigest()
            clock = None if microseconds >= 1_000_000 else str(1_000_000_000 + microseconds * 1000)
            row.update(source_sha256=source_hash, full_source_bytes=str(len(source)), subtype=4,
                       record_bytes=str(len(source)), record_sha256=source_hash,
                       observation_time_ns=clock,
                       event={"event_kind": "message", "parse_status": "decoded_keepalive", "issues": []},
                       observation={"message_type": 4, "message_detail": None, "routes": [], "issues": [], "observed_at_ns": clock})
            manifest["sequence"]["entries"][0].update(source_sha256=source_hash, source_bytes=str(len(source)))
            manifest["coverage"].update(observations="1", rejected="0")
            raw = rebind_rows(row, manifest)
            doc = bgp.from_native(raw, manifest)
            with self.subTest(microseconds=microseconds):
                self.assertEqual(doc["observations"][0]["evidence"]["observation"]["observed_at_ns"], clock)
                self.assertEqual(doc["observations"][0]["fields"]["framing"]["mrt_record_time"]["status"],
                                 "unknown" if clock is None else "observed")
                if clock is None:
                    # Old exporter promotion is rejected despite a valid seal.
                    row["observation_time_ns"] = "2000000000"
                    raw = rebind_rows(row, manifest)
                    with self.assertRaisesRegex(InvalidResearch, "cannot establish an observation time"):
                        bgp.from_native(raw, manifest)
                    row["observation_time_ns"] = None
                    # The original normalized carrier remains inert metadata;
                    # no equality join to a quarantined clock is required.
                    row["observation"]["observed_at_ns"] = "2000000000"
                    raw = rebind_rows(row, manifest)
                    self.assertEqual(bgp.from_native(raw, manifest)["observations"][0]["evidence"]["observation"]["observed_at_ns"], "2000000000")

    def test_extended_timestamp_missing_and_invalid_retained_as_unknown(self):
        for microseconds, validity in ((None, "missing_microseconds"), (1_000_000, "invalid_microseconds"),
                                       ((1 << 32) - 1, "invalid_microseconds")):
            row, raw, manifest = extended_timestamp_export(microseconds)
            doc = bgp.from_native(raw, manifest)
            time = doc["observations"][0]["fields"]["framing"]["mrt_record_time"]
            with self.subTest(microseconds=microseconds):
                self.assertEqual(time["status"], "unknown")
                self.assertEqual(time["value"]["validity"], validity)
                self.assertEqual(time["value"]["precision"], "unknown")
                self.assertIsNone(time["value"]["time_ns"])
                self.assertEqual(time["value"]["microseconds"], row["mrt_record_time"]["microseconds"])
                comparison = bgp.compare(doc, doc)
                result = next(r for r in comparison["rows"] if r["field"] == "mrt_record_time")
                self.assertEqual(result["result"], "not_comparable")
                self.assertEqual(doc["native_evidence"]["coverage"]["unknown_mrt_record_time"], "1")

    def test_extended_timestamp_precision_zero_and_upper_valid_boundary(self):
        for microseconds in (0, 999_999):
            _, raw, manifest = extended_timestamp_export(microseconds)
            doc = bgp.from_native(raw, manifest)
            time = doc["observations"][0]["fields"]["framing"]["mrt_record_time"]
            with self.subTest(microseconds=microseconds):
                self.assertEqual(time["status"], "observed")
                self.assertEqual(time["value"]["precision"], "microseconds")
                self.assertEqual(time["value"]["time_ns"], str(1_000_000_000 + microseconds * 1000))

    def test_extended_unknown_timestamp_cannot_be_promoted_to_seconds(self):
        for microseconds in (None, 1_000_000):
            row, _, manifest = extended_timestamp_export(microseconds)
            row["mrt_record_time"].update(validity="seconds", precision="seconds", time_ns="1000000000")
            raw = rebind_rows(row, manifest)
            with self.subTest(microseconds=microseconds), self.assertRaisesRegex(InvalidResearch, "time representation mismatch"):
                bgp.from_native(raw, manifest)

    def test_ordinary_mrt_time_keeps_seconds_precision(self):
        row, _, manifest = native_export()
        row["mrt_record_time"]["microseconds"] = "1000000"
        raw = rebind_rows(row, manifest)
        doc = bgp.from_native(raw, manifest)
        time = doc["observations"][0]["fields"]["framing"]["mrt_record_time"]
        self.assertEqual(time["status"], "observed")
        self.assertEqual(time["value"]["precision"], "seconds")
        self.assertEqual(time["value"]["time_ns"], "1000000000")

    def test_native_record_type_exact_u16(self):
        for field, value in (("record_type", "17"), ("record_type", True), ("subtype", 1 << 16)):
            row, _, manifest = native_export()
            row[field] = value
            raw = rebind_rows(row, manifest)
            with self.subTest(field=field, value=value), self.assertRaisesRegex(InvalidResearch, "u16 JSON integers"):
                bgp.from_native(raw, manifest)

    def test_extended_unknown_timestamp_coverage_cannot_claim_zero(self):
        _, raw, manifest = extended_timestamp_export(None)
        manifest["coverage"]["unknown_mrt_record_time"] = "0"
        seal_fixture_manifest(manifest)
        with self.assertRaisesRegex(InvalidResearch, "coverage contradicts"):
            bgp.from_native(raw, manifest)

    def test_native_identity_and_sequence_chain_adversaries(self):
        for target in ("manifest", "entry", "predecessor", "terminal", "profile"):
            _, raw, manifest = native_export()
            if target == "manifest":
                manifest["semantic_identity"] = "f" * 64
            elif target == "profile":
                manifest["semantic_profile"] = "old-profile"
            elif target == "terminal":
                manifest["sequence"]["sequence_digest"] = "f" * 64
            elif target == "predecessor":
                manifest["sequence"]["entries"][0]["predecessor_digest"] = "f" * 64
            else:
                manifest["sequence"]["entries"][0]["entry_digest"] = "f" * 64
            with self.subTest(target=target), self.assertRaisesRegex(InvalidResearch, "identity|digest|predecessor|profile"):
                bgp.from_native(raw, manifest)

    def test_rehashed_invalid_native_time_and_record_ranges(self):
        for target in ("time", "offset", "record_bytes"):
            row, _, manifest = native_export()
            if target == "time":
                row["mrt_record_time"]["time_ns"] = "1000000001"
            elif target == "offset":
                row.update(record_offset="1", record_bytes="15")
            else:
                row["record_bytes"] = "12"
            raw = rebind_rows(row, manifest)
            with self.subTest(target=target), self.assertRaisesRegex(InvalidResearch, "representation|gap|full source"):
                bgp.from_native(raw, manifest)

    def test_native_rows_preserve_record_provenance_and_raw_occurrences(self):
        _, raw, manifest = native_export()
        doc = bgp.from_native(raw, manifest)
        row = doc["observations"][0]
        self.assertEqual(row["source_range"], {"kind": "source_range", "start": "0", "end": "16"})
        self.assertEqual(row["disposition"], "accepted")
        self.assertEqual(len(row["fields"]["attributes"]["route_attributes"]["value"][0]["imported_attribute_occurrences"]), 2)
        self.assertEqual(row["evidence"]["event"], json.loads(raw)["event"])
        self.assertEqual(doc["native_evidence"], manifest)
        self.assertNotIn("frames", row["evidence"])

    def test_embedded_manifest_and_sidecar_consistency(self):
        _, raw, manifest = native_export()
        stream = raw + canonical(manifest) + b"\n"
        self.assertEqual(bgp.from_native(stream), bgp.from_native(raw, manifest))
        wrong = copy.deepcopy(manifest)
        wrong["rows_bytes"] = "1"
        with self.assertRaisesRegex(InvalidResearch, "sidecar/terminal"):
            bgp.from_native(stream, wrong)
        with self.assertRaisesRegex(InvalidResearch, "after terminal"):
            bgp.from_native(stream + raw)

    def test_native_digest_count_and_truncation_rejected(self):
        for field, value in (("rows_sha256", "0" * 64), ("rows", "0"), ("rows_bytes", "0"), ("complete", False)):
            _, raw, manifest = native_export()
            manifest[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bgp.from_native(raw, manifest)
        _, raw, manifest = native_export()
        with self.assertRaisesRegex(InvalidResearch, "newline"):
            bgp.from_native(raw[:-1], manifest)

    def test_rehashed_wrong_source_seal_and_range_rejected(self):
        for field, value in (("source_sha256", "0" * 64), ("full_source_bytes", "17"),
                             ("store_seal", "b" * 64), ("record_bytes", "17"), ("record_ordinal", "1")):
            row, _, manifest = native_export()
            row[field] = value
            raw = rebind_rows(row, manifest)
            with self.subTest(field=field), self.assertRaises(ValueError):
                bgp.from_native(raw, manifest)

    def test_unknown_container_status_does_not_admit_or_agree_disposition(self):
        row, _, manifest = native_export()
        row["event"]["parse_status"] = "quarantined_coverage_unknown"
        raw = rebind_rows(row, manifest)
        doc = bgp.from_native(raw, manifest)
        self.assertEqual(doc["observations"][0]["disposition"], "unknown")
        self.assertEqual(bgp.compare(doc, doc)["rows"][0]["result"], "not_comparable")

    def test_multiple_sources_require_selection(self):
        row, raw, manifest = native_export()
        extra = copy.deepcopy(manifest["sequence"]["entries"][0])
        extra.update(ordinal="1", source_id="second-fixture", checkpoint_id="second-checkpoint", source_sha256="1" * 64)
        manifest["sequence"]["entries"].append(extra)
        second = copy.deepcopy(row)
        second.update(sequence_ordinal="1", source_id="second-fixture", checkpoint_id="second-checkpoint", source_sha256="1" * 64)
        raw += json.dumps(second, separators=(",", ":")).encode() + b"\n"
        manifest.update(rows="2", rows_bytes=str(len(raw)), rows_sha256=hashlib.sha256(raw).hexdigest())
        manifest["coverage"].update(records="2", rows="2", observations="2", selected="2")
        seal_fixture_manifest(manifest)
        with self.assertRaisesRegex(InvalidResearch, "explicit source ordinal"):
            bgp.from_native(raw, manifest)
        self.assertEqual(len(bgp.from_native(raw, manifest, source_ordinal=0)["observations"]), 1)
        self.assertEqual(bgp.from_native(raw, manifest, source_ordinal=1)["source"]["sha256"], "1" * 64)
        with self.assertRaisesRegex(InvalidResearch, "ordinal absent"):
            bgp.from_native(raw, manifest, source_ordinal=2)

    def test_native_cli_joins_real_file_reader(self):
        _, raw, manifest = native_export()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "export.ndjson"
            path.write_bytes(raw + canonical(manifest) + b"\n")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(bgp.main(["native", str(path)]), 0)
            self.assertEqual(json.loads(stdout.getvalue())["source"]["bytes"], "16")


if __name__ == "__main__":
    unittest.main()
