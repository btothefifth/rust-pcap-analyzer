"""Tiny offline joins for BGP bundles; byte checks never qualify semantics.

The byte oracle is literal synthetic source data. Existing independently
authored native-shaped carrier fixtures exercise retained provenance; they
do not represent parsed MRT records or collector authentication.
"""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts.product_fixtures import pcap, packet
from tools.research import adapters, bgp_compare as bgp, bundle
from tools.research.contract import InvalidResearch, canonical
from tools.tests.test_bgp_compare import independent_external, native_export
from tools.tests.test_bgp_compare_fields import fixture, seal

ROOT = Path(__file__).resolve().parents[2]
RAW = b"abcdefghijklmnop"


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


class BgpBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source.mrt"
        self.source.write_bytes(RAW)
        self.left = independent_external()
        self.right = copy.deepcopy(self.left)
        self.right["observations"][0]["fields"]["message"]["message_type"]["value"] = 4

    def tearDown(self):
        self.temp.cleanup()

    def create(self, name="case.zip", left=None, right=None, **options):
        path = self.root / name
        bundle.create(path, self.source, self.left if left is None else left,
                      self.right if right is None else right, specifications=[], **options)
        return path

    def members(self, path):
        with zipfile.ZipFile(path) as archive:
            return {name: archive.read(name) for name in archive.namelist()}

    def rebuild(self, members, name="rebuilt.zip"):
        # Rebuild every outer inventory commitment, so semantic consumers must
        # reject rather than an obsolete archive hash doing the work.
        manifest = json.loads(members["manifest.json"])
        manifest["files"] = {key: identity(raw) for key, raw in sorted(members.items())
                             if key != "manifest.json"}
        members["manifest.json"] = canonical(manifest) + b"\n"
        path = self.root / name
        with zipfile.ZipFile(path, "w") as archive:
            for key, raw in members.items():
                archive.writestr(key, raw)
        return path

    def cli(self, *arguments):
        return subprocess.run([sys.executable, "-B", "-m", "tools.research", *map(str, arguments)],
                              cwd=ROOT, capture_output=True, text=True, timeout=10)

    def test_v1_first_range_matches_literal_bytes(self):
        path = self.create()
        members = self.members(path)
        manifest = json.loads(members["manifest.json"])
        report = json.loads(members["differential.json"])
        self.assertEqual(manifest["schema"], bundle.BGP_SCHEMA)
        self.assertEqual(manifest["first_divergence"]["index"], 1)
        self.assertEqual(manifest["first_divergence"]["row"]["field"], "message_type")
        self.assertEqual(report, bgp.compare(self.left, self.right))
        witnesses = json.loads(members["witnesses.json"])
        self.assertEqual([r["sha256"] for r in witnesses["ranges"]],
                         [hashlib.sha256(b"cdefghij").hexdigest()] * 2)
        self.assertEqual([(r["source_start"], r["source_end"]) for r in witnesses["ranges"]],
                         [("2", "10"), ("2", "10")])
        result = bundle.verify(path)
        self.assertEqual(result["status"], "PASS")
        for key in ("semantic_correctness_proven", "authorship_authenticated", "independent_record_mapping"):
            self.assertIs(result[key], False)

    def test_v1_agreement_has_no_ranges_or_correctness_claim(self):
        path = self.create(right=self.left)
        members = self.members(path)
        self.assertIsNone(json.loads(members["manifest.json"])["first_divergence"])
        witness = json.loads(members["witnesses.json"])
        self.assertEqual(witness["status"], "NO_OBSERVED_DIVERGENCE")
        self.assertEqual(witness["ranges"], [])
        self.assertFalse(bundle.verify(path)["semantic_correctness_proven"])

    def test_uncertainty_is_retained(self):
        self.right["observations"][0]["fields"]["message"]["message_type"]["status"] = "unknown"
        path = self.create()
        report = json.loads(self.members(path)["differential.json"])
        self.assertIsNone(report["first_observed_disagreement"])
        self.assertGreater(report["counts"]["not_comparable"], 0)
        self.assertEqual(bundle.verify(path)["status"], "PASS")

    def test_framing_disagreement_hashes_both_declared_ranges(self):
        self.right["observations"][0]["source_range"]["end"] = "11"
        path = self.create()
        members = self.members(path)
        first = json.loads(members["manifest.json"])["first_divergence"]
        self.assertEqual(first["row"]["group"], "framing")
        witness = json.loads(members["witnesses.json"])
        self.assertEqual([r["sha256"] for r in witness["ranges"]],
                         [hashlib.sha256(b"cdefghij").hexdigest(), hashlib.sha256(b"cdefghijk").hexdigest()])
        self.assertEqual(bundle.verify(path)["status"], "PASS")

    def test_v1_native_partition_sequence_and_window_are_bound(self):
        _, raw, manifest = native_export()
        left = bgp.from_native(raw, manifest, row_start=0, row_count=1)
        path = self.create(left=left, right=left)
        dataset = json.loads(self.members(path)["manifest.json"])["derived_dataset"]
        side = dataset["interpretations"]["left"]
        self.assertEqual(side["native_partition"], left["native_partition"])
        self.assertEqual(side["native_evidence"]["sequence"], manifest["sequence"])
        self.assertEqual(side["native_evidence"]["window"], manifest["window"])
        self.assertEqual(side["native_evidence"]["manifest_sha256"], hashlib.sha256(canonical(manifest)).hexdigest())
        self.assertEqual(bundle.verify(path)["status"], "PASS")

    def test_rebuilt_native_provenance_projection_cannot_substitute_metadata(self):
        _, raw, manifest = native_export()
        left = bgp.from_native(raw, manifest, row_start=0, row_count=1)
        path = self.create(left=left, right=left)
        for key in ("sequence", "window", "manifest_sha256", "native_partition"):
            members = self.members(path)
            wrapper = json.loads(members["manifest.json"])
            side = wrapper["derived_dataset"]["interpretations"]["left"]
            if key == "native_partition":
                side[key]["row_end"] = "0"
            else:
                side["native_evidence"][key] = "replacement"
            members["manifest.json"] = canonical(wrapper) + b"\n"
            with self.subTest(key=key), self.assertRaisesRegex(InvalidResearch, "derived dataset"):
                bundle.verify(self.rebuild(members, key + ".zip"))

    def test_v2_native_and_external_peer_uses_existing_comparator(self):
        row, manifest = fixture()
        left = bgp.from_native(seal(row, manifest), manifest, comparison_fields="per-field-v2")
        right = copy.deepcopy(left)
        right["producer"]["origin"] = "independent_fixture"
        right.pop("native_evidence")
        right.pop("native_coverage_verification")
        right["observations"][0].pop("evidence")
        right["observations"][0]["fields"]["nlri"]["route_actions"]["value"][0]["action"] = "announce"
        path = self.create(left=left, right=right)
        members = self.members(path)
        report = json.loads(members["differential.json"])
        self.assertEqual(report["schema"], bgp.DIFFERENTIAL_SCHEMA_V2)
        self.assertEqual(report, bgp.compare(left, right))
        self.assertEqual(json.loads(members["manifest.json"])["first_divergence"]["row"]["field"], "route_actions")
        self.assertEqual(bundle.verify(path)["status"], "PASS")

    def test_mixed_v1_v2_and_capture_modes_reject_before_publication(self):
        capture = self.root / "source.pcap"
        capture.write_bytes(pcap([packet(b"abc", "udp")]))
        generic = adapters.container_normalize(capture)
        newer = copy.deepcopy(self.right)
        newer["schema"] = bgp.SCHEMA_V2
        for peer in (generic, newer):
            path = self.root / "absent-parent" / "bad.zip"
            with self.subTest(schema=peer["schema"]), self.assertRaisesRegex(InvalidResearch, "schema mismatch"):
                bundle.create(path, self.source, self.left, peer, specifications=[])
            self.assertFalse(path.parent.exists())

    def test_nontext_interpretation_schemas_are_typed_api_and_cli_refusals(self):
        left, right, specifications = (self.root / name for name in ("left.json", "right.json", "specs.json"))
        right.write_bytes(canonical(self.right))
        specifications.write_text("[]")
        for index, schema in enumerate(([], {})):
            document = copy.deepcopy(self.left)
            document["schema"] = schema
            path = self.root / ("invalid-schema-" + str(index)) / "bad.zip"
            with self.subTest(schema=schema), self.assertRaisesRegex(InvalidResearch, "schema must be text"):
                bundle.create(path, self.source, document, self.right, specifications=[])
            self.assertFalse(path.parent.exists())
            left.write_bytes(canonical(document))
            rejected = self.cli("bundle", self.source, left, right, "--specifications", specifications, "--output", path)
            self.assertEqual(rejected.returncode, 1)
            self.assertEqual(json.loads(rejected.stdout)["status"], "ERROR")
            self.assertIn("schema must be text", json.loads(rejected.stdout)["reason"])
            self.assertFalse(path.parent.exists())

    def test_nontext_manifest_schemas_are_typed_api_and_cli_refusals(self):
        original = self.create()
        for index, schema in enumerate(([], {})):
            members = self.members(original)
            manifest = json.loads(members["manifest.json"])
            manifest["schema"] = schema
            members["manifest.json"] = canonical(manifest) + b"\n"
            path = self.rebuild(members, "manifest-schema-" + str(index) + ".zip")
            with self.subTest(schema=schema), self.assertRaisesRegex(InvalidResearch, "invalid bundle manifest"):
                bundle.verify(path)
            rejected = self.cli("verify-bundle", path)
            self.assertEqual(rejected.returncode, 1)
            self.assertEqual(json.loads(rejected.stdout)["status"], "ERROR")
            self.assertIn("invalid bundle manifest", json.loads(rejected.stdout)["reason"])

    def test_selected_source_and_normalization_mismatch_reject(self):
        self.source.write_bytes(b"ponmlkjihgfedcba")
        with self.assertRaisesRegex(InvalidResearch, "not bound"):
            self.create()
        self.source.write_bytes(RAW)
        self.right["normalization"]["config_sha256"] = "d" * 64
        with self.assertRaisesRegex(InvalidResearch, "normalization"):
            self.create()

    def test_source_change_during_capture_rejects(self):
        original = bundle.file_identity
        def changed(path, **kwargs):
            result = original(path, **kwargs)
            Path(path).write_bytes(b"ponmlkjihgfedcba")
            return result
        with patch.object(bundle, "file_identity", side_effect=changed), self.assertRaisesRegex(InvalidResearch, "source changed"):
            self.create()
        self.assertFalse((self.root / "case.zip").exists())

    def test_rehashed_source_and_range_witness_mutations_reject(self):
        path = self.create()
        members = self.members(path)
        members["source.capture"] = b"ponmlkjihgfedcba"
        manifest = json.loads(members["manifest.json"])
        manifest["source"] = {"sha256": hashlib.sha256(members["source.capture"]).hexdigest(), "bytes": "16"}
        members["manifest.json"] = canonical(manifest) + b"\n"
        with self.assertRaisesRegex(InvalidResearch, "recomputed divergence"):
            bundle.verify(self.rebuild(members, "source-tamper.zip"))
        members = self.members(path)
        witness = json.loads(members["witnesses.json"])
        witness["ranges"][0].update(source_end="9", sha256=hashlib.sha256(b"cdefghi").hexdigest())
        members["witnesses.json"] = canonical(witness) + b"\n"
        with self.assertRaisesRegex(InvalidResearch, "source witnesses"):
            bundle.verify(self.rebuild(members, "range-tamper.zip"))

    def test_rehashed_differential_and_dataset_claims_reject(self):
        path = self.create()
        for mutation, reason in (("differential", "recomputed divergence"),
                                 ("provenance", "derived dataset"), ("claims", "bundle claims")):
            members = self.members(path)
            manifest = json.loads(members["manifest.json"])
            if mutation == "differential":
                report = json.loads(members["differential.json"])
                report["semantic_correctness_proven"] = True
                members["differential.json"] = canonical(report) + b"\n"
                manifest["derived_dataset"]["differential"] = identity(members["differential.json"])
            elif mutation == "provenance":
                manifest["derived_dataset"]["independent_record_mapping"] = True
            else:
                manifest["adjudication"] = "PROVEN"
            members["manifest.json"] = canonical(manifest) + b"\n"
            with self.subTest(mutation=mutation), self.assertRaisesRegex(InvalidResearch, reason):
                bundle.verify(self.rebuild(members, mutation + ".zip"))

    def test_manifest_first_index_requires_exact_json_type(self):
        members = self.members(self.create())
        manifest = json.loads(members["manifest.json"])
        manifest["first_divergence"]["index"] = True  # Python True == 1 is not JSON identity.
        members["manifest.json"] = canonical(manifest) + b"\n"
        with self.assertRaisesRegex(InvalidResearch, "manifest divergence"):
            bundle.verify(self.rebuild(members))

    def test_rebuilt_valid_interpretations_still_establish_no_authenticity_or_semantics(self):
        # The source isn't an MRT record. Coherent invented interpretations can
        # reproduce a comparison and byte-range hashes, never parser truth.
        self.left["observations"][0]["source_range"]["end"] = "9"
        self.right["observations"][0]["source_range"]["end"] = "9"
        self.left["observations"][0]["fields"]["message"]["message_type"]["value"] = "invented"
        replacement = b"ponmlkjihgfedcba"
        self.source.write_bytes(replacement)
        for document in (self.left, self.right):
            document["source"] = {"sha256": hashlib.sha256(replacement).hexdigest(), "bytes": "16"}
        result = bundle.verify(self.create())
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["authorship_authenticated"])
        self.assertFalse(result["semantic_correctness_proven"])
        self.assertFalse(result["independent_record_mapping"])

    def test_swapped_bundle_schema_cannot_downgrade_verification(self):
        members = self.members(self.create())
        manifest = json.loads(members["manifest.json"])
        manifest["schema"] = bundle.SCHEMA
        members["manifest.json"] = canonical(manifest) + b"\n"
        with self.assertRaisesRegex(InvalidResearch, "mixed bundle mode"):
            bundle.verify(self.rebuild(members))

    def test_exact_expanded_member_and_source_caps_and_one_below(self):
        baseline = self.create()
        members = self.members(baseline)
        expanded = sum(map(len, members.values()))
        maximum = max(map(len, members.values()))
        with patch.object(bundle, "MAX_BUNDLE", expanded), patch.object(bundle, "MAX_MEMBER", maximum):
            self.assertEqual(bundle.verify(self.create("exact.zip"))["status"], "PASS")
        for constant, limit in (("MAX_BUNDLE", expanded - 1), ("MAX_MEMBER", maximum - 1)):
            with self.subTest(consumer="verify", constant=constant), patch.object(bundle, constant, limit):
                with self.assertRaises(InvalidResearch):
                    bundle.verify(baseline)
        for constant, limit, reason in (("MAX_BUNDLE", expanded - 1, "expanded bundle"),
                                        ("MAX_MEMBER", maximum - 1, "member size"),
                                        ("MAX_MEMBER", len(RAW) - 1, "input byte")):
            path = self.root / (constant + str(limit)) / "case.zip"
            with self.subTest(constant=constant, limit=limit), patch.object(bundle, constant, limit):
                with self.assertRaisesRegex(InvalidResearch, reason):
                    bundle.create(path, self.source, self.left, self.right, specifications=[])
                self.assertFalse(path.parent.exists())
        # Empty observations keep every document tiny while an inert source
        # reaches the exact shared source/member cap.
        source = self.root / "cap-source"
        data = b"x" * 4096
        source.write_bytes(data)
        left = copy.deepcopy(self.left)
        left["source"] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": "4096"}
        left["observations"] = []
        with patch.object(bundle, "MAX_MEMBER", len(data)):
            path = self.root / "source-exact.zip"
            bundle.create(path, source, left, left, specifications=[])
            self.assertEqual(bundle.verify(path)["status"], "PASS")

    def test_generic_bundle_sibling_remains_supported(self):
        self.source.write_bytes(pcap([packet(b"abc", "udp")]))
        left = adapters.container_normalize(self.source)
        path = self.create(left=left, right=left)
        manifest = json.loads(self.members(path)["manifest.json"])
        self.assertEqual(manifest["schema"], bundle.SCHEMA)
        self.assertNotIn("derived_dataset", manifest)
        self.assertEqual(bundle.verify(path)["schema"], "pcap-evidence.research-bundle-verification.v1")

    def test_physical_archive_size_admission_precedes_no_clobber_publication(self):
        # Use the real accepted ZIP_STORED codec to separate physical archive
        # size from expanded size without a large incompressible fixture.
        original_zip = zipfile.ZipFile
        class StoredZip(original_zip):
            def writestr(self, entry, data, *args, **kwargs):
                entry = copy.copy(entry)
                entry.compress_type = zipfile.ZIP_STORED
                return super().writestr(entry, data, *args, **kwargs)
        with patch.object(bundle.zipfile, "ZipFile", StoredZip):
            baseline = self.create("stored.zip")
            actual = baseline.stat().st_size
            with original_zip(baseline) as archive:
                self.assertLess(sum(entry.file_size for entry in archive.infolist()), actual - 1)
            with patch.object(bundle, "MAX_BUNDLE", actual):
                exact = self.create("archive-exact.zip")
                self.assertEqual(exact.stat().st_size, actual)
                self.assertEqual(bundle.verify(exact)["status"], "PASS")
            output = self.root / "archive-one-below.zip"
            with patch.object(bundle, "MAX_BUNDLE", actual - 1), patch.object(bundle.os, "link", wraps=bundle.os.link) as publish:
                with self.assertRaisesRegex(InvalidResearch, "bundle size limit"):
                    self.create(output.name)
                publish.assert_not_called()
            self.assertFalse(output.exists())
            self.assertEqual(list(self.root.glob(".research-*")), [])

    def test_public_cli_create_verify_refusals_and_no_clobber(self):
        left, right, specifications = (self.root / name for name in ("left.json", "right.json", "specs.json"))
        left.write_bytes(canonical(self.left))
        right.write_bytes(canonical(self.right))
        specifications.write_text("[]")
        output = self.root / "cli.zip"
        args = ("bundle", self.source, left, right, "--specifications", specifications, "--output", output)
        created = self.cli(*args)
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
        before = output.read_bytes()
        verified = self.cli("verify-bundle", output)
        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
        self.assertFalse(json.loads(verified.stdout)["semantic_correctness_proven"])
        collision = self.cli(*args)
        self.assertEqual(collision.returncode, 1)
        self.assertEqual(output.read_bytes(), before)
        bad = copy.deepcopy(self.right)
        bad["schema"] = bgp.SCHEMA_V2
        right.write_bytes(canonical(bad))
        rejected = self.cli(*args[:-1], self.root / "invalid.zip")
        self.assertEqual(rejected.returncode, 1)
        self.assertFalse((self.root / "invalid.zip").exists())
        members = self.members(output)
        witness = json.loads(members["witnesses.json"])
        witness["ranges"][0]["sha256"] = "0" * 64
        members["witnesses.json"] = canonical(witness) + b"\n"
        rejected = self.cli("verify-bundle", self.rebuild(members, "cli-rebuilt.zip"))
        self.assertEqual(rejected.returncode, 1)
        self.assertIn("source witnesses", json.loads(rejected.stdout)["reason"])


if __name__ == "__main__":
    unittest.main()
