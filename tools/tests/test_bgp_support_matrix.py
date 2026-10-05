import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "docs" / "product" / "bgp-support-matrix.json"
REQUIRED_AREAS = {
    "core",
    "capabilities",
    "nlri",
    "core_attributes",
    "common_extensions",
    "as_semantics",
    "refresh_restart",
    "route_state",
    "policy",
    "external_input",
    "product_integration",
    "stream_evidence",
    "qualification",
}


class BgpSupportMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = json.loads(MATRIX.read_text(encoding="utf-8"))

    def test_schema_and_authority_are_pinned(self):
        self.assertEqual(
            self.matrix["schema"], "pcap-evidence.bgp-support-matrix.v1"
        )
        self.assertEqual(
            self.matrix["authority"], "docs/product/BGP_COMPLETION.md"
        )
        self.assertTrue((ROOT / self.matrix["authority"]).is_file())

    def test_every_declared_profile_area_has_exactly_one_current_row(self):
        areas = [entry["area"] for entry in self.matrix["entries"]]
        self.assertEqual(set(areas), REQUIRED_AREAS)
        self.assertEqual(len(areas), len(REQUIRED_AREAS))
        self.assertEqual(set(self.matrix["profile_areas"]), REQUIRED_AREAS)

    def test_rows_are_unique_bounded_and_point_to_repository_evidence(self):
        allowed_states = set(self.matrix["states"])
        ids = set()
        for entry in self.matrix["entries"]:
            with self.subTest(entry=entry["id"]):
                self.assertRegex(entry["id"], r"^BGP-S\d{3}$")
                self.assertNotIn(entry["id"], ids)
                ids.add(entry["id"])
                self.assertIn(entry["state"], allowed_states)
                self.assertTrue(entry["feature"].strip())
                self.assertTrue(entry["remaining"].strip())
                if entry["state"] == "open":
                    self.assertEqual(entry["code"], [])
                    self.assertEqual(entry["tests"], [])
                    self.assertTrue(entry["planned_code"])
                    self.assertTrue(entry["planned_tests"])
                    continue
                for field in ("code", "tests"):
                    self.assertTrue(entry[field])
                    for relative in entry[field]:
                        self.assertFalse(Path(relative).is_absolute())
                        self.assertNotIn("..", Path(relative).parts)
                        self.assertTrue(
                            (ROOT / relative).is_file(),
                            f"missing {field} path for {entry['id']}: {relative}",
                        )

    def test_cli_help_matches_the_reviewed_source_snapshot(self):
        # pcap-depth prints usage().detail for --help. Pin that exact public
        # string without executing the native binary in this static contract check.
        source = (ROOT / "product" / "src" / "bin" / "pcap-depth.rs").read_text(
            encoding="utf-8"
        )
        marker = 'Error::new(ErrorCode::Usage,0,"arguments","'
        self.assertEqual(source.count(marker), 1)
        start = source.index(marker) + len(marker)
        end = source.index('")', start)
        help_detail = source[start:end]
        self.assertEqual(
            hashlib.sha256(help_detail.encode("utf-8")).hexdigest(),
            "9ab96b19f7ee46025860c58d23c056b713150938a1469178ba4be48407f0cda1",
        )
        for selector in (
            "bgp query STORE",
            "--prefix-mode exact|contains|contained-by",
            "--attribute-scope current-effective|any-retained-version|observation-event",
            "--reported-start-ns I --reported-end-ns I",
            "bgp changes STORE",
            "bgp expectations STORE",
            "--comparison-fields legacy-v1|per-field-v2",
        ):
            self.assertIn(selector, help_detail)

    def test_no_row_claims_full_qualification_before_all_gates_exist(self):
        qualified = [
            entry for entry in self.matrix["entries"] if entry["state"] == "qualified"
        ]
        self.assertEqual(qualified, [])


if __name__ == "__main__":
    unittest.main()
