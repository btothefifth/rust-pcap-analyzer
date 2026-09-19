import unittest

from scripts.validate_followup import artifact_name


class FollowupArtifactNames(unittest.TestCase):
    def test_root_manifest_has_stable_name(self):
        self.assertEqual(artifact_name("Cargo.toml"), "core")

    def test_nested_manifest_has_windows_safe_name(self):
        self.assertEqual(artifact_name("product/ffi/Cargo.toml"), "product-ffi")


if __name__ == "__main__":
    unittest.main()
