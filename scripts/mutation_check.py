#!/usr/bin/env python3
"""Three intentional production-code defects must make their exact tests go red.
Works in owned temporary copies, never edits the user's working tree. Compilation
failure does NOT count as a killed semantic mutant. Requires installed pinned Rust.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
ROOT = Path(__file__).resolve().parents[1]
MUTANTS = [
    ("src/time.rs", "value & 0x80 == 0", "value & 0x70 == 0", "capture_contract", "section_endianness_interface_reset_and_signed_offset"),
    ("src/tcp.rs", "if policy == OverlapPolicy::RejectConflict {", "if false && policy == OverlapPolicy::RejectConflict {", "reconstruction", "conflicting_overlap_is_an_explicit_gap_not_fabricated_payload"),
    ("src/index.rs", "if index.encode()?.as_slice() != sidecar {", "if false && index.encode()?.as_slice() != sidecar {", "integrity", "sidecar_self_hash_cannot_authorize_forged_metadata"),
]


def run(root: Path, suite: str, test: str) -> subprocess.CompletedProcess:
    return subprocess.run(["cargo", "test", "--locked", "--offline", "--test", suite, test, "--", "--exact"],
                          cwd=root, env=dict(os.environ, CARGO_TERM_COLOR="never"), capture_output=True, text=True, timeout=180)


def main() -> int:
    if shutil.which("cargo") is None or shutil.which("rustc") is None:
        print(json.dumps({"status": "BLOCKED", "reason": "native compiler unavailable", "mutations_executed": 0}))
        return 2
    receipts = []
    with tempfile.TemporaryDirectory(prefix="pcap-evidence-mutation-") as directory:
        root = Path(directory) / "repo"
        shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(".git", "target", "__pycache__", "evidence", "*.zip"))
        for file, old, new, suite, test in MUTANTS:
            baseline = run(root, suite, test)
            assert baseline.returncode == 0 and "1 passed" in baseline.stdout, baseline.stdout + baseline.stderr
            path = root / file
            original = path.read_text()
            assert original.count(old) == 1, (file, "mutation anchor must be unique")
            path.write_text(original.replace(old, new))
            try:
                mutant = run(root, suite, test)
                killed = mutant.returncode != 0 and f"test {test} ... FAILED" in mutant.stdout and "1 failed" in mutant.stdout
                assert killed, "mutant survived, did not reach target test, or did not compile:\n" + mutant.stdout + mutant.stderr
                receipts.append({"file": file, "test": f"{suite}::{test}", "status": "SEMANTIC_MUTANT_KILLED", "stdout": mutant.stdout})
            finally:
                path.write_text(original)
    print(json.dumps({"status": "PASS", "mutations_executed": len(receipts), "receipts": receipts}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
