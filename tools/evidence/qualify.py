"""Run actual gates and retain honest PASS/FAIL/BLOCKED receipts.

Never installs tools, fetches dependencies, changes protocol expectations, or
silently skips native proof. Fuzzing is opt-in and its actual duration is recorded;
a short smoke run is not represented as a sustained campaign.
"""
from __future__ import annotations
import argparse
import datetime
import json
from pathlib import Path
import platform
import shutil
import sys
from .process import run


def aggregate(results: list[dict]) -> str:
    return "FAIL" if any(x["status"] == "FAIL" for x in results) else "BLOCKED" if any(x["status"] == "BLOCKED" for x in results) else "PASS"


def gates(root: Path, receipt_directory: Path, *, native=True, timeout=1200, fuzz_seconds: int = 0) -> dict:
    root = root.resolve()
    receipt_directory.mkdir(parents=True, exist_ok=False)
    checks = [run([sys.executable, "-m", "unittest", "discover", "-s", "tools/tests", "-v"],
                  receipt_directory, "python-tests", timeout=timeout, cwd=root)]
    if native:
        commands = [
            ("root-test", ["cargo", "test", "--locked", "--offline", "--all-targets"]),
            ("root-release-test", ["cargo", "test", "--locked", "--offline", "--release", "--all-targets"]),
            ("root-clippy", ["cargo", "clippy", "--locked", "--offline", "--all-targets", "--", "-D", "warnings"]),
            ("root-format", ["cargo", "fmt", "--all", "--", "--check"]),
            ("stream-test", ["cargo", "test", "--manifest-path", "streaming/Cargo.toml", "--locked", "--offline", "--all-targets"]),
            ("stream-release-test", ["cargo", "test", "--manifest-path", "streaming/Cargo.toml", "--locked", "--offline", "--release", "--all-targets"]),
            ("stream-clippy", ["cargo", "clippy", "--manifest-path", "streaming/Cargo.toml", "--locked", "--offline", "--all-targets", "--", "-D", "warnings"]),
            ("stream-format", ["cargo", "fmt", "--manifest-path", "streaming/Cargo.toml", "--all", "--", "--check"]),
            ("stream-build", ["cargo", "build", "--manifest-path", "streaming/Cargo.toml", "--locked", "--offline", "--release"]),
        ]
        checks += [run(argv, receipt_directory, name, timeout=timeout, cwd=root) for name, argv in commands]
    else:
        checks.append(dict(status="BLOCKED", reason="native_gates_not_requested", command=[]))
    if fuzz_seconds:
        if fuzz_seconds < 1:
            raise ValueError("fuzz seconds must be positive")
        for target in ("streaming", "protocols", "network"):
            cmd = ["cargo", "+nightly", "fuzz", "run", target, "--", f"-max_total_time={fuzz_seconds}",
                   "-timeout=10", "-rss_limit_mb=1024", "-max_len=65536"]
            check = run(cmd, receipt_directory, "fuzz-" + target, timeout=fuzz_seconds + 300,
                        cwd=root / "streaming", max_log_bytes=256*1024*1024)
            check["requested_seconds"] = fuzz_seconds
            check["qualification"] = "smoke_only" if fuzz_seconds < 3600 else "bounded_campaign_not_completeness_proof"
            checks.append(check)
    receipt = dict(schema="pcap-evidence.qualification.v1", status=aggregate(checks),
                   time_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   platform=platform.platform(), python=sys.version, checks=checks,
                   fuzz_campaign_requested=fuzz_seconds > 0, cross_platform_claim=False,
                   representative_real_world_qualification=False, large_capture_performance_qualification=False)
    (receipt_directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("repository", type=Path); p.add_argument("receipt_directory", type=Path)
    p.add_argument("--no-native", action="store_true", help="overall result remains BLOCKED")
    p.add_argument("--timeout", type=float, default=1200)
    p.add_argument("--fuzz-seconds", type=int, default=0)
    a = p.parse_args(argv)
    receipt = gates(a.repository, a.receipt_directory, native=not a.no_native, timeout=a.timeout, fuzz_seconds=a.fuzz_seconds)
    print(json.dumps(receipt, indent=2))
    return {"PASS":0,"FAIL":1,"BLOCKED":2}[receipt["status"]]
