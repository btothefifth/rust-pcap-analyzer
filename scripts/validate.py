#!/usr/bin/env python3
"""Ordered validation with honest, machine-readable PASS/FAIL/BLOCKED receipts.
Does not install tools, alter fixtures, or weaken tests when prerequisites fail.
Native builds create Cargo's target/; the only other write is the requested receipt.
"""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
ROOT = Path(__file__).resolve().parents[1]


def receipt_command(command: list[str]) -> list[str]:
    """Keep machine receipts portable instead of leaking the runner's path."""
    return ["python" if part == sys.executable else part for part in command]


def source_identity() -> str:
    digest = hashlib.sha256()
    for file in sorted(ROOT.rglob("*")):
        relative = file.relative_to(ROOT)
        if not file.is_file() or file.is_symlink() or set(relative.parts) & {"target", "evidence", ".git", "__pycache__", ".pytest_cache"} or file.suffix in {".zip", ".pyc"}:
            continue
        digest.update(relative.as_posix().encode() + b"\0" + hashlib.sha256(file.read_bytes()).digest())
    return digest.hexdigest()


def sanitize_output(value: str) -> str:
    """Keep machine receipts independent of the runner's checkout path."""
    root = str(ROOT)
    return value.replace(root, "<repo>").replace(root.replace("\\", "/"), "<repo>")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receipt", type=Path, default=ROOT / "evidence/local-validation.json")
    args = p.parse_args()
    receipt = {"schema": "pcap-evidence.validation.v1", "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "platform": platform.platform(), "python": sys.version.split()[0], "source_identity": source_identity(), "steps": [],
               "status": "BLOCKED", "native_rust_executed": False}
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", CARGO_TERM_COLOR="never")

    def execute(command: list[str], native: bool = False) -> bool:
        start = time.monotonic()
        try:
            result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=300, check=False)
            step = {"command": receipt_command(command), "status": "PASS" if result.returncode == 0 else "FAIL", "exit_code": result.returncode,
                    "stdout": sanitize_output(result.stdout), "stderr": sanitize_output(result.stderr),
                    "elapsed_seconds": round(time.monotonic()-start, 3)}
        except (OSError, subprocess.TimeoutExpired) as error:
            step = {"command": receipt_command(command), "status": "BLOCKED" if isinstance(error, FileNotFoundError) else "FAIL",
                    "error": str(error), "elapsed_seconds": round(time.monotonic()-start, 3)}
        receipt["steps"].append(step)
        if native and step["status"] == "PASS":
            receipt["native_rust_executed"] = True
        print(f"{step['status']}: {' '.join(command)}")
        return step["status"] == "PASS"

    good = True
    for command in [[sys.executable, "scripts/static_check.py"], [sys.executable, "scripts/make_fixtures.py", "--check"],
                    [sys.executable, "scripts/reference_verify.py"], [sys.executable, "scripts/test_oracle.py"]]:
        if not execute(command):
            good = False
            receipt["status"] = "FAIL"
            break
    if good:
        if shutil.which("cargo") is None or shutil.which("rustc") is None:
            receipt["steps"].append({"status": "BLOCKED", "command": ["cargo", "test", "--locked", "--offline"],
                                     "reason": "Rust compiler/Cargo absent; native checks were not run"})
        else:
            binary_name = "target/debug/pcap-evidence.exe" if os.name == "nt" else "target/debug/pcap-evidence"
            commands = [["rustc", "--version"], ["cargo", "check", "--locked", "--offline", "--all-targets"],
                        ["cargo", "test", "--locked", "--offline", "--all-targets"],
                        ["cargo", "test", "--locked", "--offline", "--release", "--all-targets"],
                        ["cargo", "clippy", "--locked", "--offline", "--all-targets", "--", "-D", "warnings"],
                        ["cargo", "build", "--locked", "--offline", "--bins"],
                        [sys.executable, "scripts/check_cli.py", "--binary", binary_name],
                        [sys.executable, "scripts/check_hardening_cli.py", "--binary", binary_name],
                        [sys.executable, "scripts/mutation_check.py"]]
            receipt["status"] = "PASS"
            for command in commands:
                if not execute(command, native=command[:2] == ["cargo", "test"]):
                    receipt["status"] = "FAIL"
                    break
    receipt["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    receipt["source_unchanged"] = source_identity() == receipt["source_identity"]
    if not receipt["source_unchanged"]:
        receipt["status"] = "FAIL"
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(f"{receipt['status']}: receipt written to {args.receipt}")
    return 0 if receipt["status"] == "PASS" else 2 if receipt["status"] == "BLOCKED" else 1

if __name__ == "__main__":
    raise SystemExit(main())
