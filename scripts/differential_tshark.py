#!/usr/bin/env python3
"""Optional container-field differential check, not a universal correctness oracle.
Compares frame ordinals, capture/original lengths and representable timestamps.
No live capture and no name resolution. Existing tshark required; no installs.
"""
import argparse
from fractions import Fraction
import json
import shutil
import subprocess
import sys
from pathlib import Path
sys.dont_write_bytecode = True
from reference_verify import parse

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("capture", type=Path)
    args = p.parse_args()
    tool = shutil.which("tshark")
    if tool is None:
        print(json.dumps({"status": "BLOCKED", "reason": "tshark not installed"}))
        return 2
    version = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=10, check=True).stdout.splitlines()[0]
    command = [tool, "-n", "-r", str(args.capture), "-T", "fields", "-e", "frame.number", "-e", "frame.cap_len", "-e", "frame.len", "-e", "frame.time_epoch"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=True)
    packets = parse(args.capture.read_bytes())["packets"]
    lines = result.stdout.splitlines()
    assert len(lines) == len(packets), "packet count disagreement"
    unresolved = []
    for number, (line, expected) in enumerate(zip(lines, packets), 1):
        fields = line.split("\t")
        assert [int(x) for x in fields[:3]] == [number, len(expected["data"]), expected["original"]]
        if expected["ns"] is None:
            unresolved.append(number)
        else:
            assert len(fields) >= 4 and Fraction(fields[3]) * 10**9 == int(expected["ns"]), (number, "timestamp disagreement")
    print(json.dumps({"status": "PASS", "tool": version, "packets_compared": len(packets), "time_not_compared": unresolved,
                      "scope": "container fields only; this does not validate Rust, reassembly, or attack attribution"}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
