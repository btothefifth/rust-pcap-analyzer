#!/usr/bin/env python3
"""Measure the actual CLI read/parse/reconstruct/serialize path; no SLO assertions.
stdout goes to an OS null sink, so durable report-file publication is excluded.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import time

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("capture", type=Path)
    p.add_argument("--binary", type=Path, default=Path("target/release/pcap-evidence"))
    p.add_argument("--runs", type=int, default=5)
    args = p.parse_args()
    if not 1 <= args.runs <= 100:
        p.error("runs must be in 1..100")
    binary = args.binary.resolve()
    if not binary.is_file():
        p.error("build the release binary first; on Windows pass the .exe path")
    source_hash = hashlib.sha256(args.capture.read_bytes()).hexdigest()
    elapsed = []
    for _ in range(args.runs):
        start = time.perf_counter()
        subprocess.run([str(binary), "analyze", str(args.capture.resolve())], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=300, check=True)
        elapsed.append(time.perf_counter() - start)
    assert hashlib.sha256(args.capture.read_bytes()).hexdigest() == source_hash
    print(json.dumps({"scope": "CLI with OS-null stdout; includes JSON encoding but not durable output-file I/O", "capture_sha256": source_hash,
                      "samples_seconds": elapsed, "median_seconds": statistics.median(elapsed),
                      "minimum_seconds": min(elapsed), "maximum_seconds": max(elapsed),
                      "cache_state": "uncontrolled; not a cold-storage benchmark", "production_slo_claim": False}, indent=2))

if __name__ == "__main__":
    main()
