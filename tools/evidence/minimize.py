"""Bounded packet-subset ddmin for a reproducible disagreement predicate.

Predicate argv must contain {capture}. Exit 0 means the same specific disagreement
persists; exit 1 means it does not; any other exit/timeout stops the reduction.
Do not use a predicate that merely accepts any crash. This is not byte-level
malformed-container repair. Metadata other than PCAP headers/SHB/IDB is omitted;
finite SHB lengths become unknown (-1). The output is a derived test artifact,
never an archival copy. Packet bytes remain exact and the frame map is retained.
"""
from __future__ import annotations
import argparse
import json
import math
import os
from pathlib import Path
import struct
import subprocess
import tempfile
from .containers import Reader, Record
from .common import InvalidEvidence, digest_file, publish_new


def ddmin(items: list[int], predicate, max_calls: int = 100) -> tuple[list[int], int, bool]:
    if max_calls < 1:
        raise ValueError("max_calls must be positive")
    calls = 1
    if not predicate(items):
        raise InvalidEvidence("initial capture does not reproduce the target disagreement")
    current, n = list(items), 2
    while len(current) >= 2 and calls < max_calls:
        width = math.ceil(len(current) / n)
        reduced = False
        for start in range(0, len(current), width):
            if calls >= max_calls:
                break
            candidate = current[:start] + current[start + width:]
            calls += 1
            if predicate(candidate):
                current, n, reduced = candidate, max(2, n - 1), True
                break
        if not reduced:
            if n >= len(current):
                break
            n = min(len(current), n * 2)
    # Greedy single deletion also proves the single-packet/empty boundary.
    minimal = False
    if calls < max_calls:
        for item in list(current):
            if calls >= max_calls:
                break
            candidate = [x for x in current if x != item]
            calls += 1
            if predicate(candidate):
                current = candidate
        else:
            minimal = True
    return current, calls, minimal


def write_subset(records: list[Record], selected: set[int], path: Path) -> None:
    with path.open("wb") as out:
        for r in records:
            if r.packet is not None:
                if r.packet.frame in selected:
                    out.write(r.raw)
            elif r.kind == "pcap_header" or r.kind == 1:
                out.write(r.raw)
            elif r.kind == 0x0A0D0D0A:
                raw = bytearray(r.raw)
                struct.pack_into(r.endian + "q", raw, 16, -1)
                out.write(raw)


def minimize(source: Path, destination: Path, command: list[str], *, max_bytes=64*1024*1024,
             max_packets=10000, max_calls=100, timeout=30) -> dict:
    if source.stat().st_size > max_bytes:
        raise InvalidEvidence("reducer input exceeds explicit memory budget; select a small region first")
    if not command or not any("{capture}" in x for x in command):
        raise InvalidEvidence("predicate argv must include {capture}")
    if destination.exists():
        raise FileExistsError(destination)
    with source.open("rb") as f:
        records = list(Reader(f).records())
    frames = [r.packet.frame for r in records if r.packet is not None]
    if len(frames) > max_packets:
        raise InvalidEvidence("reducer packet budget exceeded")
    with tempfile.TemporaryDirectory(prefix="pcap-ddmin-", dir=destination.parent) as td:
        candidate = Path(td) / "candidate.pcap"
        def predicate(selected):
            write_subset(records, set(selected), candidate)
            argv = [x.replace("{capture}", str(candidate.resolve())) for x in command]
            completed = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       stdin=subprocess.DEVNULL, timeout=timeout, check=False)
            if completed.returncode not in (0, 1):
                raise InvalidEvidence(f"predicate failed operationally: exit {completed.returncode}")
            return completed.returncode == 0
        selected, calls, minimal = ddmin(frames, predicate, max_calls)
        write_subset(records, set(selected), candidate)
        digest = digest_file(candidate)
        publish_new(candidate, destination)
    return dict(status="PASS", qualification="target_predicate_preserved_not_semantic_truth",
                source_sha256=digest_file(source), result_sha256=digest, calls=calls,
                single_deletion_minimal=minimal, budget_exhausted=calls>=max_calls,
                frame_map=[dict(derived_frame=i+1, original_frame=old) for i,old in enumerate(selected)],
                metadata_policy="keep_capture_section_interface_headers_only; finite_section_lengths_removed")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path); p.add_argument("destination", type=Path)
    p.add_argument("--max-bytes", type=int, default=64*1024*1024)
    p.add_argument("--max-packets", type=int, default=10000)
    p.add_argument("--max-calls", type=int, default=100)
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("predicate", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    cmd = a.predicate[1:] if a.predicate[:1] == ["--"] else a.predicate
    receipt = minimize(a.source,a.destination,cmd,max_bytes=a.max_bytes,max_packets=a.max_packets,max_calls=a.max_calls,timeout=a.timeout)
    print(json.dumps(receipt, indent=2))
    return 0
