#!/usr/bin/env python3
"""Black-box Rust CLI checks using the independent Python fixture oracle.
Requires an already-built binary. Does not install/build tools or modify captures.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
sys.dont_write_bytecode = True
from reference_verify import FIX, parse, verify


def run(binary: Path, *args: str) -> dict:
    result = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        raise AssertionError(f"CLI failed ({result.returncode}): {args}\n{result.stderr}")
    return json.loads(result.stdout)


def provenance(node: object, packets: list[dict]) -> int:
    """Independently reconstruct every exported byte range from original packets."""
    checked = 0
    if isinstance(node, dict):
        if {"length", "sha256", "spans"}.issubset(node):
            rebuilt = bytearray()
            cursor = 0
            for span in node["spans"]:
                assert span["start"] == cursor < span["end"]
                packet = packets[span["packet"]["frame"] - 1]
                assert int(span["packet"]["record_offset"]) == packet["offset"]
                count = span["end"] - span["start"]
                raw = packet["data"][span["packet_start"]:span["packet_start"] + count]
                assert len(raw) == count
                rebuilt.extend(raw)
                cursor = span["end"]
            assert cursor == node["length"]
            assert hashlib.sha256(rebuilt).hexdigest() == node["sha256"]
            if "hex" in node:
                assert rebuilt.hex() == node["hex"]
            checked += 1
        checked += sum(provenance(value, packets) for value in node.values())
    elif isinstance(node, list):
        checked += sum(provenance(value, packets) for value in node)
    return checked


def check(binary: Path) -> dict:
    verify()  # Cheapest independent prerequisites must pass first.
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in FIX.iterdir() if p.is_file()}
    cases = json.loads((FIX / "TRUTH.json").read_text())["cases"]
    inspected = 0
    for name, expected in cases.items():
        if expected.get("reject"):
            result = subprocess.run([str(binary), "inspect", str(FIX / name)], capture_output=True, text=True, timeout=30)
            assert result.returncode == 4 and not result.stdout, name
            assert "error" in json.loads(result.stderr)
            continue
        native = run(binary, "inspect", str(FIX / name), "--include-payload")
        oracle = parse((FIX / name).read_bytes())
        packets = [r["body"] for r in native["records"] if r["body"]["kind"] == "packet"]
        assert len(packets) == len(oracle["packets"]), name
        for a, b in zip(packets, oracle["packets"]):
            assert a["packet_hex"] == b["data"].hex()
            assert a["packet_sha256"] == hashlib.sha256(b["data"]).hexdigest()
            assert a["metadata"]["interface"] == b["interface"] and a["metadata"]["section"] == b["section"]
            stamp = a["metadata"]["timestamp"]
            assert (stamp["unix_ns_exact"] if stamp else None) == b["ns"]
        inspected += 1
    proof_spans = 0
    for name in ["dnp3_tcp.pcap", "modbus_tcp.pcap", "ipv4_fragments.pcap", "conflicting_tcp.pcap"]:
        native = run(binary, "analyze", str(FIX / name), "--include-payload")
        packets = parse((FIX / name).read_bytes())["packets"]
        proof_spans += provenance(native, packets)
        assert len(native["packets"]) == len(packets)
        assert all(p["disposition"] not in ["pending", "fragment_pending"] for p in native["packets"])
        assert native["capture_sha256"] == hashlib.sha256((FIX / name).read_bytes()).hexdigest()
        if name == "dnp3_tcp.pcap":
            messages = [m for a in native["applications"] for m in a["data"].get("messages", [])]
            assert sorted(m["class"] for m in messages) == ["request", "response", "unsolicited"]
            assert any(t["status"] == "candidate_pair" for t in native["transaction_candidates"])
            labeled = run(binary, "analyze", str(FIX / name), "--include-payload", "--labels", str(FIX / "attempts.tsv"))
            assert labeled["flows"] == native["flows"] and labeled["applications"] == native["applications"]
            assert labeled["attempt_label_matches"][0]["status"] == "candidate_evidence_found"
    with tempfile.TemporaryDirectory(prefix="pcap-evidence-blackbox-") as directory:
        index = Path(directory) / "source.pcidx"
        built = subprocess.run([str(binary), "index", str(FIX / "mixed_sections.pcapng"), "-o", str(index)], capture_output=True, timeout=30)
        assert built.returncode == 0
        assert run(binary, "verify-index", str(FIX / "mixed_sections.pcapng"), "--index", str(index))["verified"]
        entry = run(binary, "packet", str(FIX / "mixed_sections.pcapng"), "--index", str(index), "--frame", "1")
        assert bytes.fromhex(entry["packet_hex"]) == parse((FIX / "mixed_sections.pcapng").read_bytes())["packets"][0]["data"]
        assert set(Path(directory).iterdir()) == {index}
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in FIX.iterdir() if p.is_file()}
    assert after == before, "inspection/analysis modified evidence files or created sidecars"
    return {"native_cli_executed": True, "container_cases": inspected, "provenance_objects_rebuilt": proof_spans,
            "observer_purity": "passed", "scope": "synthetic fixtures, not an external capture corpus"}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, default=Path("target/debug/pcap-evidence"))
    args = p.parse_args()
    binary = args.binary.resolve()
    if os.name == "nt" and not binary.exists():
        binary = binary.with_suffix(".exe")
    if not binary.is_file():
        print(json.dumps({"status": "BLOCKED", "reason": "already-built Rust binary required", "binary": str(binary)}))
        return 2
    print(json.dumps(check(binary), indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
