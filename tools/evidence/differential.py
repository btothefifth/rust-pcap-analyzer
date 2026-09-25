"""Layered differential runner. Tool disagreement is a finding, not an oracle vote.

Exact packet comparisons: Python container oracle, pcap-stream and optionally
pcap-parser. TShark independently checks lengths/time (its encapsulation IDs are
not PCAP LINKTYPE values). Zeek and Suricata outputs have different grains and
are retained as semantic observations, NOT falsely equated to packet rows.
"""
from __future__ import annotations
import argparse
from decimal import Decimal
import itertools
import json
from pathlib import Path
import shutil
from .common import canonical, digest_file, InvalidEvidence, load_json, bounded_lines
from .containers import Reader
from .index import ChainReader
from .process import run

EXACT = ("frame", "record_offset", "data_offset", "captured_length", "original_length", "section", "interface", "link_type", "timestamp_ns", "packet_sha256")

def rust_rows(path: Path):
    with path.open("rb") as f:
        for _, e in ChainReader(f):
            if e["kind"] == "packet.observed":
                yield {k: e["data"][k] for k in EXACT}

def json_rows(path: Path):
    with path.open("rb") as f:
        for line in bounded_lines(f, 65536):
            yield load_json(line)

def first_difference(expected, actual, fields=EXACT) -> dict:
    count = 0
    for count, (a, b) in enumerate(itertools.zip_longest(expected, actual), 1):
        if a is None or b is None:
            return dict(status="FAIL", frame=count, reason="packet_count_disagreement", expected=a, actual=b)
        mismatch = {k: dict(expected=a.get(k), actual=b.get(k)) for k in fields if a.get(k) != b.get(k)}
        if mismatch:
            return dict(status="FAIL", frame=count, reason="first_layer_disagreement", fields=mismatch)
    return dict(status="PASS", compared_packets=count, fields=list(fields))

def tshark_rows(path: Path):
    with path.open("rt", encoding="utf-8") as f:
        for line in f:
            items = line.rstrip("\n").split("\t")
            if len(items) != 4:
                raise InvalidEvidence("unexpected TShark packet row")
            frame, caplen, length, time = items
            ns = Decimal(time) * 1_000_000_000 if time else None
            exact = None if ns is None or ns != ns.to_integral_value() else str(int(ns))
            yield dict(frame=frame, captured_length=int(caplen), original_length=int(length), timestamp_ns=exact)

def compare_capture(capture: Path, directory: Path, binary: str, *, timeout=300,
                    pcap_parser: str | None = None, semantic: bool = False,
                    required: tuple[str, ...] = ("pcap-stream", "tshark")) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    independent = directory / "python.packets.ndjson"
    with capture.open("rb") as source, independent.open("xb") as out:
        for packet in Reader(source).packets():
            out.write(canonical(packet.row()) + b"\n")
    results = {}
    native = run([binary, "analyze", str(capture.resolve()), "--run-id", "differential-v1"], directory, "pcap-stream", timeout=timeout)
    results["pcap-stream"] = native
    if native["status"] == "PASS":
        native["comparison"] = first_difference(json_rows(independent), rust_rows(Path(native["stdout"])))
        native["status"] = native["comparison"]["status"]
    tshark = run(["tshark", "-n", "-r", str(capture.resolve()), "-T", "fields", "-E", "separator=\t",
                  "-e", "frame.number", "-e", "frame.cap_len", "-e", "frame.len", "-e", "frame.time_epoch"], directory, "tshark", timeout=timeout)
    results["tshark"] = tshark
    if tshark["status"] == "PASS":
        tshark["comparison"] = first_difference(json_rows(independent), tshark_rows(Path(tshark["stdout"])), ("frame", "captured_length", "original_length", "timestamp_ns"))
        tshark["status"] = tshark["comparison"]["status"]
    if pcap_parser:
        other = run([pcap_parser, str(capture.resolve())], directory, "pcap-parser", timeout=timeout)
        results["pcap-parser"] = other
        if other["status"] == "PASS":
            other["comparison"] = first_difference(json_rows(independent), json_rows(Path(other["stdout"])), ("frame", "captured_length", "original_length"))
            other["status"] = other["comparison"]["status"]
    if semantic:
        zeek_dir, suri_dir = directory / "zeek-logs", directory / "suricata-logs"
        zeek_dir.mkdir(); suri_dir.mkdir()
        results["zeek"] = run(["zeek", "-Cr", str(capture.resolve()), "LogAscii::use_json=T"], directory, "zeek", timeout=timeout, cwd=zeek_dir.resolve())
        results["suricata"] = run(["suricata", "-r", str(capture.resolve()), "-l", str(suri_dir.resolve()), "--runmode", "single"], directory, "suricata", timeout=timeout)
        for name in ("zeek", "suricata"):
            results[name]["interpretation"] = "execution_only; manual semantic adjudication required; not packet equivalence"
    versions = {}
    for name, cmd in (("pcap-stream", [binary,"--version"]), ("tshark",["tshark","--version"]), ("zeek",["zeek","--version"]), ("suricata",["suricata","--build-info"])):
        if name in results:
            versions[name] = run(cmd, directory, name + "-version", timeout=20, max_log_bytes=1024*1024)
    mandatory = [results.get(name, dict(status="BLOCKED", reason="not_requested")) for name in required]
    status = "FAIL" if any(x["status"] == "FAIL" for x in results.values()) else "BLOCKED" if any(x["status"] == "BLOCKED" for x in mandatory) else "PASS"
    return dict(schema="pcap-evidence.differential.v1", status=status, capture_sha256=digest_file(capture),
                comparisons=results, versions=versions, required=list(required),
                gate="packet boundaries/lengths/time first; then flow/stream/protocol/transaction manually against specifications")

def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("capture", type=Path)
    p.add_argument("output_directory", type=Path)
    p.add_argument("--binary", required=True)
    p.add_argument("--pcap-parser")
    p.add_argument("--semantic", action="store_true")
    p.add_argument("--require", default="pcap-stream,tshark")
    p.add_argument("--timeout", type=float, default=300)
    a = p.parse_args(argv)
    receipt = compare_capture(a.capture, a.output_directory, a.binary, timeout=a.timeout,
                               pcap_parser=a.pcap_parser, semantic=a.semantic, required=tuple(a.require.split(",")))
    (a.output_directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))
    return {"PASS":0,"FAIL":1,"BLOCKED":2}[receipt["status"]]
