#!/usr/bin/env python3
"""Compare product NDJSON and TLV event streams for the Tier-A fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.product.tlv import events as tlv_events


FIXTURES = (
    "dnp3_split_conflict.pcap",
    "dnp3_split_gap.pcap",
    "dnp3_split_valid.pcap",
    "modbus_bits_bad_padding.pcap",
    "modbus_bits_valid.pcap",
    "modbus_fc23_split.pcap",
    "modbus_generation_overlap.pcap",
    "modbus_interleaved.pcap",
    "modbus_partial_same.pcap",
    "modbus_partial_sibling.pcap",
    "modbus_mei_exception_reuse.pcap",
)


def run_product(binary: Path, capture: Path, output: Path, output_format: str, run_id: str) -> None:
    result = subprocess.run(
        [
            str(binary),
            "analyze",
            str(capture),
            "--profile",
            "ics-full",
            "--max-packets", "32",
            "--max-output-bytes", "1048576",
            "--window-bytes", "4096",
            "--format",
            output_format,
            "-o",
            str(output),
            "--run-id",
            run_id,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout)[-4096:]
        raise RuntimeError(f"{output_format} failed for {capture.name}: {detail}")


def read_ndjson(path: Path) -> list[dict]:
    values = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            wrapper = json.loads(line)
            if not isinstance(wrapper, dict) or not isinstance(wrapper.get("event"), dict):
                raise ValueError(f"invalid NDJSON event wrapper in {path}")
            values.append(wrapper["event"])
    return values


def read_tlv(path: Path) -> list[dict]:
    with path.open("rb") as stream:
        return list(tlv_events(stream))


def semantic_event_count(values: list[dict]) -> int:
    count = 0
    for value in values:
        data = value.get("data")
        if not isinstance(data, dict):
            continue
        if "semantic_subset" in data or "object_semantic_subsets" in data:
            count += 1
        if isinstance(data.get("object_semantic_subset"), dict):
            count += 1
    return count


def packet_bytes(capture):
    packets = []
    data = capture.read_bytes()
    offset = 24
    while offset < len(data):
        length = struct.unpack_from('<I', data, offset + 8)[0]
        packets.append(data[offset + 16:offset + 16 + length])
        offset += 16 + length
    return packets


def field_bytes(field, packets):
    raw = bytearray()
    for span in field["evidence"]["spans"]:
        packet = packets[int(span["frame"]) - 1]
        start = int(span["packet_start"])
        raw.extend(packet[start:start + int(span["end"]) - int(span["start"])])
    return raw


def verify_device_objects(events, capture):
    packets = packet_bytes(capture)
    objects = 0
    for event in events:
        subset = event["data"].get("semantic_subset", {})
        for report in subset.get("interpretations", []):
            for record in report["records"]:
                for field in record["fields"]:
                    if field["name"] == "object_value_octet_count":
                        raw = field_bytes(field, packets)
                        if (field["type"] != "unsigned" or field["value"] != str(len(raw))
                                or field["evidence"]["sha256"] != hashlib.sha256(raw).hexdigest()):
                            raise AssertionError("FC43 device object differs from its wire bytes")
                        objects += 1
    if not objects:
        raise AssertionError("missing FC43 device objects")


def verify_split_fc23(events, capture):
    packets = packet_bytes(capture)
    mapping, = [e["data"]["read_mapping"] for e in events if e["kind"] == "transaction.candidate"]
    if (mapping["starting_address_zero_based"], mapping["quantity"]) != (0xabcd, 2):
        raise AssertionError("FC23 read mapping differs from the wire request")
    by_id = {e["sequence"]: e for e in events}
    for role, name, expected, frames in [
        ("request", "read_start_zero_based", b"\xab\xcd", [4, 5]),
        ("response", "register_u16", b"\x12\x34", [6, 7]),
    ]:
        message = by_id[mapping[role]]["data"]
        if message["role"] != role:
            raise AssertionError(f"FC23 mapping references the wrong {role}")
        report, = message["semantic_subset"]["interpretations"]
        field = next(f for rec in report["records"] for f in rec["fields"] if f["name"] == name)
        spans = field["evidence"]["spans"]
        raw = field_bytes(field, packets)
        if ([int(s["frame"]) for s in spans] != frames or raw != expected
                or int(field["value"]) != int.from_bytes(expected, "big")):
            raise AssertionError(f"FC23 {name} differs from its packet witnesses")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    binary = args.binary.resolve()
    if sys.platform == "win32" and binary.suffix.lower() != ".exe":
        binary = binary.with_suffix(".exe")
    if not binary.is_file():
        raise FileNotFoundError(f"product binary unavailable: {binary}")

    fixture_root = ROOT / "fixtures" / "semantics"
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    validator = Draft202012Validator(json.loads((ROOT / "docs/semantics/semantic.schema.json").read_text()))
    results = []
    for fixture_name in FIXTURES:
        capture = fixture_root / fixture_name
        run_id = f"semantic-parity-{capture.stem}"
        ndjson_path = output_dir / f"{capture.stem}.ndjson"
        tlv_path = output_dir / f"{capture.stem}.tlv"
        run_product(binary, capture, ndjson_path, "ndjson", run_id)
        run_product(binary, capture, tlv_path, "tlv", run_id)
        ndjson = read_ndjson(ndjson_path)
        tlv = read_tlv(tlv_path)
        if ndjson != tlv:
            for index, (left, right) in enumerate(zip(ndjson, tlv), 1):
                if left != right:
                    raise AssertionError(f"{capture.name}: event {index} differs between NDJSON and TLV")
            raise AssertionError(f"{capture.name}: event counts differ")
        if not ndjson or ndjson[-1].get("kind") != "capture.complete":
            raise AssertionError(f"{capture.name}: missing terminal capture event")
        if ndjson[-1]["data"].get("source_sha256") != hashlib.sha256(capture.read_bytes()).hexdigest():
            raise AssertionError(f"{capture.name}: incorrect source hash")
        for event in ndjson:
            if "semantic_subset" in event["data"]:
                validator.validate(event["data"]["semantic_subset"])
        if fixture_name == "modbus_fc23_split.pcap":
            verify_split_fc23(ndjson, capture)
        if fixture_name == "modbus_interleaved.pcap":
            verify_device_objects(ndjson, capture)
        results.append(
            {
                "fixture": fixture_name,
                "events": len(ndjson),
                "semantic_events": semantic_event_count(ndjson),
                "ndjson_bytes": ndjson_path.stat().st_size,
                "tlv_bytes": tlv_path.stat().st_size,
            }
        )

    if not any(item["semantic_events"] for item in results):
        raise AssertionError("no semantic event was observed in the fixture set")
    print(json.dumps({"status": "PASS", "fixtures": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}))
        raise SystemExit(1)
