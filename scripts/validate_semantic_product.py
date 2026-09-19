#!/usr/bin/env python3
"""Compare product NDJSON and TLV event streams for the Tier-A fixtures."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.product.tlv import events as tlv_events


FIXTURES = (
    "dnp3_split_conflict.pcap",
    "dnp3_split_gap.pcap",
    "dnp3_split_valid.pcap",
    "modbus_bits_bad_padding.pcap",
    "modbus_bits_valid.pcap",
)


def run_product(binary: Path, capture: Path, output: Path, output_format: str, run_id: str) -> None:
    result = subprocess.run(
        [
            str(binary),
            "analyze",
            str(capture),
            "--profile",
            "ics-full",
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
