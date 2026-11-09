"""Offline MRT route-field probe using the pinned, optional mrtparse 2.2.0 wheel.

The external parser assesses wire syntax, not negotiated session admission.
No native observations are inputs to this adapter. Commands are provenance only.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import io
import ipaddress
from pathlib import Path
import struct
import sys

from . import bgp_compare as bgp
from .contract import InvalidResearch, canonical

WHEEL_SHA256 = "1672a92950eafb8fb5f6b56fe4c4ce0ebae8ec87de7b1489df7780418c311ca7"
MAX_SOURCE = 16 * 1024 * 1024
MAX_RECORD = 1024 * 1024


def load_decoder(wheel: Path):
    with wheel.open("rb") as source:
        raw = source.read(19117)
    if len(raw) != 19116 or hashlib.sha256(raw).hexdigest() != WHEEL_SHA256:
        raise InvalidResearch("expected pinned mrtparse 2.2.0 wheel")
    if "mrtparse" in sys.modules:
        raise InvalidResearch("mrtparse already loaded; use a fresh adapter process")
    sys.path.insert(0, str(wheel.resolve()))
    try:
        return importlib.import_module("mrtparse")
    finally:
        sys.path.pop(0)


def number(label):
    """mrtparse uses a one-member numeric-to-name dictionary for enumerations."""
    if type(label) is not dict or len(label) != 1:
        raise InvalidResearch("unexpected external enumeration")
    return int(next(iter(label)))


def prefix_row(index, afi, safi, prefix, length, path_id=None):
    address = str(ipaddress.ip_network(f"{prefix}/{length}", strict=False).network_address)
    return {"route_index": str(index), "prefix": {
        "afi": afi, "safi": safi, "length": length, "address": address,
    }, "path_id": path_id}


def fields(decoded):
    """Return one row per RIB entry, or one per other complete MRT record."""
    kind, subtype = number(decoded["type"]), number(decoded["subtype"])
    if kind == 13 and subtype in (2, 3, 4, 5, 8, 9, 10, 11):
        afi = 1 if subtype in (2, 3, 8, 9) else 2
        safi = 1 if subtype in (2, 4, 8, 10) else 2
        return [(i, [{"route_index": "0", "action": "announce"}],
                 [prefix_row(0, afi, safi, decoded["prefix"], decoded["length"], entry.get("path_id"))])
                for i, entry in enumerate(decoded["rib_entries"])] or [(None, None, None)]
    message = decoded.get("bgp_message")
    if kind in (16, 17) and message and number(message["type"]) == 2:
        actions, prefixes = [], []
        def add(action, routes, afi=1, safi=1):
            for route in routes:
                i = len(actions)
                actions.append({"route_index": str(i), "action": action})
                prefixes.append(prefix_row(i, afi, safi, route["prefix"], route["length"], route.get("path_id")))
        add("withdraw", message["withdrawn_routes"])
        multiprotocol = []
        for attribute in message["path_attributes"]:
            code = number(attribute["type"])
            if code not in (14, 15):
                continue
            value = attribute["value"]
            # mrtparse also uses this decoder for abbreviated MRT next hops.
            # A malformed BGP MP_REACH can therefore succeed without a family
            # or NLRI. It supplies no comparable route fields.
            if not all(key in value for key in ("afi", "safi")):
                return [(None, None, None)]
            afi, safi = number(value["afi"]), number(value["safi"])
            routes = value.get("nlri" if code == 14 else "withdrawn_routes")
            if not isinstance(routes, list):
                return [(None, None, None)]
            if afi not in (1, 2) or safi not in (1, 2):
                return [(None, None, None)]
            multiprotocol.append((code, value, afi, safi))
        # The normalized contract orders withdrawals before announcements.
        for code, value, afi, safi in multiprotocol:
            if code == 15:
                add("withdraw", value["withdrawn_routes"], afi, safi)
        add("announce", message["nlri"])
        for code, value, afi, safi in multiprotocol:
            if code == 14:
                add("announce", value["nlri"], afi, safi)
        return [(None, actions, prefixes)]
    return [(None, None, None)]


def interpret(raw: bytes, decoder, *, row_start=0, row_count=128):
    if not 0 < len(raw) <= MAX_SOURCE or row_start < 0 or not 0 < row_count <= 10000:
        raise InvalidResearch("source/partition budget")
    observations, offset, ordinal, output_bytes = [], 0, 0, 0
    while offset < len(raw):
        if len(raw) - offset < 12:
            raise InvalidResearch("short MRT header")
        length = struct.unpack_from("!I", raw, offset + 8)[0] + 12
        if length > MAX_RECORD or length > len(raw) - offset:
            raise InvalidResearch("record budget or truncated source")
        stream = io.BytesIO(raw[offset:offset + length])
        reader = decoder.Reader(stream)
        try:
            item = next(reader)
            projected = [(None, None, None)] if item.err else fields(item.data)
        finally:
            stream.close()
        for entry, actions, prefixes in projected:
            if row_start <= ordinal < row_start + row_count:
                available = actions is not None
                status = "observed" if available else "unknown"
                coverage = "complete" if available else "not_collected"
                row = {"record_offset": str(offset), "source_range": {
                    "kind": "source_range", "start": str(offset), "end": str(offset + length)},
                    "disposition": "unknown", "coverage": {"disposition": "not_collected", "nlri": "partial"},
                    "fields": {"nlri": {
                        "route_actions": {"status": status, "value": actions},
                        "route_prefixes": {"status": status, "value": prefixes}}},
                    "field_coverage": {"nlri": {name: coverage for name in bgp.PER_FIELD_NAMES}}}
                if entry is not None:
                    row["entry_index"] = str(entry)
                output_bytes += len(canonical(row))
                if output_bytes > 4 * 1024 * 1024:
                    raise InvalidResearch("external interpretation budget; narrow partition")
                observations.append(row)
            ordinal += 1
        offset += length
    if not observations:
        raise InvalidResearch("partition outside source")
    config = {"semantic_profile": bgp.NATIVE_PROFILE, "replay_relationship": "unknown"}
    return bgp.validate({"schema": bgp.SCHEMA_V2,
        "source": {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": str(len(raw))},
        "normalization": {"profile": bgp.NORMALIZATION_V2, "config_sha256": hashlib.sha256(canonical(config)).hexdigest()},
        "producer": {"id": "mrtparse", "version": "2.2.0", "adapter_version": "1",
                     "origin": "external_tool", "command": []}, "observations": observations})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--row-start", type=int, default=0)
    parser.add_argument("--row-count", type=int, default=128)
    args = parser.parse_args()
    with args.source.open("rb") as source:
        raw = source.read(MAX_SOURCE + 1)
    print(canonical(interpret(raw, load_decoder(args.wheel), row_start=args.row_start, row_count=args.row_count)).decode())


if __name__ == "__main__":
    main()
