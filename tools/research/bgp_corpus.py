"""Bounded RIPE RIS prefix acquisition for the PR #2 research recipe.

Fetch is explicit; no network request occurs on import. Retained complete records
are a derived source, not an authenticated or complete copy of the parent dump.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import struct
import urllib.request
import zlib

from .contract import InvalidResearch, canonical, digest

COMPRESSED_LIMIT = 256 * 1024
EXPANDED_LIMIT = 2 * 1024 * 1024


def select_records(expanded: bytes, kind: str):
    """Keep the first peer table/two RIB records, or 32 UPDATE-container records."""
    selected, ranges, offset = [], [], 0
    while offset + 12 <= len(expanded):
        _, record_type, subtype, length = struct.unpack_from("!IHHI", expanded, offset)
        end = offset + 12 + length
        if end > len(expanded):
            break
        if kind == "bview" and not selected and (record_type, subtype) != (13, 1):
            raise InvalidResearch("RIB prefix must start with its peer table")
        selected.append(expanded[offset:end])
        ranges.append({"start": offset, "end": end})
        offset = end
        if len(selected) == (3 if kind == "bview" else 32):
            break
    if len(selected) < (3 if kind == "bview" else 32):
        raise InvalidResearch("bounded prefix lacks required complete records")
    return b"".join(selected), ranges


def acquire(output: Path, collector: str, date: str, kind: str):
    if collector not in ("rrc00", "rrc01") or date not in ("20261001", "20261002") or kind not in ("bview", "updates"):
        raise InvalidResearch("source outside the fixed qualification matrix")
    output.mkdir(exist_ok=False)
    url = f"https://data.ris.ripe.net/{collector}/2026.10/{kind}.{date}.0000.gz"
    request = urllib.request.Request(url, headers={"Range": f"bytes=0-{COMPRESSED_LIMIT - 1}", "Accept-Encoding": "identity"})
    started = datetime.now(timezone.utc).isoformat()
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.geturl() != url or response.status not in (200, 206):
            raise InvalidResearch("unexpected acquisition endpoint/status")
        if response.status == 206 and not response.headers.get("Content-Range", "").startswith("bytes 0-"):
            raise InvalidResearch("range response does not start at zero")
        compressed = response.read(COMPRESSED_LIMIT)
        transport = {"status": response.status, "content_length": response.headers.get("Content-Length"),
                     "content_range": response.headers.get("Content-Range")}
    (output / "prefix.gz").write_bytes(compressed)
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    expanded = decoder.decompress(compressed, EXPANDED_LIMIT)
    (output / "expanded-prefix.mrt").write_bytes(expanded)
    source, ranges = select_records(expanded, kind)
    (output / "source.mrt").write_bytes(source)
    receipt = {"url": url, "retrieval_started_utc": started, "retrieval_finished_utc": datetime.now(timezone.utc).isoformat(),
               "transport": transport, "collector": collector, "date_utc": date, "kind": kind,
               "parent_sha256": None, "parent_complete": False, "gzip_trailer_verified": True if decoder.eof else None,
               "compressed": {"bytes": len(compressed), "sha256": digest(compressed)},
               "expanded_prefix": {"bytes": len(expanded), "sha256": digest(expanded)},
               "source": {"bytes": len(source), "sha256": digest(source)}, "expanded_ranges": ranges,
               "selection": "first peer table plus two RIB records" if kind == "bview" else "first 32 complete MRT records",
               "limits": {"compressed_bytes": COMPRESSED_LIMIT, "expanded_bytes": EXPANDED_LIMIT}}
    (output / "acquisition.json").write_bytes(canonical(receipt) + b"\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--collector", required=True, choices=("rrc00", "rrc01"))
    parser.add_argument("--date", required=True, choices=("20261001", "20261002"))
    parser.add_argument("--kind", required=True, choices=("bview", "updates"))
    args = parser.parse_args()
    print(canonical(acquire(args.output, args.collector, args.date, args.kind)).decode())


if __name__ == "__main__":
    main()
