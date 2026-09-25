"""Independent Python packet-container oracle; one exact packet row per line."""
from __future__ import annotations
import argparse
from pathlib import Path
from .containers import Reader
from .common import canonical

def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("capture", type=Path)
    p.add_argument("--evidence", action="store_true")
    p.add_argument("--max-packet", type=int, default=1024 * 1024)
    a = p.parse_args(argv)
    with a.capture.open("rb") as f:
        for packet in Reader(f, packet_limit=a.max_packet, evidence=a.evidence).packets():
            print(canonical(packet.row()).decode())
    return 0
