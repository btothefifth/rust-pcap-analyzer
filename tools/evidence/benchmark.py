"""Opt-in workload generator and bounded-output process benchmark.

No throughput extrapolation, multi-hundred-GB qualification, or aggregate RAM
claim follows from a small synthetic run. Record capture mix and event-output
costs. Process log growth is polled, not a hard OS disk or CPU sandbox.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
from .common import digest_file, publish_new
from .process import run


def checksum(data: bytes) -> int:
    data += bytes(len(data) % 2)
    value = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def dns_packet(identifier: int, key: int) -> bytes:
    dns = struct.pack("!6H", identifier & 65535, 0x100, 1, 0, 0, 0) + b"\x07example\x04test\x00\x00\x01\x00\x01"
    udp = struct.pack("!4H", 10000 + key % 50000, 53535, 8 + len(dns), 0) + dns
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), identifier & 65535, 0, 64, 17, 0,
                               bytes([10, 0, (key >> 8) & 255, key & 255]), bytes([10, 255, 255, 254])))
    struct.pack_into("!H", ip, 10, checksum(bytes(ip)))
    return bytes(12) + b"\x08\x00" + ip + udp


def generate(path: Path, packets: int, keys: int = 1024) -> dict:
    if packets < 0 or not 1 <= keys <= 65536:
        raise ValueError("nonnegative packet count and 1..65536 keys required")
    if path.exists():
        raise FileExistsError(path)
    packet_len = len(dns_packet(0, 0))
    estimated = 24 + packets * (16 + packet_len)
    if shutil.disk_usage(path.parent).free < estimated + 1024*1024:
        raise OSError("insufficient free disk for requested synthetic capture")
    fd, name = tempfile.mkstemp(prefix=".benchmark-", dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, "wb", buffering=1024*1024) as out:
            out.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i in range(packets):
                b = dns_packet(i, i % keys)
                out.write(struct.pack("<IIII", 1_700_000_000 + i // 1_000_000, i % 1_000_000, len(b), len(b)))
                out.write(b)
        publish_new(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    return dict(status="PASS", kind="synthetic_dns_udp_nonstandard_port", packets=packets, keys=keys,
                source_bytes=path.stat().st_size, source_sha256=digest_file(path), representative_production_mix=False)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    g = sub.add_parser("generate"); g.add_argument("capture", type=Path); g.add_argument("--packets", type=int, required=True); g.add_argument("--keys", type=int, default=1024)
    r = sub.add_parser("run"); r.add_argument("capture", type=Path); r.add_argument("directory", type=Path); r.add_argument("--binary", required=True); r.add_argument("--timeout", type=float, default=3600); r.add_argument("--max-output-bytes", type=int, default=1024*1024*1024)
    a = p.parse_args(argv)
    if a.action == "generate":
        receipt = generate(a.capture, a.packets, a.keys)
    else:
        a.directory.mkdir(parents=True, exist_ok=False)
        receipt = run([a.binary, "analyze", str(a.capture.resolve()), "--run-id", "benchmark-v1"], a.directory, "analyze", timeout=a.timeout, max_log_bytes=a.max_output_bytes)
        receipt.update(source_bytes=a.capture.stat().st_size, source_sha256=digest_file(a.capture),
                       measured_scope="single capture and local environment", rss_measured=False,
                       throughput_extrapolation_permitted=False)
        if receipt["status"] == "PASS" and receipt["elapsed_seconds"] > 0:
            receipt["input_mib_per_second"] = round(a.capture.stat().st_size / 1048576 / receipt["elapsed_seconds"], 6)
        (a.directory / "benchmark.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))
    return {"PASS":0,"FAIL":1,"BLOCKED":2}[receipt["status"]]
