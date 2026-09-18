#!/usr/bin/env python3
"""Deterministic source ZIP and per-file integrity manifest. Never includes target,
.git, caches, real captures outside tests/fixtures, or outputs outside this repo.
Packaging proves byte integrity only, not a successful native build.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile
ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {".git", "target", "__pycache__", ".pytest_cache", "artifacts"}
SOURCE_DIRS = {"src", "tests", "scripts", "docs", "examples", "fuzz", "streaming",
               "corpus", ".github", "evidence"}
ROOT_FILES = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".gitignore", ".gitattributes",
              "README.md", "LICENSE", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md"}
CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap", ".bin"}

def files():
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        # Do not accidentally ship an analysis.json or a private capture placed in
        # the project root by a user running the documented examples.
        if len(relative.parts) == 1 and relative.name not in ROOT_FILES:
            continue
        if len(relative.parts) > 1 and relative.parts[0] not in SOURCE_DIRS:
            continue
        if relative.parts[:2] == ("fuzz", "corpus") or relative.parts[:3] == ("streaming", "fuzz", "corpus"):
            continue
        if path.suffix.lower() in CAPTURE_SUFFIXES and relative.parts[:2] != ("tests", "fixtures"):
            continue
        if path.is_file() and not path.is_symlink() and not (set(relative.parts) & EXCLUDED) and path.suffix not in {".pyc", ".zip"}:
            yield path, relative.as_posix()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=ROOT.parent / "pcap-evidence.zip")
    args = p.parse_args()
    if ROOT == args.output.resolve() or ROOT in args.output.resolve().parents:
        p.error("archive output must be outside the source root")
    manifest = {"schema": "pcap-evidence.source-files.v1", "files": {name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path, name in files() if not name.startswith("evidence/")}}
    (ROOT / "evidence/source-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path, name in files():
            info = zipfile.ZipInfo("pcap-evidence/" + name, date_time=(2026, 9, 16, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    args.output.with_suffix(args.output.suffix + ".sha256").write_text(f"{digest}  {args.output.name}\n")
    with zipfile.ZipFile(args.output) as archive:
        assert archive.testzip() is None
        count = len(archive.infolist())
    print(json.dumps({"archive": str(args.output), "files": count, "bytes": args.output.stat().st_size, "sha256": digest,
                      "native_build_claim": False}, indent=2))

if __name__ == "__main__":
    main()
