"""Opt-in, hash-pinned corpus fetching; never automatically fetches captures.

The bundled manifest is navigation to upstream fixtures, not a claim that each
upstream fixture is a real production recording or freely relicensable. No third
party packet bytes are redistributed by this handoff.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
import urllib.request
import urllib.parse
from .common import InvalidEvidence, digest_file, digest_hex, publish_new, load_json

ALLOWED_HOSTS = {"raw.githubusercontent.com", "gitlab.com", "www.wireshark.org", "wiki.wireshark.org"}

def validate_url(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS or u.username or u.password or u.port not in (None, 443):
        raise InvalidEvidence("corpus URLs must use an approved HTTPS upstream host without credentials")
    return url

class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def destination(root: Path, name: str) -> Path:
    p = PurePosixPath(name)
    if p.is_absolute() or not p.parts or ".." in p.parts or "\\" in name:
        raise InvalidEvidence("unsafe corpus path")
    target = root.joinpath(*p.parts)
    if root.resolve() not in target.resolve().parents:
        raise InvalidEvidence("corpus path escapes root")
    if any(x.is_symlink() for x in (target, *target.parents) if x != root.parent):
        raise InvalidEvidence("symlink in corpus destination")
    return target

def entries(path: Path) -> list[dict]:
    manifest = load_json(path.read_bytes())
    if manifest.get("schema") != "pcap-evidence.corpus.v1" or not isinstance(manifest.get("entries"), list):
        raise InvalidEvidence("unsupported corpus manifest")
    seen = set()
    for e in manifest["entries"]:
        if e["name"] in seen:
            raise InvalidEvidence("duplicate corpus name")
        seen.add(e["name"])
        validate_url(e["url"])
        digest_hex(e["sha256"])
        if type(e["size"]) is not int or not 0 < e["size"] <= 64 * 1024 * 1024:
            raise InvalidEvidence("invalid or excessive corpus entry size")
        if not e.get("upstream_license_review_required"):
            raise InvalidEvidence("explicit third-party license review declaration required")
    return manifest["entries"]

def verify_entry(path: Path, entry: dict) -> dict:
    if not path.is_file():
        return dict(name=entry["name"], status="BLOCKED", reason="capture_not_fetched")
    if path.stat().st_size != entry["size"] or digest_file(path) != entry["sha256"]:
        raise InvalidEvidence(f"corpus bytes changed: {entry['name']}")
    if "git_blob_sha1" in entry:
        h = hashlib.sha1(b"blob " + str(entry["size"]).encode() + b"\0")
        with path.open("rb") as f:
            for b in iter(lambda: f.read(1024 * 1024), b""):
                h.update(b)
        if h.hexdigest() != entry["git_blob_sha1"]:
            raise InvalidEvidence("Git blob identity disagrees with corpus pin")
    return dict(name=entry["name"], status="PASS", verification="exact_source_bytes", sha256=entry["sha256"])

def fetch_entry(root: Path, entry: dict) -> dict:
    target = destination(root, entry["name"])
    if target.exists():
        return verify_entry(target, entry)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".corpus-", dir=target.parent)
    temp = Path(name)
    try:
        opener = urllib.request.build_opener(SafeRedirect())
        request = urllib.request.Request(validate_url(entry["url"]), headers={"User-Agent": "pcap-evidence-corpus/1"})
        with os.fdopen(fd, "wb") as out, opener.open(request, timeout=30) as remote:
            count = 0
            while True:
                b = remote.read(min(65536, entry["size"] - count + 1))
                if not b:
                    break
                count += len(b)
                if count > entry["size"]:
                    raise InvalidEvidence("upstream response exceeds pinned length")
                out.write(b)
        verify_entry(temp, entry)
        publish_new(temp, target)
        return verify_entry(target, entry)
    finally:
        temp.unlink(missing_ok=True)

def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["verify", "fetch"])
    p.add_argument("manifest", type=Path)
    p.add_argument("directory", type=Path)
    p.add_argument("--allow-network", action="store_true")
    a = p.parse_args(argv)
    if a.action == "fetch" and not a.allow_network:
        p.error("fetch requires explicit --allow-network and your authorization to use upstream captures")
    results = []
    for e in entries(a.manifest):
        result = fetch_entry(a.directory, e) if a.action == "fetch" else verify_entry(destination(a.directory, e["name"]), e)
        results.append(result)
    print(json.dumps(dict(status="BLOCKED" if any(x["status"] == "BLOCKED" for x in results) else "PASS", entries=results), indent=2))
    return 2 if any(x["status"] == "BLOCKED" for x in results) else 0
