"""Disk-backed source-bound evidence index, streaming queries, and replay verification.

A self-hash is NOT a trust boundary. `build` checks bytes/links; only `verify`
regenerates the canonical analysis with a trusted executable and compares every
stored projection. A receipt does not make a subsequently mutable database trusted.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from typing import Any, BinaryIO, Iterator
from .common import (InvalidEvidence, bounded_lines, canonical, digest_file, digest_hex,
                     load_json, publish_new, signed, small_int, time_key, unsigned)

DOMAIN = b"pcap-evidence/event/v1\0"
SCHEMA_ID = "pcap-evidence.analytics.v1"
SCHEMA = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE events(seq TEXT PRIMARY KEY, seq_sort TEXT NOT NULL UNIQUE,
 kind TEXT NOT NULL, status TEXT NOT NULL, session TEXT, direction INTEGER, protocol TEXT,
 previous_sha256 TEXT NOT NULL, event_sha256 TEXT NOT NULL, body TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE packets(frame TEXT PRIMARY KEY, frame_sort TEXT NOT NULL UNIQUE,
 record_offset TEXT NOT NULL, data_offset TEXT NOT NULL, caplen INTEGER NOT NULL,
 original_length INTEGER NOT NULL, link_type INTEGER NOT NULL, section INTEGER NOT NULL,
 interface INTEGER NOT NULL, sha256 TEXT NOT NULL, timestamp_ns TEXT, ts_sort TEXT,
 raw_timestamp TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE sessions(session TEXT PRIMARY KEY, transport TEXT, source_ip TEXT,
 source_port INTEGER, destination_ip TEXT, destination_port INTEGER, key_json TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE event_packets(seq TEXT NOT NULL REFERENCES events(seq),
 frame TEXT NOT NULL REFERENCES packets(frame), PRIMARY KEY(seq,frame)) WITHOUT ROWID;
CREATE TABLE spans(seq TEXT NOT NULL REFERENCES events(seq), ordinal INTEGER NOT NULL,
 frame TEXT NOT NULL REFERENCES packets(frame), packet_start INTEGER NOT NULL,
 start INTEGER NOT NULL, end INTEGER NOT NULL, PRIMARY KEY(seq,ordinal)) WITHOUT ROWID;
CREATE TABLE relations(seq TEXT NOT NULL REFERENCES events(seq),
 target TEXT NOT NULL REFERENCES events(seq), PRIMARY KEY(seq,target)) WITHOUT ROWID;
CREATE TABLE facts(seq TEXT NOT NULL REFERENCES events(seq), key TEXT NOT NULL,
 value TEXT NOT NULL, PRIMARY KEY(seq,key,value)) WITHOUT ROWID;
CREATE TABLE stream_constraints(seq TEXT PRIMARY KEY REFERENCES events(seq), session TEXT,
 direction INTEGER, start TEXT NOT NULL, end TEXT NOT NULL, reason TEXT NOT NULL) WITHOUT ROWID;
CREATE INDEX packets_time ON packets(ts_sort,frame);
CREATE INDEX packets_source_offset ON packets(data_offset);
CREATE INDEX events_protocol ON events(protocol,seq_sort);
CREATE INDEX events_session ON events(session,seq_sort);
CREATE INDEX events_kind ON events(kind,seq_sort);
CREATE INDEX event_packets_frame ON event_packets(frame,seq);
CREATE INDEX sessions_source ON sessions(source_ip,source_port,session);
CREATE INDEX sessions_destination ON sessions(destination_ip,destination_port,session);
CREATE INDEX facts_lookup ON facts(key,value,seq);
CREATE INDEX constraints_scope ON stream_constraints(session,direction);
"""
TABLE_KEYS = {
    "meta": "key", "events": "seq_sort", "packets": "frame_sort", "sessions": "session",
    "event_packets": "seq,frame", "spans": "seq,ordinal", "relations": "seq,target",
    "facts": "seq,key,value", "stream_constraints": "seq",
}

class ChainReader:
    def __init__(self, file: BinaryIO, max_line: int = 8 * 1024 * 1024):
        self.file, self.max_line = file, max_line
        self.start: dict | None = None
        self.complete: dict | None = None
        self.count = 0
        self.previous = bytes(32)
        self.run_id: str | None = None

    def __iter__(self) -> Iterator[tuple[dict, dict]]:
        for line in bounded_lines(self.file, self.max_line):
            if self.complete is not None:
                raise InvalidEvidence("events after capture.complete")
            wrapper = load_json(line)
            if type(wrapper) is not dict or set(wrapper) != {"event", "previous_sha256", "event_sha256"}:
                raise InvalidEvidence("invalid hash-chain wrapper")
            event = wrapper["event"]
            if type(event) is not dict or event.get("schema") != "pcap-evidence.event.v1":
                raise InvalidEvidence("unsupported event schema")
            if digest_hex(wrapper["previous_sha256"]) != self.previous:
                raise InvalidEvidence("broken previous-event link")
            encoded = canonical(event)
            digest = hashlib.sha256(DOMAIN + self.previous + encoded).digest()
            if digest_hex(wrapper["event_sha256"]) != digest:
                raise InvalidEvidence("event digest mismatch")
            if canonical(wrapper) + b"\n" != line:
                raise InvalidEvidence("noncanonical event encoding")
            self.count += 1
            if unsigned(event.get("sequence")) != self.count:
                raise InvalidEvidence("noncontiguous event sequence")
            run = event.get("run_id")
            if not isinstance(run, str) or not 1 <= len(run.encode()) <= 128 or any(ord(c) < 32 for c in run):
                raise InvalidEvidence("invalid run ID")
            if self.count == 1:
                if event.get("kind") != "capture.start":
                    raise InvalidEvidence("missing capture.start")
                self.run_id, self.start = run, event
            elif run != self.run_id or event.get("kind") == "capture.start":
                raise InvalidEvidence("mixed runs or duplicate start")
            if event.get("kind") == "capture.aborted":
                raise InvalidEvidence("aborted analysis cannot create a completed index")
            if event.get("kind") == "capture.complete":
                self.complete = event
                if unsigned(event["data"]["events"]) != self.count:
                    raise InvalidEvidence("completion event count mismatch")
            self.previous = digest
            yield wrapper, event
        if self.complete is None:
            raise InvalidEvidence("missing capture.complete; source binding is provisional")


def schema_rows(db: sqlite3.Connection) -> list[tuple]:
    return list(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"))


def connect_read(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 32 * 1024 * 1024)
    db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 1024 * 1024)
    db.execute("PRAGMA query_only=ON")
    db.execute("PRAGMA trusted_schema=OFF")
    db.execute("PRAGMA cache_size=-16384")
    db.execute("PRAGMA mmap_size=0")
    reference = sqlite3.connect(":memory:")
    try:
        reference.executescript(SCHEMA)
        if schema_rows(db) != schema_rows(reference):
            db.close()
            raise InvalidEvidence("unexpected index schema, views, triggers, or indexes")
    finally:
        reference.close()
    return db


def _meta(db: sqlite3.Connection, key: str, value: Any) -> None:
    db.execute("INSERT INTO meta VALUES (?,?)", (key, canonical(value).decode()))


def read_meta(db: sqlite3.Connection) -> dict:
    return {k: load_json(v) for k, v in db.execute("SELECT key,value FROM meta")}


def packet_at(file: BinaryIO, offset: int, count: int) -> bytes:
    file.seek(offset)
    data = file.read(count)
    if len(data) != count:
        raise InvalidEvidence("indexed packet range exceeds source")
    return data


def primitive_facts(data: Any, prefix: str = "", depth: int = 0) -> Iterator[tuple[str, str]]:
    if depth > 8:
        return
    if type(data) is dict:
        for key, value in data.items():
            if isinstance(key, str) and len(key) <= 128:
                yield from primitive_facts(value, f"{prefix}.{key}".lstrip("."), depth + 1)
    elif type(data) is list:
        for value in data:
            yield from primitive_facts(value, prefix, depth + 1)
    elif isinstance(data, (str, int, bool)) and prefix:
        value = data if isinstance(data, str) else json.dumps(data)
        yield prefix, value


def _project(db: sqlite3.Connection, wrapper: dict, e: dict, source: BinaryIO | None,
             source_size: int | None, frame_count: int) -> tuple[int, int]:
    seq = e["sequence"]
    kind, status, session, direction, protocol = (e.get(k) for k in ("kind", "status", "session", "direction", "protocol"))
    if not isinstance(kind, str) or status not in {"observed", "candidate", "ambiguous", "incomplete", "unsupported", "rejected"}:
        raise InvalidEvidence("invalid event kind/status")
    if session is not None:
        unsigned(session)
    if direction is not None:
        small_int(direction, 1)
    if protocol is not None and (not isinstance(protocol, str) or len(protocol) > 128):
        raise InvalidEvidence("invalid protocol identifier")
    db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)",
               (seq, f"{int(seq):020d}", kind, status, session, direction, protocol,
                wrapper["previous_sha256"], wrapper["event_sha256"], canonical(e).decode()))
    data = e.get("data")
    if not isinstance(data, dict):
        raise InvalidEvidence("event.data must be an object")
    if kind == "packet.observed":
        frame = data["frame"]
        if unsigned(frame) != frame_count + 1:
            raise InvalidEvidence("noncontiguous packet ordinals")
        record_offset, offset = unsigned(data["record_offset"]), unsigned(data["data_offset"])
        cap = small_int(data["captured_length"])
        if cap > 16 * 1024 * 1024 or offset < record_offset or offset + cap >= 1 << 64:
            raise InvalidEvidence("invalid/oversized packet extent")
        expected = digest_hex(data["packet_sha256"])
        if source_size is not None and offset + cap > source_size:
            raise InvalidEvidence("packet outside supplied source")
        if source is not None and hashlib.sha256(packet_at(source, offset, cap)).digest() != expected:
            raise InvalidEvidence("packet bytes disagree with source")
        ns = data.get("timestamp_ns")
        db.execute("INSERT INTO packets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            frame, f"{int(frame):020d}", str(record_offset), str(offset), cap,
            small_int(data["original_length"]), small_int(data["link_type"]),
            small_int(data["section"]), small_int(data["interface"]), expected.hex(),
            ns, time_key(ns), canonical(data.get("raw_timestamp")).decode(),
        ))
        frame_count += 1
    if kind == "flow.start":
        if session is None:
            raise InvalidEvidence("flow.start without session ID")
        key = data["key"]
        db.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?,?)", (
            session, key["transport"], key["source_ip"], small_int(key["source_port"], 65535),
            key["destination_ip"], small_int(key["destination_port"], 65535), canonical(key).decode(),
        ))
    evidence = e.get("evidence")
    if type(evidence) is not dict:
        raise InvalidEvidence("missing typed evidence")
    refs = evidence.get("packets")
    spans = evidence.get("spans")
    if not isinstance(refs, list) or not isinstance(spans, list) or len(refs) > 100_000 or len(spans) > 100_000:
        raise InvalidEvidence("invalid/excessive evidence references")
    frame_set = set()
    for ref in refs:
        frame = ref["frame"]
        unsigned(frame)
        row = db.execute("SELECT record_offset FROM packets WHERE frame=?", (frame,)).fetchone()
        if row is None or row[0] != ref["record_offset"] or frame in frame_set:
            raise InvalidEvidence("invalid or duplicate packet reference")
        frame_set.add(frame)
        db.execute("INSERT INTO event_packets VALUES (?,?)", (seq, frame))
    length = unsigned(evidence.get("byte_length"))
    if length > 16 * 1024 * 1024:
        raise InvalidEvidence("evidence byte budget exceeded")
    cursor = 0
    reconstructed = hashlib.sha256()
    for ordinal, span in enumerate(spans):
        frame = span["frame"]
        start, end, local = (unsigned(span[k]) for k in ("start", "end", "packet_start"))
        if frame not in frame_set or start != cursor or end <= start or end > length:
            raise InvalidEvidence("noncontiguous or unreferenced source span")
        row = db.execute("SELECT record_offset,data_offset,caplen FROM packets WHERE frame=?", (frame,)).fetchone()
        if row is None or row[0] != span["record_offset"] or local + end - start > row[2]:
            raise InvalidEvidence("span exceeds its source packet")
        if source is not None:
            reconstructed.update(packet_at(source, int(row[1]) + local, end - start))
        db.execute("INSERT INTO spans VALUES (?,?,?,?,?,?)", (seq, ordinal, frame, local, start, end))
        cursor = end
    if cursor != length:
        raise InvalidEvidence("spans do not cover reconstructed bytes")
    hashed = evidence.get("reconstructed_sha256")
    if hashed is not None:
        expected = digest_hex(hashed)
        if source is not None and reconstructed.digest() != expected:
            raise InvalidEvidence("reconstructed bytes do not match source spans")
    elif length:
        raise InvalidEvidence("nonempty evidence missing reconstructed hash")
    related = e.get("related_events", [])
    if not isinstance(related, list) or len(related) > 100_000:
        raise InvalidEvidence("invalid relationship list")
    for target in dict.fromkeys(related):
        if unsigned(target) >= int(seq):
            raise InvalidEvidence("forward or self event relationship")
        db.execute("INSERT INTO relations VALUES (?,?)", (seq, target))
        db.execute("INSERT OR IGNORE INTO event_packets SELECT ?,frame FROM event_packets WHERE seq=?", (seq, target))
    interval = e.get("stream_range")
    if interval is not None:
        start, end = signed(interval["start"], 64), signed(interval["end"], 64)
        if start > end:
            raise InvalidEvidence("inverted stream range")
        if kind in {"stream.gap", "stream.conflict"}:
            db.execute("INSERT INTO stream_constraints VALUES (?,?,?,?,?,?)",
                       (seq, session, direction, str(start), str(end), str(data.get("reason", data.get("policy", "")))))
    omitted = 0
    if kind == "protocol.message":
        for count, (key, value) in enumerate(primitive_facts(data)):
            if count >= 256 or len(key) > 512 or len(value.encode()) > 2048:
                omitted += 1
                continue
            db.execute("INSERT OR IGNORE INTO facts VALUES (?,?,?)", (seq, key, value))
        if protocol == "http1":
            for header in data.get("headers", []):
                value = header.get("value", {}).get("text")
                if isinstance(value, str) and len(value.encode()) <= 2048:
                    db.execute("INSERT OR IGNORE INTO facts VALUES (?,?,?)", (seq, "http." + header["name"], value))
    return frame_count, omitted


def build(log: BinaryIO, destination: Path, *, source: Path | None,
          max_line: int = 8 * 1024 * 1024, max_disk: int | None = None) -> dict:
    destination = destination.resolve()
    if destination.exists():
        raise FileExistsError(destination)
    fd, filename = tempfile.mkstemp(prefix=".evidence-index-", suffix=".sqlite", dir=destination.parent)
    os.close(fd)
    temp = Path(filename)
    db = sqlite3.connect(temp)
    capture = source.open("rb") if source is not None else None
    source_size = os.fstat(capture.fileno()).st_size if capture is not None else None
    reader = ChainReader(log, max_line)
    count = omitted = 0
    try:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA temp_store=FILE")
        db.execute("PRAGMA cache_size=-16384")
        db.execute("PRAGMA mmap_size=0")
        db.executescript(SCHEMA)
        for wrapper, event in reader:
            count, missed = _project(db, wrapper, event, capture, source_size, count)
            omitted += missed
            if reader.count % 1000 == 0:
                db.commit()
                if max_disk is not None:
                    used = sum(p.stat().st_size for p in (temp, Path(str(temp) + "-wal")) if p.exists())
                    if used > max_disk:
                        raise InvalidEvidence("index disk budget exceeded")
        if reader.start is None or reader.complete is None:
            raise InvalidEvidence("missing start or completion binding")
        final = reader.complete["data"]
        if unsigned(final["packets"]) != count:
            raise InvalidEvidence("completion packet count mismatch")
        expected_source = digest_hex(final["source_sha256"]).hex()
        if source is not None and (source.stat().st_size != unsigned(final["source_bytes"]) or digest_file(source) != expected_source):
            raise InvalidEvidence("source identity mismatch")
        config = reader.start["data"]["config"]
        metadata = dict(schema=SCHEMA_ID, run_id=reader.run_id, source_sha256=expected_source,
                        source_bytes=final["source_bytes"], events=str(reader.count), packets=str(count),
                        terminal_event_sha256=reader.previous.hex(), config=config,
                        config_sha256=hashlib.sha256(canonical(config)).hexdigest(),
                        implementation=reader.start["data"]["implementation"],
                        verification="source_bytes_and_spans_checked" if source else "event_chain_only",
                        semantic_replay_verified=False, metadata_values_not_indexed=omitted)
        for key, value in metadata.items():
            _meta(db, key, value)
        db.commit()
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        if list(db.execute("PRAGMA foreign_key_check")):
            raise InvalidEvidence("unresolved event references")
        db.close()
        if max_disk is not None and temp.stat().st_size > max_disk:
            raise InvalidEvidence("index disk budget exceeded")
        publish_new(temp, destination)
        return metadata
    finally:
        if capture is not None:
            capture.close()
        try:
            db.close()
        except sqlite3.Error:
            pass
        for suffix in ("", "-wal", "-shm"):
            Path(str(temp) + suffix).unlink(missing_ok=True)


def replay_args(config: dict, source: Path, run_id: str) -> list[str]:
    args = ["analyze", str(source.resolve()), "--run-id", run_id]
    options = {
        "max_active_keys": "active-flows", "max_active_payload": "active-bytes",
        "window_payload": "window-bytes", "window_packets": "window-packets",
        "idle_frames": "idle-frames", "max_tunnel_contexts": "tunnel-contexts",
        "max_tunnel_depth": "tunnel-depth", "fragment_payload": "fragment-bytes",
        "max_event_bytes": "event-bytes", "max_plugin_bytes": "plugin-bytes",
        "max_plugin_events": "plugin-events", "max_probe_bytes": "probe-bytes",
        "max_source_bytes": "source-bytes", "max_detectors": "detectors",
        "idle_timeout_ns": "idle-ns",
    }
    for key, option in options.items():
        value = config[key]
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise InvalidEvidence("invalid replay configuration")
        args += ["--" + option, str(value)]
    limits = {
        "max_block_bytes": "block-bytes", "max_packet_bytes": "packet-bytes",
        "max_interfaces": "interfaces", "max_options": "options", "max_stream_span": "stream-span",
        "max_fragment_sets": "fragment-sets", "max_fragments_per_set": "fragments-per-set",
        "fragment_frame_lifetime": "fragment-lifetime", "max_protocol_messages": "native-messages",
        "max_application_bytes": "application-bytes", "max_correlation_checks": "correlation-checks",
    }
    for key, option in limits.items():
        args += ["--" + option, str(config["container_limits"][key])]
    overlap = {"reject_conflict": "reject", "first_observed": "first", "last_observed": "last"}
    args += ["--overlap", overlap[config["overlap"]]]
    for key, option in (("dnp3_ports", "dnp3-port"), ("modbus_ports", "modbus-port")):
        ports = config[key]
        if not isinstance(ports, list) or not ports:
            raise InvalidEvidence("CLI replay currently requires nonempty configured port lists")
        args += ["--" + option, ",".join(str(small_int(p, 65535)) for p in ports)]
    for enabled, option in ((config["include_payload"], "include-payload"),
                            (config["allow_port_hints"], "allow-port-hints"),
                            (config["parse_mode"] == "evidence", "evidence"),
                            (config["checksums"] == "RequireValid", "strict-checksums")):
        if enabled:
            args.append("--" + option)
    return args


def verify(database: Path, source: Path, binary: Path, *, timeout: float = 3600,
           expected_config_sha256: str | None = None) -> dict:
    db = connect_read(database)
    try:
        meta = read_meta(db)
        if expected_config_sha256 is not None and meta["config_sha256"] != expected_config_sha256:
            raise InvalidEvidence("configuration is not the caller's trusted policy")
        if digest_file(source) != meta["source_sha256"]:
            raise InvalidEvidence("source digest mismatch")
        if not binary.is_file():
            raise FileNotFoundError(f"trusted replay executable unavailable: {binary}")
        with tempfile.TemporaryDirectory(prefix="pcap-index-replay-") as directory:
            directory = Path(directory)
            log, errors, rebuilt = (directory / name for name in ("events.ndjson", "stderr.txt", "rebuilt.sqlite"))
            with log.open("wb") as output, errors.open("wb") as stderr:
                run = subprocess.run([str(binary.resolve()), *replay_args(meta["config"], source, meta["run_id"])],
                                     stdout=output, stderr=stderr, timeout=timeout, check=False)
            if run.returncode != 0:
                with errors.open("rt", errors="replace") as detail_file:
                    detail = detail_file.read(4096)
                raise InvalidEvidence(f"canonical replay failed ({run.returncode}): {detail}")
            with log.open("rb") as stream:
                build(stream, rebuilt, source=source, max_line=small_int(meta["config"]["max_event_bytes"]))
            other = connect_read(rebuilt)
            try:
                    for table, order in TABLE_KEYS.items():
                        # Iterating cursors, not fetchall: even whole-database comparison is bounded.
                        left = db.execute(f"SELECT * FROM {table} ORDER BY {order}")
                        right = other.execute(f"SELECT * FROM {table} ORDER BY {order}")
                        try:
                            while True:
                                a, b = left.fetchone(), right.fetchone()
                                if a != b:
                                    raise InvalidEvidence(f"canonical replay disagrees with index table {table}")
                                if a is None:
                                    break
                        finally:
                            # Explicitly release cursors before Windows removes the
                            # rebuilt database from the temporary replay directory.
                            left.close()
                            right.close()
            finally:
                other.close()
        return dict(status="PASS", verification="source_and_canonical_replay_and_all_projections",
                    source_sha256=meta["source_sha256"], config_sha256=meta["config_sha256"],
                    binary_sha256=digest_file(binary), events=meta["events"], packets=meta["packets"])
    finally:
        db.close()


def query(database: Path, *, protocol: str | None = None, session: str | None = None,
          ip: str | None = None, port: int | None = None, start_ns: str | None = None,
          end_ns: str | None = None, metadata: tuple[str, str] | None = None,
          kind: str | None = None, limit: int = 100) -> Iterator[dict]:
    if not 1 <= limit <= 1_000_000:
        raise ValueError("limit must be 1..1000000")
    if start_ns is not None and end_ns is not None and signed(start_ns) > signed(end_ns):
        raise ValueError("inverted time range")
    conditions, values = [], []
    for name, value in (("protocol", protocol), ("session", session), ("kind", kind)):
        if value is not None:
            conditions.append(f"e.{name}=?")
            values.append(value)
    if ip is not None or port is not None:
        sides, params = [], []
        for side in ("source", "destination"):
            clauses = ["s.session=e.session"]
            if ip is not None:
                clauses.append(f"s.{side}_ip=?")
                params.append(ip)
            if port is not None:
                clauses.append(f"s.{side}_port=?")
                params.append(small_int(port, 65535))
            sides.append("(" + " AND ".join(clauses) + ")")
        conditions.append("EXISTS(SELECT 1 FROM sessions s WHERE " + " OR ".join(sides) + ")")
        values.extend(params)
    if start_ns is not None or end_ns is not None:
        clauses = ["ep.seq=e.seq", "p.frame=ep.frame", "p.ts_sort IS NOT NULL"]
        if start_ns is not None:
            clauses.append("p.ts_sort>=?")
            values.append(time_key(start_ns))
        if end_ns is not None:
            clauses.append("p.ts_sort<=?")
            values.append(time_key(end_ns))
        conditions.append("EXISTS(SELECT 1 FROM event_packets ep JOIN packets p ON p.frame=ep.frame WHERE " + " AND ".join(clauses) + ")")
    if metadata is not None:
        conditions.append("EXISTS(SELECT 1 FROM facts f WHERE f.seq=e.seq AND f.key=? AND f.value=?)")
        values.extend(metadata)
    sql = "SELECT e.body FROM events e" + (" WHERE " + " AND ".join(conditions) if conditions else "") + " ORDER BY e.seq_sort LIMIT ?"
    values.append(limit)
    db = connect_read(database)
    try:
        for (body,) in db.execute(sql, values):
            yield load_json(body)
    finally:
        db.close()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("build")
    p.add_argument("events", help="NDJSON path or - for stdin")
    p.add_argument("database", type=Path)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--max-line", type=int, default=8 * 1024 * 1024)
    p.add_argument("--max-disk", type=int)
    p = sub.add_parser("verify")
    p.add_argument("database", type=Path)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--timeout", type=float, default=3600)
    p.add_argument("--expected-config-sha256")
    p = sub.add_parser("query")
    p.add_argument("database", type=Path)
    for name in ("protocol", "session", "ip", "start-ns", "end-ns", "kind"):
        p.add_argument("--" + name)
    p.add_argument("--port", type=int)
    p.add_argument("--metadata", help="Exact dotted.key=value")
    p.add_argument("--limit", type=int, default=100)
    a = parser.parse_args(argv)
    if a.command == "build":
        stream = sys.stdin.buffer if a.events == "-" else open(a.events, "rb")
        try:
            print(json.dumps(build(stream, a.database, source=a.source, max_line=a.max_line, max_disk=a.max_disk), indent=2))
        finally:
            if stream is not sys.stdin.buffer:
                stream.close()
    elif a.command == "verify":
        print(json.dumps(verify(a.database, a.source, a.binary, timeout=a.timeout, expected_config_sha256=a.expected_config_sha256), indent=2))
    else:
        metadata = None
        if a.metadata:
            if "=" not in a.metadata:
                parser.error("--metadata requires key=value")
            metadata = tuple(a.metadata.split("=", 1))
        for event in query(a.database, protocol=a.protocol, session=a.session, ip=a.ip, port=a.port,
                           start_ns=a.start_ns, end_ns=a.end_ns, metadata=metadata, kind=a.kind, limit=a.limit):
            print(canonical(event).decode())
    return 0
