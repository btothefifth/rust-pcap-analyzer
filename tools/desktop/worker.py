"""Isolated analysis worker. Native and container-only modes never silently switch."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from .store import initialize
from .resources import publish_state, ResourceGuard, WorkerStopped
from tools.evidence.index import ChainReader, _project
from tools.evidence.common import canonical
from tools.evidence.containers import Reader
DOMAIN=b"pcap-evidence/event/v1\0"

def state(path, value):
    publish_state(path, value)

def inspection_lines(source,run_id):
    """Explicit container-reference mode; never presented as Rust protocol analysis."""
    seq=0;previous=bytes(32);h=hashlib.sha256();size=0;packets=0;records=0
    def emit(kind,data,evidence=None):
        nonlocal seq,previous
        seq+=1
        ev=dict(schema="pcap-evidence.event.v1",run_id=run_id,sequence=str(seq),kind=kind,status="observed",source_binding="requires_capture_complete",session=None,direction=None,protocol=None,stream_range=None,related_events=[],evidence=evidence or dict(byte_length="0",reconstructed_sha256=None,packets=[],spans=[]),data=data)
        body=canonical(ev);digest=hashlib.sha256(DOMAIN+previous+body).digest()
        line=canonical(dict(event=ev,previous_sha256=previous.hex(),event_sha256=digest.hex()))+b"\n";previous=digest;return line
    yield emit("capture.start",dict(implementation="independent-python-container/1",config=dict(mode="container_inspection_only"),plugins=[],reconstruction_scope="no_protocol_or_stream_analysis"))
    with source.open("rb")as f:
        for record in Reader(f).records():
            h.update(record.raw);size+=len(record.raw);records+=1
            if record.packet:
                p=record.packet;r=p.row();packets+=1
                data={"frame":str(p.frame),"record_offset":str(p.record_offset),"data_offset":str(p.data_offset),"captured_length":len(p.data),"original_length":p.original_length,"link_type":p.link,"section":p.section,"interface":p.interface,"timestamp_ns":r["timestamp_ns"],"raw_timestamp":None if p.ticks is None else {"ticks":str(p.ticks),"resolution_code":p.resolution,"offset_seconds":str(p.offset)},"packet_sha256":r["packet_sha256"],"warnings":[],"snaplen_truncated":len(p.data)<p.original_length}
                yield emit("packet.observed",data,dict(byte_length="0",reconstructed_sha256=None,packets=[dict(frame=str(p.frame),record_offset=str(p.record_offset))],spans=[]))
            else:yield emit("capture.metadata",dict(record_offset=str(record.offset),record_length=str(len(record.raw)),record_sha256=hashlib.sha256(record.raw).hexdigest(),opaque=True))
    yield emit("capture.complete",dict(source_sha256=h.hexdigest(),source_bytes=str(size),packets=str(packets),records=str(records),events=str(seq+1),complete_protocol_history=False))

class LineInput:
    def __init__(self,iterator):self.it=iter(iterator)
    def readline(self,limit=-1):
        try:line=next(self.it)
        except StopIteration:return b""
        if limit>=0 and len(line)>limit:raise ValueError("line budget")
        return line

def _source_digest(source, guard):
    value = hashlib.sha256()
    with source.open("rb") as file:
        while data := file.read(65536):
            guard.check()
            value.update(data)
    return value.hexdigest()


def run(directory, source, mode, engine=None, profile="ics-full",
        disk_budget=10*1024**3, timeout_seconds=86400):
    directory = Path(directory)
    source = Path(source).resolve(strict=True)
    if not source.is_file():
        raise ValueError("regular input required")
    guard = ResourceGuard(directory, disk_budget, timeout_seconds)
    status_path = directory / "state.json"
    run_id = directory.name
    current = dict(id=run_id, state="running", mode=mode, source_name=source.name,
                   source_bytes=str(source.stat().st_size), packets="0", events="0",
                   source_binding="provisional", semantic_replay_verified=False)
    state(status_path, current)
    db = proc = log = error_thread = None
    count = events = committed_count = committed_events = 0
    terminal = None
    started = time.monotonic()
    with guard:
        try:
            guard.check()
            db = initialize(directory / "events.sqlite")
            page_size = db.execute("PRAGMA page_size").fetchone()[0]
            db.execute("PRAGMA max_page_count=" + str(max(16, disk_budget // 3 // page_size)))
            db.execute("PRAGMA journal_size_limit=" + str(min(16*1024**2, disk_budget // 8)))
            if mode == "rust":
                if engine is None or not Path(engine).is_file():
                    raise ValueError("configured Rust engine unavailable")
                command = [str(Path(engine).resolve()), "analyze", str(source), "--profile", profile,
                           "--format", "ndjson", "--run-id", run_id,
                           "--max-output-bytes", str(disk_budget // 3)]
                proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, shell=False)
                guard.attach(proc)
                def errors():
                    total = 0
                    with (directory / "stderr.txt").open("xb") as file:
                        while raw := proc.stderr.read(4096):
                            n = min(len(raw), 65536 - total)
                            if n > 0:
                                file.write(raw[:n]); total += n
                            if len(raw) > n:
                                guard.stop("native_stderr_budget")
                                break
                error_thread = threading.Thread(target=errors, daemon=True)
                error_thread.start()
                input_stream = proc.stdout
            elif mode == "container":
                input_stream = LineInput(inspection_lines(source, run_id))
            else:
                raise ValueError("unknown worker mode")
            chain = ChainReader(input_stream)
            log = (directory / "events.ndjson").open("xb")
            written = 0
            last = 0
            with source.open("rb") as capture:
                for wrapper, event in chain:
                    guard.check()
                    line = canonical(wrapper) + b"\n"
                    if written + len(line) > disk_budget // 3:
                        raise WorkerStopped("event_spool_disk_budget")
                    if not db.in_transaction:
                        db.execute("BEGIN")
                    db.execute("SAVEPOINT current_event")
                    try:
                        new_count, _ = _project(db, wrapper, event, capture, source.stat().st_size, count)
                        db.execute("RELEASE current_event")
                    except BaseException:
                        db.execute("ROLLBACK TO current_event")
                        db.execute("RELEASE current_event")
                        raise
                    log.write(line)
                    written += len(line)
                    count = new_count
                    events += 1
                    if event["kind"] == "capture.complete":
                        terminal = event["data"]
                    if events % 1000 == 0 or time.monotonic() - last > 0.5:
                        db.commit()
                        committed_count, committed_events = count, events
                        log.flush()
                        db.execute("PRAGMA wal_checkpoint(PASSIVE)")
                        last = time.monotonic()
                        guard.sample(); guard.check()
                        current.update(packets=str(count), events=str(events))
                        state(status_path, current)
                db.commit()
                committed_count, committed_events = count, events
                log.flush(); os.fsync(log.fileno())
            guard.check()
            if proc is not None and proc.wait(timeout=5):
                raise ValueError("native analysis exited unsuccessfully")
            if (terminal is None or str(count) != terminal["packets"]
                    or _source_digest(source, guard) != terminal["source_sha256"]
                    or str(source.stat().st_size) != terminal["source_bytes"]):
                raise ValueError("terminal source binding/count mismatch")
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            guard.sample(); guard.check()
            current.update(state="complete", packets=str(count), events=str(events),
                           source_binding="bytes_and_spans_checked", source_sha256=terminal["source_sha256"],
                           elapsed_seconds=round(time.monotonic()-started, 3),
                           logical_disk_high_water_bytes=str(guard.peak))
            state(status_path, current)
            return 0
        except BaseException as error:
            if db is not None:
                try: db.rollback()
                except Exception: pass
            cancelled = guard.reason == "cancelled"
            current.update(state="cancelled" if cancelled else "failed",
                           packets=str(committed_count), events=str(committed_events),
                           source_binding="provisional_prefix", log_tail_may_exceed_projection=True,
                           error_code=guard.reason or type(error).__name__,
                           error=(guard.reason or str(error))[:256],
                           logical_disk_high_water_bytes=str(guard.peak))
            state(status_path, current)
            return 1
        finally:
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            if error_thread is not None:
                error_thread.join(timeout=2)
            if proc is not None:
                if proc.stdout is not None: proc.stdout.close()
                if proc.stderr is not None: proc.stderr.close()
            if log is not None: log.close()
            if db is not None: db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("source", type=Path)
    parser.add_argument("--mode", choices=["container", "rust"], default="rust")
    parser.add_argument("--engine", type=Path)
    parser.add_argument("--profile", default="ics-full")
    parser.add_argument("--disk-budget", type=int, default=10*1024**3)
    parser.add_argument("--timeout-seconds", type=float, default=86400)
    args = parser.parse_args()
    raise SystemExit(run(args.directory, args.source, args.mode, args.engine, args.profile,
                         args.disk_budget, args.timeout_seconds))
