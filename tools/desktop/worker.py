"""Single isolated local analysis job. Engine commands come from trusted startup settings."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import uuid
from .store import initialize
from tools.evidence.index import ChainReader,_project
from tools.evidence.common import canonical,digest_file
from tools.evidence.containers import Reader
DOMAIN=b"pcap-evidence/event/v1\0"

def state(path,value):
    temp=path.with_name(path.name+"."+uuid.uuid4().hex+".next")
    try:
        temp.write_text(json.dumps(value))
        for attempt in range(25):
            try:
                os.replace(temp,path)
                break
            except PermissionError:
                if attempt == 24:
                    raise
                time.sleep(0.004*(attempt+1))
    finally:
        temp.unlink(missing_ok=True)

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

def run(directory,source,mode,engine=None,profile="ics-full",disk_budget=10*1024**3):
    directory=Path(directory);source=Path(source).resolve(strict=True);status_path=directory/"state.json"
    if not source.is_file():raise ValueError("regular input required")
    run_id=directory.name;db=initialize(directory/"events.sqlite");db.execute("PRAGMA max_page_count="+str(max(100,disk_budget//8192)))
    proc=None;error_thread=None;count=0;events=0;terminal=None;started=time.time();log=None
    current=dict(id=run_id,state="running",mode=mode,source_name=source.name,source_bytes=str(source.stat().st_size),packets="0",events="0",source_binding="provisional",semantic_replay_verified=False)
    state(status_path,current)
    try:
        if mode=="rust":
            if engine is None or not Path(engine).is_file():raise ValueError("configured Rust engine unavailable")
            cmd=[str(Path(engine).resolve()),"analyze",str(source),"--profile",profile,"--format","ndjson","--run-id",run_id,"--max-output-bytes",str(disk_budget//2)]
            proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False)
            def errors():
                with (directory/"stderr.txt").open("wb")as f:
                    total=0
                    while raw:=proc.stderr.read(4096):
                        n=min(len(raw),65536-total)
                        if n>0:f.write(raw[:n]);total+=n
                        if total>=65536:proc.kill();break
            error_thread=threading.Thread(target=errors,daemon=True);error_thread.start();input_stream=proc.stdout
        elif mode=="container":input_stream=LineInput(inspection_lines(source,run_id))
        else:raise ValueError("unknown worker mode")
        chain=ChainReader(input_stream);log=(directory/"events.ndjson").open("xb");written=0;last=0
        with source.open("rb")as capture:
            for wrapper,event in chain:
                line=canonical(wrapper)+b"\n";written+=len(line)
                if written>disk_budget//2:raise ValueError("event spool disk budget exceeded")
                if not db.in_transaction:db.execute("BEGIN")
                db.execute("SAVEPOINT current_event")
                try:
                    new_count,_=_project(db,wrapper,event,capture,source.stat().st_size,count)
                    db.execute("RELEASE current_event")
                except BaseException:
                    db.execute("ROLLBACK TO current_event");db.execute("RELEASE current_event");raise
                log.write(line);count=new_count;events+=1
                if event["kind"]=="capture.complete":terminal=event["data"]
                if events%1000==0 or time.monotonic()-last>0.5:
                    db.commit();log.flush();last=time.monotonic()
                    current.update(packets=str(count),events=str(events));state(status_path,current)
            db.commit();log.flush()
        if proc is not None:
            rc=proc.wait(timeout=5)
            if rc:raise ValueError("native analysis exited with status "+str(rc))
        if terminal is None or str(count)!=terminal["packets"] or digest_file(source)!=terminal["source_sha256"] or str(source.stat().st_size)!=terminal["source_bytes"]:raise ValueError("terminal source binding/count mismatch")
        current.update(state="complete",packets=str(count),events=str(events),source_binding="bytes_and_spans_checked",source_sha256=terminal["source_sha256"],elapsed_seconds=round(time.time()-started,3))
        state(status_path,current)
    except BaseException as e:
        db.commit();current.update(state="failed",packets=str(count),events=str(events),source_binding="provisional_prefix",error=type(e).__name__+": "+str(e)[:256]);state(status_path,current)
        return 1
    finally:
        if log is not None:log.close()
        if proc is not None and proc.poll()is None:proc.kill();proc.wait(timeout=5)
        if error_thread:error_thread.join(timeout=2)
        db.close()
    return 0
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("directory",type=Path);p.add_argument("source",type=Path);p.add_argument("--mode",choices=["container","rust"],default="rust");p.add_argument("--engine",type=Path);p.add_argument("--profile",default="ics-full");p.add_argument("--disk-budget",type=int,default=10*1024**3);a=p.parse_args()
    raise SystemExit(run(a.directory,a.source,a.mode,a.engine,a.profile,a.disk_budget))
