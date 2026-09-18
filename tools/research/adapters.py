"""Explicit offline differential adapters, isolated from native analysis code.

No command in an imported manifest is executed. Tools run only when the caller
supplies a binary for an allowlisted adapter. This is process isolation, not an OS
sandbox; only trusted local executables should be configured. Time/output limits
bound the harness; they do not prove a target's security or semantic conformance.
"""
from __future__ import annotations
import csv
import io
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from .contract import (InvalidResearch, MAX_ROWS, canonical, digest, file_identity,
                       observation, snapshot, decode_json, LAYERS)

FIELDS = ("frame.number", "frame.cap_len", "frame.len", "frame.time_epoch",
          "eth.type", "ip.version", "ip.src", "ip.dst", "ip.proto",
          "ipv6.version", "ipv6.src", "ipv6.dst", "ipv6.nxt",
          "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw",
          "udp.srcport", "udp.dstport", "udp.length")

@dataclass(frozen=True)
class ProcessResult:
    command: tuple[str, ...]
    status: str
    returncode: int | None
    stdout: bytes
    stderr: bytes
    elapsed_seconds: float

def execute(command, *, timeout=30.0, output_limit=8*1024*1024, cwd=None):
    if not command or not 0 < timeout <= 3600 or not 1 <= output_limit <= 64*1024*1024:
        raise InvalidResearch("invalid research process budget")
    executable = Path(command[0])
    if not executable.is_file() or not executable.is_absolute():
        return ProcessResult(tuple(command), "BLOCKED", None, b"", b"explicit executable missing", 0)
    if os.name == "nt" and executable.suffix.lower() in {".bat", ".cmd"}:
        raise InvalidResearch("shell scripts are not research executables")
    start = time.monotonic()
    env = {**os.environ, "LC_ALL": "C", "TZ": "UTC", "CARGO_NET_OFFLINE": "true"}
    try:
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
                                start_new_session=os.name == "posix")
    except OSError as e:
        return ProcessResult(tuple(command), "BLOCKED", None, b"", str(type(e).__name__).encode(), 0)
    over = threading.Event()
    buffers = [bytearray(), bytearray()]
    def pump(pipe, out):
        try:
            while data := pipe.read(8192):
                room = output_limit-len(out)
                out.extend(data[:room])
                if len(data) > room:
                    over.set()
                    break
        finally: pipe.close()
    threads = [threading.Thread(target=pump,args=(pipe,buf),daemon=True) for pipe,buf in zip((proc.stdout,proc.stderr),buffers)]
    for t in threads: t.start()
    status = None
    def stop():
        try:
            if os.name == "posix": os.killpg(proc.pid, signal.SIGKILL)
            else: proc.kill()
        except ProcessLookupError: pass
    while True:
        if over.is_set(): status = "OUTPUT_LIMIT"; break
        if time.monotonic()-start > timeout: status = "TIMEOUT"; break
        if proc.poll() is not None and not any(t.is_alive() for t in threads): break
        time.sleep(0.005)
    if status: stop()
    try: code = proc.wait(timeout=2)
    except subprocess.TimeoutExpired: stop(); code = proc.wait(timeout=2)
    for t in threads: t.join(timeout=2)
    if any(t.is_alive() for t in threads):
        # A descendant holding a pipe must not make a completed tool appear clean.
        stop(); status = status or "PIPE_NOT_CLOSED"
    status = status or ("OUTPUT_LIMIT" if over.is_set() else "PASS" if code == 0 else "CRASH" if code < 0 else "TOOL_ERROR")
    return ProcessResult(tuple(command),status,code,bytes(buffers[0]),bytes(buffers[1]),round(time.monotonic()-start,6))

def _source(path):
    return file_identity(path)

def _producer(name, version, args, origin="external_tool"):
    return {"id": name, "version": version[:128] or "unknown", "origin": origin,
            "config_sha256": digest(canonical(args)), "command": list(args), "dependencies": []}

def epoch_ns(value):
    """Exact signed decimal conversion. Inexact sub-ns values stay unknown."""
    import re
    if not re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?", value) or len(value)>64:
        raise InvalidResearch("invalid external timestamp")
    negative=value.startswith("-"); whole,_,fraction=value.lstrip("-").partition(".")
    if len(fraction)>9 and any(x!="0" for x in fraction[9:]): return None
    n=int(whole)*1_000_000_000+int((fraction[:9]+"0"*9)[:9])
    return str(-n if negative else n)

def tshark_normalize(raw, source, version):
    if len(raw)>8*1024*1024: raise InvalidResearch("adapter output limit")
    try: text=raw.decode("utf-8",errors="strict")
    except UnicodeError: raise InvalidResearch("non-UTF-8 TShark field output") from None
    reader=csv.DictReader(io.StringIO(text),delimiter="\t")
    if tuple(reader.fieldnames or ()) != FIELDS:
        raise InvalidResearch("TShark field schema differs; adapter requires review")
    observations=[]; seen=set()
    def uint(value):
        if not value: return None
        # Multiple occurrences signal nested/ambiguous layer scope; do not select first.
        if "," in value: return None
        try: number=int(value,16 if value.startswith("0x") else 10)
        except ValueError: raise InvalidResearch("invalid numeric TShark field") from None
        if not 0<=number<(1<<64): raise InvalidResearch("numeric TShark field range")
        return str(number)
    for row in reader:
        if len(observations)>MAX_ROWS-5: raise InvalidResearch("adapter observation budget")
        frame=uint(row["frame.number"])
        if frame is None or frame=="0" or frame in seen: raise InvalidResearch("duplicate/missing TShark frame")
        seen.add(frame); key="frame:"+frame
        observations.append(observation("capture_record",key,{"captured_length":uint(row["frame.cap_len"]),"original_length":uint(row["frame.len"])},frames=[frame]))
        observations.append(observation("timestamp",key,{"unix_ns":epoch_ns(row["frame.time_epoch"]) if row["frame.time_epoch"] else None},frames=[frame]))
        if row["eth.type"] and "," not in row["eth.type"]:
            observations.append(observation("link_layer",key,{"ether_type":uint(row["eth.type"])},frames=[frame]))
        ip="ip" if row["ip.version"] and not row["ipv6.version"] else "ipv6" if row["ipv6.version"] and not row["ip.version"] else None
        if ip and all("," not in row[x] for x in (ip+".src",ip+".dst",ip+".version")):
            observations.append(observation("network_layer",key,{"version":uint(row[ip+".version"]),"source_ip":row[ip+".src"],"destination_ip":row[ip+".dst"]},frames=[frame]))
        transport="tcp" if row["tcp.srcport"] and not row["udp.srcport"] else "udp" if row["udp.srcport"] and not row["tcp.srcport"] else None
        if transport and "," not in row[transport+".srcport"] and "," not in row[transport+".dstport"]:
            v={"transport":transport,"source_port":uint(row[transport+".srcport"]),"destination_port":uint(row[transport+".dstport"])}
            observations.append(observation("transport_identity",key,v,frames=[frame]))
    return snapshot(_producer("tshark",version,["-n","-r","<capture>","-T","fields","fixed-fields-v1"]),source,observations,
                    notes=["Multiple layer occurrences are deliberately not flattened. No external packet-byte/hash claim is fabricated.","Only field-level common coverage is comparable; endpoint/session semantics are not normalized here."])

def container_normalize(path):
    from tools.evidence.containers import Reader
    rows=[]; packet_count=0
    with Path(path).open("rb") as file:
        for record in Reader(file).records():
            if record.packet is None: continue
            p=record.packet;packet_count+=1
            if len(rows)>MAX_ROWS-3: raise InvalidResearch("research fixture packet count budget")
            r=p.row();key="frame:"+str(p.frame)
            common=dict(frames=[p.frame],spans=[{"frame":str(p.frame),"start":"0","end":str(len(p.data))}] if p.data else [])
            rows.append(observation("capture_record",key,{"captured_length":str(len(p.data)),"original_length":str(p.original_length),"record_offset":str(p.record_offset),"data_offset":str(p.data_offset),"section":str(p.section),"interface":str(p.interface),"link_type":str(p.link)},**common))
            rows.append(observation("packet_bytes",key,{"sha256":digest(p.data),"captured_length":str(len(p.data))},**common))
            rows.append(observation("timestamp",key,{"unix_ns":r["timestamp_ns"],"ticks":r["ticks"],"resolution":str(r["resolution"]),"offset_seconds":r["offset_seconds"]},**common))
    coverage={l:"complete" if l in {"capture_record","packet_bytes","timestamp"} else "not_collected" for l in LAYERS}
    return snapshot(_producer("independent-python-container","1",[],"independent_fixture"),_source(path),rows,coverage,
                    notes=["Independent container implementation, not a protocol oracle or majority vote."])

def event_normalize(raw, source, version, *, producer="pcap-evidence-product", origin="independent_engine"):
    """Normalize native NDJSON without borrowing external interpretations."""
    from tools.evidence.index import ChainReader
    # Bound each JSON tree before the inherited strict canonical hash-chain reader.
    if len(raw)>8*1024*1024: raise InvalidResearch("native event output byte budget")
    for line in raw.splitlines(keepends=True): decode_json(line)
    rows=[];packet_count=0;complete=False
    for _wrapper, e in ChainReader(io.BytesIO(raw)):
        d=e["data"];evidence=e.get("evidence",{});frames=[p["frame"] for p in evidence.get("packets",[])[:256]]
        kwargs=dict(frames=frames,events=[e["sequence"]])
        if len(rows)>MAX_ROWS-3: raise InvalidResearch("native observation budget")
        if e["kind"]=="packet.observed":
            key="frame:"+str(d["frame"]);packet_count+=1
            kwargs["frames"]=[d["frame"]]
            rows.append(observation("capture_record",key,{k:str(d[k]) for k in ("captured_length","original_length","record_offset","data_offset","section","interface","link_type")},**kwargs))
            rows.append(observation("packet_bytes",key,{"sha256":d["packet_sha256"],"captured_length":str(d["captured_length"])},**kwargs))
            time=d.get("raw_timestamp")
            rows.append(observation("timestamp",key,{"unix_ns":d.get("timestamp_ns"),"ticks":time["ticks"] if time else None,"resolution":str(time["resolution_code"]) if time else None,"offset_seconds":time["offset_seconds"] if time else None},**kwargs))
        elif e["kind"]=="network.observed" and len(frames)==1 and d.get("transport") in {"tcp","udp"}:
            key="frame:"+frames[0]
            rows.append(observation("transport_identity",key,{k:str(d[k]) for k in ("transport","source_port","destination_port")},**kwargs))
        elif e["kind"]=="capture.complete":
            if d.get("source_sha256")!=source["sha256"]: raise InvalidResearch("native terminal source binding differs")
            complete=True
    if not complete: raise InvalidResearch("native run has no successful complete-source binding")
    coverage={l:"complete" if l in {"capture_record","packet_bytes","timestamp"} else "partial" if any(r["layer"]==l for r in rows) else "not_collected" for l in LAYERS}
    # Incomplete/ambiguous flow states are not projected as verified TCP state.
    return snapshot(_producer(producer,version,["analyze","<capture>","--format","ndjson"],origin),source,rows,coverage,
                    notes=["Canonical packet and observed tuple surface only; application fields require dedicated semantic adapters."])

def run_adapter(kind, path, binary=None, *, timeout=30):
    source=_source(path)
    if kind=="container":
        return {"status":"PASS","snapshot":container_normalize(path),"artifacts":{},"execution":None}
    if kind not in {"product","tshark","probe"}: raise InvalidResearch("adapter not in executable allowlist")
    if binary is None:
        return {"status":"BLOCKED","reason":"explicit local executable not supplied","artifacts":{},"execution":None}
    binary=Path(binary).resolve(strict=False)
    version_result=execute([str(binary),"--version" if kind!="tshark" else "-v"],timeout=min(timeout,10),output_limit=65536)
    version=version_result.stdout.decode("utf-8","replace").splitlines()
    version=version[0][:128] if version else "version_query_failed"
    if kind=="product": argv=[str(binary),"analyze",str(path),"--profile","ics-full","--format","ndjson","--max-packets","2000","--max-output-bytes",str(8*1024*1024),"--run-id","research"]
    elif kind=="tshark":
        argv=[str(binary),"-n","-r",str(path),"-T","fields","-E","header=y","-E","separator=/t","-E","quote=d","-E","occurrence=a"]
        for field in FIELDS: argv += ["-e",field]
    else: raise InvalidResearch("use native probe case runner for explicit protocol input")
    result=execute(argv,timeout=timeout)
    artifacts={"stdout":result.stdout,"stderr":result.stderr,"version":version_result.stdout+version_result.stderr}
    receipt={"status":result.status,"returncode":result.returncode,"elapsed_seconds":result.elapsed_seconds,
             "command":[x.replace(str(path),"<capture>").replace(str(binary),"<configured-binary>") for x in argv],
             "binary_sha256":file_identity(binary,max_bytes=512*1024*1024)["sha256"],"version":version,
             "host_process_sandbox":False}
    if _source(path)!=source: raise InvalidResearch("input changed during adapter execution")
    if result.status!="PASS": return {"status":result.status,"artifacts":artifacts,"execution":receipt}
    try:
        value=tshark_normalize(result.stdout,source,version) if kind=="tshark" else event_normalize(result.stdout,source,version)
    except (ValueError,KeyError,TypeError) as exc:
        return {"status":"ADAPTER_ERROR","reason":str(exc)[:256],"artifacts":artifacts,"execution":receipt}
    return {"status":"PASS","snapshot":value,"artifacts":artifacts,"execution":receipt}
