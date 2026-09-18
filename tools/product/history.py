"""Immutable-source archive and disk-backed stream-hypothesis reconstruction.

The source archive is byte-exact. The interval store is a tested full-history
vertical slice, NOT an automatic TCP generation/state machine: its caller must
supply independently justified session identities and unwrapped sequence offsets.
All policies expose conflicting alternatives and missing ranges. Disk storage
never silently promotes an analysis window into an endpoint connection.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from .comparison import canonical
from tools.evidence.common import digest_file

SCHEMA="pcap-evidence.history.v1"

def archive(source, destination, *, chunk_bytes=4*1024*1024, disk_budget=1024**4):
    source=Path(source).resolve(strict=True);destination=Path(destination)
    if destination.exists():raise FileExistsError(destination)
    if not 4096<=chunk_bytes<=16*1024*1024 or disk_budget<=0:raise ValueError("archive budgets")
    destination.parent.mkdir(parents=True,exist_ok=True)
    temp=Path(tempfile.mkdtemp(prefix=".history-",dir=destination.parent))
    try:
        total=index_bytes=number=0;h=hashlib.sha256();ih=hashlib.sha256()
        with source.open("rb") as f,(temp/"chunks.ndjson").open("xb")as index:
            initial=os.fstat(f.fileno())
            if not source.is_file():raise ValueError("regular input required")
            while raw:=f.read(chunk_bytes):
                name=f"{number:016x}.chunk"
                row={"file":name,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
                line=canonical(row)+b"\n";total+=len(raw);index_bytes+=len(line);number+=1
                if total+index_bytes+4096>disk_budget:raise ValueError("archive disk budget exceeded")
                with (temp/name).open("xb")as out:out.write(raw);out.flush();os.fsync(out.fileno())
                index.write(line);ih.update(line);h.update(raw)
                if number>1_000_000:raise ValueError("archive chunk count budget")
            end=os.fstat(f.fileno())
            if (initial.st_size,initial.st_mtime_ns,initial.st_ctime_ns)!=(end.st_size,end.st_mtime_ns,end.st_ctime_ns):raise ValueError("source changed during archival read")
            index.flush();os.fsync(index.fileno())
        manifest={"schema":SCHEMA,"source_bytes":str(total),"source_sha256":h.hexdigest(),"chunk_bytes":chunk_bytes,
                  "chunks_count":str(number),"index_sha256":ih.hexdigest(),"index_bytes":str(index_bytes),
                  "reconstruction":"source_retention_only_not_tcp_interpretation","complete":True}
        with (temp/"manifest.json").open("xb")as out:out.write(canonical(manifest)+b"\n");out.flush();os.fsync(out.fileno())
        destination.mkdir()
        # Publish the completion manifest LAST. An interrupted directory has no
        # completion certificate and can be discarded or independently inspected.
        for p in temp.iterdir():
            if p.name!="manifest.json":os.rename(p,destination/p.name)
        os.rename(temp/"manifest.json",destination/"manifest.json")
        return manifest
    finally:
        for p in temp.iterdir():p.unlink()
        temp.rmdir()

def _manifest(root):
    p=root/"manifest.json"
    if p.is_symlink() or p.stat().st_size>16384:raise ValueError("archive manifest budget/path")
    from tools.research.contract import decode_json
    m=decode_json(p.read_bytes(),16384)
    if m.get("schema")!=SCHEMA or m.get("complete")is not True:raise ValueError("archive incomplete")
    if not 0<=int(m["chunks_count"])<=1_000_000:raise ValueError("archive chunk count")
    return m

def _chunks(root):
    from tools.research.contract import decode_json
    p=root/"chunks.ndjson"
    if p.is_symlink():raise ValueError("symlink chunk index")
    with p.open("rb")as f:
        for i in range(1_000_001):
            line=f.readline(513)
            if not line:break
            if i==1_000_000 or len(line)>512 or not line.endswith(b"\n"):raise ValueError("chunk index budget")
            c=decode_json(line,512)
            if c["file"]!=f"{i:016x}.chunk" or type(c["bytes"])is not int or not 1<=c["bytes"]<=16*1024*1024:raise ValueError("invalid ordered chunk")
            yield c,line

def verify_archive(directory):
    root=Path(directory).resolve(strict=True);m=_manifest(root)
    h=hashlib.sha256();ih=hashlib.sha256();total=count=index_bytes=0
    for c,line in _chunks(root):
        p=root/c["file"]
        if p.is_symlink():raise ValueError("symlink chunk")
        with p.open("rb")as f:raw=f.read(16*1024*1024+1)
        if len(raw)!=c["bytes"]or hashlib.sha256(raw).hexdigest()!=c["sha256"]:raise ValueError("chunk identity mismatch")
        total+=len(raw);h.update(raw);ih.update(line);count+=1;index_bytes+=len(line)
    if str(total)!=m["source_bytes"]or h.hexdigest()!=m["source_sha256"]or str(count)!=m["chunks_count"]or ih.hexdigest()!=m["index_sha256"]or str(index_bytes)!=m["index_bytes"]:raise ValueError("source/index identity mismatch")
    return {"status":"PASS","source_bytes":str(total),"source_sha256":h.hexdigest(),"endpoint_semantics_verified":False}

def replay_archive(directory, output):
    proof=verify_archive(directory);root=Path(directory)
    for c,_ in _chunks(root):
        p=root/c["file"]
        with p.open("rb")as f:raw=f.read(c["bytes"]+1)
        if len(raw)!=c["bytes"]or hashlib.sha256(raw).hexdigest()!=c["sha256"]:raise ValueError("archive changed after verification")
        from .tlv import write_all
        write_all(output,raw)
    return proof

class StreamStore:
    """Disk-backed unwrapped intervals, keyed by explicit analysis hypotheses.

    Each segment retains its original source-file byte offset and hash. Append
    is transactional. Reconstruction outputs bounded pieces, alternatives and
    provenance; endpoint session attribution is deliberately caller-owned.
    """
    def __init__(self, database, source, *, create=False, disk_budget=4*1024**3):
        self.path=Path(database);self.source=Path(source).resolve(strict=True);self.budget=disk_budget
        if disk_budget<65536:raise ValueError("disk budget too small")
        if create:
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        elif not self.path.is_file():raise FileNotFoundError(self.path)
        self.db=sqlite3.connect(self.path);self.db.execute("PRAGMA trusted_schema=OFF");self.db.execute("PRAGMA temp_store=FILE");self.db.execute("PRAGMA cache_size=-8192")
        self.db.execute("PRAGMA max_page_count="+str(disk_budget//4096))
        identity=digest_file(self.source)
        if create:
            self.db.executescript("CREATE TABLE meta(k TEXT PRIMARY KEY,v TEXT); CREATE TABLE segments(id INTEGER PRIMARY KEY,scope TEXT NOT NULL,direction INTEGER NOT NULL,start INTEGER NOT NULL,end INTEGER NOT NULL,source_offset INTEGER NOT NULL,bytes INTEGER NOT NULL,sha256 TEXT NOT NULL); CREATE INDEX intervals ON segments(scope,direction,start,end);")
            self.db.executemany("INSERT INTO meta VALUES (?,?)",[("schema","stream-hypotheses-v1"),("source_sha256",identity),("source_bytes",str(self.source.stat().st_size))]);self.db.commit()
        m=dict(self.db.execute("SELECT k,v FROM meta"))
        if m.get("schema")!="stream-hypotheses-v1"or m.get("source_sha256")!=identity or m.get("source_bytes")!=str(self.source.stat().st_size):self.db.close();raise ValueError("stream store source mismatch")
        self.identity=identity
    def close(self):self.db.close()
    def append(self,scope,direction,start,source_offset,length):
        if not isinstance(scope,str)or not 1<=len(scope)<=256 or direction not in (0,1):raise ValueError("explicit bounded scope required")
        if any(type(n)is not int for n in (start,source_offset,length))or not -(1<<62)<=start<1<<62 or not 0<length<=65536 or source_offset<0 or source_offset+length>self.source.stat().st_size:raise ValueError("segment bounds")
        with self.source.open("rb")as f:f.seek(source_offset);raw=f.read(length)
        if len(raw)!=length:raise ValueError("source truncated")
        with self.db:self.db.execute("INSERT INTO segments(scope,direction,start,end,source_offset,bytes,sha256) VALUES (?,?,?,?,?,?,?)",(scope,direction,start,start+length,source_offset,length,hashlib.sha256(raw).hexdigest()))
    def reconstruct(self,scope,direction, *, policy="reject",piece_bytes=4096,max_work=64*1024*1024):
        if policy not in {"reject","first","last"}or not 1<=piece_bytes<=65536:raise ValueError("reconstruction policy/budget")
        row=self.db.execute("SELECT MIN(start),MAX(end) FROM segments WHERE scope=? AND direction=?",(scope,direction)).fetchone()
        if row[0]is None:return
        pos,end=row;work=0
        with self.source.open("rb")as source:
            while pos<end:
                next_boundary=self.db.execute("SELECT MIN(x) FROM (SELECT start AS x FROM segments WHERE scope=? AND direction=? AND start>? UNION ALL SELECT end FROM segments WHERE scope=? AND direction=? AND end>?)",(scope,direction,pos,scope,direction,pos)).fetchone()[0]
                bound=min(end,pos+piece_bytes,next_boundary or end)
                values=[]
                for sid,a,b,offset,length,digest in self.db.execute("SELECT id,start,end,source_offset,bytes,sha256 FROM segments WHERE scope=? AND direction=? AND start<=? AND end>? ORDER BY id",(scope,direction,pos,pos)):
                    work+=length
                    if work>max_work or len(values)>=4096:raise ValueError("reconstruction work/overlap budget")
                    source.seek(offset);raw=source.read(length)
                    if len(raw)!=length or hashlib.sha256(raw).hexdigest()!=digest:raise ValueError("source segment changed")
                    selected=raw[pos-a:bound-a]
                    values.append({"segment":sid,"source_start":str(offset+pos-a),"source_end":str(offset+bound-a),"hex":selected.hex(),"sha256":hashlib.sha256(selected).hexdigest()})
                distinct={v["hex"]for v in values};conflict=len(distinct)>1
                result={"scope":scope,"direction":direction,"start":str(pos),"end":str(bound),"status":"gap"if not values else "conflict"if conflict else "candidate",
                        "policy":policy,"alternatives":values,"bytes_hex":None,"automatic_connection_identity":False}
                if values and not(conflict and policy=="reject"):result["bytes_hex"]=values[-1 if policy=="last"else 0]["hex"]
                yield result;pos=bound
