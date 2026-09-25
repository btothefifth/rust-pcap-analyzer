"""Bounded indexed queries used by both the browser UI and tests."""
from __future__ import annotations
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from tools.evidence.common import canonical,time_key
from tools.evidence.index import SCHEMA,_project

MAX_ROWS=200

def initialize(path):
    db=sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL");db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA foreign_keys=ON");db.execute("PRAGMA trusted_schema=OFF")
    db.execute("PRAGMA cache_size=-8192");db.execute("PRAGMA mmap_size=0");db.execute("PRAGMA temp_store=FILE")
    db.executescript(SCHEMA);db.commit()
    return db

def connect(path):
    path=Path(path).resolve(strict=True)
    db=sqlite3.connect(path.as_uri()+"?mode=ro",uri=True,timeout=1)
    db.execute("PRAGMA trusted_schema=OFF");db.execute("PRAGMA query_only=ON");db.execute("PRAGMA cache_size=-8192")
    # Cap SQLite virtual-machine work. This is not a process memory sandbox.
    steps=[0]
    def budget():steps[0]+=1;return steps[0]>3000
    db.set_progress_handler(budget,1000)
    return db

@contextmanager
def read_db(path):
    db=connect(path)
    try:
        yield db
    finally:
        db.close()

def decimal(value):
    if not isinstance(value,str)or not value.isascii()or not value.isdecimal()or len(value)>20:raise ValueError("decimal cursor required")
    n=int(value)
    if not 0<=n<1<<64:raise ValueError("cursor outside u64")
    return str(n)

def query(path,filters=None):
    f=filters or {};allowed={"after","limit","kind","status","protocol","session","frame","ip","port","start_ns","end_ns"}
    if not isinstance(f,dict)or set(f)-allowed:raise ValueError("unknown filter")
    limit=f.get("limit",MAX_ROWS)
    if isinstance(limit,str):limit=int(limit)
    if type(limit)is not int or not 1<=limit<=MAX_ROWS:raise ValueError("page size outside 1..200")
    sql="SELECT e.body FROM events e WHERE e.seq_sort>?";args=[decimal(f.get("after","0")).zfill(20)]
    for key in ("kind","status","protocol","session"):
        value=f.get(key)
        if value:
            if not isinstance(value,str)or len(value)>128:raise ValueError("filter size")
            sql+=f" AND e.{key}=?";args.append(value)
    if f.get("frame"):
        sql+=" AND EXISTS(SELECT 1 FROM event_packets ep WHERE ep.seq=e.seq AND ep.frame=?)";args.append(decimal(f["frame"]))
    if f.get("ip"):
        import ipaddress
        address=str(ipaddress.ip_address(f["ip"]))
        sql+=" AND EXISTS(SELECT 1 FROM sessions s WHERE s.session=e.session AND (s.source_ip=? OR s.destination_ip=?))";args.extend([address,address])
    if f.get("port"):
        port=int(f["port"])
        if not 0<=port<=65535:raise ValueError("port range")
        sql+=" AND EXISTS(SELECT 1 FROM sessions s WHERE s.session=e.session AND (s.source_port=? OR s.destination_port=?))";args.extend([port,port])
    for key,op in (("start_ns",">="),("end_ns","<=")):
        if f.get(key):
            text=f[key]
            if not isinstance(text,str)or len(text)>40:raise ValueError("time range")
            sort=time_key(text)
            sql+=f" AND EXISTS(SELECT 1 FROM event_packets ep JOIN packets p ON ep.frame=p.frame WHERE ep.seq=e.seq AND p.ts_sort{op}?)";args.append(sort)
    sql+=" ORDER BY e.seq_sort LIMIT ?";args.append(limit+1)
    with read_db(path)as db:rows=[json.loads(row[0])for row in db.execute(sql,args)]
    more=len(rows)>limit;rows=rows[:limit]
    return {"rows":rows,"has_more":more,"next":rows[-1]["sequence"]if rows else f.get("after","0"),"limit":limit}

def overview(path):
    with read_db(path)as db:
        kinds=dict(db.execute("SELECT kind,COUNT(*) FROM events GROUP BY kind"))
        statuses=dict(db.execute("SELECT status,COUNT(*) FROM events GROUP BY status"))
        protocols=dict(db.execute("SELECT protocol,COUNT(*) FROM events WHERE protocol IS NOT NULL GROUP BY protocol ORDER BY protocol LIMIT 100"))
        first=db.execute("SELECT timestamp_ns FROM packets WHERE ts_sort IS NOT NULL ORDER BY ts_sort LIMIT 1").fetchone()
        last=db.execute("SELECT timestamp_ns FROM packets WHERE ts_sort IS NOT NULL ORDER BY ts_sort DESC LIMIT 1").fetchone()
    return {"kinds":kinds,"states":statuses,"protocols":protocols,"first_ns":first[0]if first else None,"last_ns":last[0]if last else None}

def detail(path,sequence):
    sequence=decimal(sequence)
    with read_db(path)as db:
        row=db.execute("SELECT body FROM events WHERE seq=?",(sequence,)).fetchone()
        if row is None:raise ValueError("event not found")
        parents=[x[0]for x in db.execute("SELECT target FROM relations WHERE seq=? LIMIT 201",(sequence,))]
        children=[x[0]for x in db.execute("SELECT seq FROM relations WHERE target=? LIMIT 201",(sequence,))]
        spans=[dict(zip(("frame","packet_start","start","end"),x))for x in db.execute("SELECT frame,packet_start,start,end FROM spans WHERE seq=? ORDER BY ordinal LIMIT 257",(sequence,))]
    return {"event":json.loads(row[0]),"parents":parents[:200],"children":children[:200],"spans":spans[:256],"truncated":len(parents)>200 or len(children)>200 or len(spans)>256}

def packet_bytes(path,source,frame,start=0,count=256):
    frame=decimal(frame)
    if type(start)is not int or type(count)is not int or start<0 or not 1<=count<=4096:raise ValueError("hex viewport bounds")
    with read_db(path)as db:row=db.execute("SELECT data_offset,caplen,sha256 FROM packets WHERE frame=?",(frame,)).fetchone()
    if row is None:raise ValueError("packet not found")
    offset,length,digest=row
    if length>1024*1024 or start>length:raise ValueError("packet length/range budget")
    with Path(source).open("rb")as file:file.seek(int(offset));raw=file.read(length)
    if len(raw)!=length or hashlib.sha256(raw).hexdigest()!=digest:raise ValueError("packet/source changed; bytes not trusted")
    return {"frame":frame,"packet_start":str(start),"source_start":str(int(offset)+start),"captured_length":str(length),"hex":raw[start:start+count].hex(),"packet_sha256":digest,"packet_hash_checked":True}

def reverse(path,frame,start,end,after="0"):
    frame=decimal(frame);after=decimal(after)
    if type(start)is not int or type(end)is not int or not 0<=start<end<=1024*1024:raise ValueError("source range")
    with read_db(path)as db:
        rows=[json.loads(x[1])for x in db.execute("SELECT DISTINCT e.seq_sort,e.body FROM spans s JOIN events e ON s.seq=e.seq WHERE s.frame=? AND s.packet_start<? AND s.packet_start+(s.end-s.start)>? AND e.seq_sort>? ORDER BY e.seq_sort LIMIT 201",(frame,end,start,after.zfill(20)))]
    return {"rows":rows[:200],"has_more":len(rows)>200}

def timeline(path,after="0",maximum=10000,bins=60):
    after=decimal(after)
    if not 1<=maximum<=10000 or not 1<=bins<=120:raise ValueError("timeline budget")
    with read_db(path)as db:
        rows=list(db.execute("SELECT frame,timestamp_ns FROM packets WHERE frame_sort>? ORDER BY frame_sort LIMIT ?",(after.zfill(20),maximum+1)))
    more=len(rows)>maximum;rows=rows[:maximum];known=[int(t)for _,t in rows if t is not None]
    if not known:return {"buckets":[],"unknown":len(rows),"has_more":more,"next":rows[-1][0]if rows else after,"scope":"bounded_packet_page"}
    lo,hi=min(known),max(known);width=max(1,(hi-lo+bins)//bins);counts=[0]*bins
    for n in known:counts[min(bins-1,(n-lo)//width)]+=1
    return {"buckets":[{"start_ns":str(lo+i*width),"count":n}for i,n in enumerate(counts)],"unknown":len(rows)-len(known),"has_more":more,"next":rows[-1][0]if rows else after,"scope":"bounded_packet_page","clock_reversals_preserved_in_source":True}
