"""Independent typed TLV reader/writer matching the Rust product sink.

Unknown value tags are retained as Opaque values, not silently trusted. Reader
limits apply before allocation. Hash checks establish integrity, not authorship.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import struct
from typing import BinaryIO
MAGIC=b"PCEVTLV1"
DOMAIN=b"pcap-evidence/tlv/v1\0"
MAX_RECORD=8*1024*1024
@dataclass(frozen=True)
class Opaque:
    tag:int
    data:bytes

def encode(value, *, limit=MAX_RECORD):
    if type(limit)is not int or not 5<=limit<=MAX_RECORD:raise ValueError("TLV byte budget")
    nodes=0
    def walk(v,depth,budget):
        nonlocal nodes
        nodes+=1
        if depth>24 or nodes>100000 or budget<5:raise ValueError("TLV tree/record budget")
        if v is None:tag,body=0,b""
        elif type(v)is bool:tag,body=1,bytes([v])
        elif type(v)is int:
            if not 0<=v<1<<64:raise ValueError("TLV u64 range")
            tag,body=2,struct.pack("!Q",v)
        elif isinstance(v,str):
            if len(v)>budget-5:raise ValueError("TLV string budget")
            tag,body=3,v.encode("utf-8")
        elif isinstance(v,(list,dict)):
            tag=4 if isinstance(v,list)else 5;body=bytearray()
            if isinstance(v,dict)and any(not isinstance(k,str)for k in v):raise ValueError("TLV key type")
            items=v if isinstance(v,list)else (part for pair in v.items()for part in pair)
            for part in items:body.extend(walk(part,depth+1,budget-5-len(body)))
        elif isinstance(v,Opaque):
            if not 6<=v.tag<=255 or not isinstance(v.data,bytes):raise ValueError("opaque tag/body")
            tag,body=v.tag,v.data
        else:raise ValueError("unsupported TLV value")
        if len(body)+5>budget:raise ValueError("TLV record budget")
        return bytes([tag])+struct.pack("!I",len(body))+body
    return walk(value,0,limit)

def decode(raw, *, limit=MAX_RECORD):
    if not isinstance(raw,bytes)or len(raw)>limit:raise ValueError("TLV byte budget")
    nodes=0
    def walk(at,end,depth):
        nonlocal nodes
        nodes+=1
        if depth>24 or nodes>100000:raise ValueError("TLV tree budget")
        if at+5>end:raise ValueError("truncated TLV header")
        tag=raw[at];n=struct.unpack_from("!I",raw,at+1)[0];a=at+5;b=a+n
        if b>end:raise ValueError("truncated TLV value")
        if tag==0:
            if n:raise ValueError("null length")
            value=None
        elif tag==1:
            if n!=1 or raw[a] not in (0,1):raise ValueError("boolean encoding")
            value=bool(raw[a])
        elif tag==2:
            if n!=8:raise ValueError("u64 width")
            value=struct.unpack_from("!Q",raw,a)[0]
        elif tag==3:value=raw[a:b].decode("utf-8")
        elif tag in (4,5):
            items=[];p=a
            while p<b:
                x,p=walk(p,b,depth+1);items.append(x)
            if tag==4:value=items
            else:
                if len(items)%2:raise ValueError("object key/value pairing")
                value={}
                for k,v in zip(items[::2],items[1::2]):
                    if not isinstance(k,str)or k in value:raise ValueError("duplicate/non-string object key")
                    value[k]=v
        else:value=Opaque(tag,raw[a:b])
        return value,b
    result,end=walk(0,len(raw),0)
    if end!=len(raw):raise ValueError("trailing TLV values")
    return result

def read_exact(f,n, *, eof=False):
    out=bytearray()
    while len(out)<n:
        part=f.read(n-len(out))
        if not part:
            if eof and not out:return b""
            raise ValueError("truncated TLV stream")
        out.extend(part)
    return bytes(out)

def events(f:BinaryIO, *, max_record=MAX_RECORD, require_complete=True):
    if read_exact(f,8)!=MAGIC:raise ValueError("TLV magic")
    previous=bytes(32);seq=0;complete=False;terminal=False;run_id=None
    while header:=read_exact(f,4,eof=True):
        if terminal:raise ValueError("records after terminal event")
        n=struct.unpack("!I",header)[0]
        if not 72<=n<=max_record-4:raise ValueError("TLV frame budget/length")
        record=read_exact(f,n);number=struct.unpack_from("!Q",record)[0]
        if number!=seq+1 or record[8:40]!=previous:raise ValueError("TLV chain sequence")
        digest=hashlib.sha256(DOMAIN+previous+record[:8]+record[72:]).digest()
        if digest!=record[40:72]:raise ValueError("TLV hash mismatch")
        value=decode(record[72:],limit=max_record)
        if not isinstance(value,dict)or value.get("sequence")!=str(number):raise ValueError("event sequence mismatch")
        if number==1 and value.get("kind")!="capture.start":raise ValueError("missing start event")
        if number==1:
            run_id=value.get("run_id")
            if not isinstance(run_id,str)or not 1<=len(run_id)<=128:raise ValueError("run identity")
        elif value.get("run_id")!=run_id or value.get("kind")=="capture.start":raise ValueError("mixed/restarted run")
        complete=value.get("kind")=="capture.complete"
        terminal=complete or value.get("kind")=="capture.aborted"
        previous=digest;seq=number;yield value
    if require_complete and not complete:raise ValueError("TLV run incomplete; no complete-source binding")

def write_all(f, raw):
    view=memoryview(raw)
    while view:
        n=f.write(view)
        if type(n)is not int or n<=0 or n>len(view):raise OSError("short/failed binary output")
        view=view[n:]

def write_events(f:BinaryIO, values, *, max_record=MAX_RECORD):
    write_all(f,MAGIC);previous=bytes(32)
    for seq,value in enumerate(values,1):
        if value.get("sequence")!=str(seq):raise ValueError("noncontiguous events")
        body=encode(value,limit=max_record-76);number=struct.pack("!Q",seq)
        digest=hashlib.sha256(DOMAIN+previous+number+body).digest()
        write_all(f,struct.pack("!I",72+len(body))+number+previous+digest+body);previous=digest
