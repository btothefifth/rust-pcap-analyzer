"""Independent reader for the Rust history journal and its source witnesses.

This is a development/investigation verifier, not the TCP semantic authority.
Passing proves framing, hashes, packet metadata, spans and index membership;
run `pcap-history verify` to regenerate state decisions from the source.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
from tools.evidence.containers import Reader as CaptureReader

MAGIC = b"PCHIST01"
DOMAIN = b"pcap-evidence/history-record/v1\0"
ENGINE = b"pcap-evidence-history/1;state-policy/1"
MAX_RECORD = 16 * 1024 * 1024

class InvalidHistory(ValueError): pass
class TruncatedHistory(InvalidHistory): pass

class Cursor:
    def __init__(self, data): self.data, self.at = data, 0
    def take(self, n):
        if type(n) is not int or n < 0 or self.at + n > len(self.data):
            raise TruncatedHistory("truncated history field")
        value=self.data[self.at:self.at+n];self.at+=n;return value
    def unpack(self, fmt): return struct.unpack("<"+fmt,self.take(struct.calcsize("<"+fmt)))
    def integer(self, fmt): return self.unpack(fmt)[0]
    def boolean(self):
        n=self.integer("B")
        if n not in (0,1):raise InvalidHistory("noncanonical boolean")
        return bool(n)
    def blob(self, maximum):
        n=self.integer("I")
        if n>maximum:raise InvalidHistory("blob budget")
        return self.take(n)
    def end(self):
        if self.at!=len(self.data):raise InvalidHistory("trailing field data")

def exact(file,n,eof=False):
    out=bytearray()
    while len(out)<n:
        raw=file.read(n-len(out))
        if not raw:
            if eof and not out:return b""
            raise TruncatedHistory("partial journal record")
        out.extend(raw)
    return bytes(out)

def identity(path, maximum=1024**4):
    path=Path(path)
    if path.is_symlink()or not path.is_file():raise InvalidHistory("regular non-symlink source required")
    h=hashlib.sha256();n=0
    with Path(path).open("rb") as f:
        while b:=f.read(65536):
            n+=len(b)
            if n>maximum:raise InvalidHistory("source byte budget")
            h.update(b)
    return {"sha256":h.hexdigest(),"bytes":n}

def header(file):
    prefix=exact(file,12)
    if prefix[:8]!=MAGIC:raise InvalidHistory("unsupported journal magic")
    n=struct.unpack("<I",prefix[8:])[0]
    if n>4096:raise InvalidHistory("header budget")
    body=exact(file,n);digest=exact(file,32)
    if hashlib.sha256(prefix+body).digest()!=digest:raise InvalidHistory("header hash mismatch")
    d=Cursor(body);source={"sha256":d.take(32).hex(),"bytes":d.integer("Q")};config=Cursor(d.blob(2048));d.end()
    if config.blob(128)!=ENGINE:raise InvalidHistory("unknown engine/policy version")
    limits=config.unpack("Q"*15);policy=config.integer("B");config.end()
    v=limits
    if (policy not in (0,1) or not 0<v[0]<=((1<<64)-1)//8 or v[1]<1024
        or not 0<v[2]<=((1<<64)-1)//2 or not 4096<=v[3]<=MAX_RECORD
        or not 1<=v[4]<=4096 or not 1<=v[5]<=4096 or not 1<=v[6]<=4096
        or not 1<=v[7]<=64 or not 1<=v[8]<(1<<31) or not 2<=v[9]<=1_000_000
        or not 2<=v[10]<=64 or not 1<=v[11]<=1024*1024 or not 1<=v[12]<=65536
        or not v[13] or not v[14] or source["bytes"]>v[0]):
        raise InvalidHistory("invalid configuration")
    return dict(source=source,limits=limits,policy=policy,hash=digest,size=12+n+32)

def records(file,h):
    previous=h["hash"];ordinal=0;terminal=False
    while length:=exact(file,4,eof=True):
        if terminal:raise InvalidHistory("record after terminal")
        offset=file.tell()-4;n=struct.unpack("<I",length)[0]
        if not 9<=n<=h["limits"][3] or ordinal>=h["limits"][2]:raise InvalidHistory("record budget")
        payload=exact(file,n);digest=exact(file,32)
        if hashlib.sha256(DOMAIN+previous+length+payload).digest()!=digest:raise InvalidHistory("journal hash mismatch")
        kind,seq=struct.unpack("<BQ",payload[:9]);ordinal+=1
        if kind not in (1,2,3,4,254,255) or seq!=ordinal:raise InvalidHistory("record sequence/type")
        terminal=kind in (254,255);previous=digest
        yield kind,seq,payload[9:],offset,digest

def decode_key(raw):
    d=Cursor(raw);section,interface=d.unpack("II");n=d.integer("B")
    if n>8:raise InvalidHistory("VLAN budget")
    vlans=d.unpack("H"*n)
    if any(x>4095 for x in vlans):raise InvalidHistory("VLAN ID")
    n=d.integer("B")
    if n>16:raise InvalidHistory("tunnel budget")
    tunnels=[d.blob(512).decode("utf-8") for _ in range(n)]
    endpoints=[]
    for _ in range(2):
        family=d.integer("B")
        if family not in (4,6):raise InvalidHistory("address family")
        endpoints.append((family,d.take(4 if family==4 else 16),d.integer("H")))
    d.end()
    if endpoints[0]>endpoints[1] or any(any(ord(c)<32 or 127<=ord(c)<=159 for c in p) for p in tunnels):
        raise InvalidHistory("noncanonical tuple")
    return dict(section=section,interface=interface,vlans=vlans,tunnels=tunnels,endpoints=endpoints)

def decode_tcp(body,h):
    outer=Cursor(body);d=Cursor(outer.blob(h["limits"][3]));decision=Cursor(outer.blob(h["limits"][3]));outer.end()
    key=decode_key(d.blob(10000));direction=d.integer("B");frame=d.integer("Q")
    if direction>1 or frame==0:raise InvalidHistory("TCP direction/frame")
    if d.boolean():d.take(16)
    raw=d.blob(65535);n=d.integer("I")
    if n>h["limits"][6]:raise InvalidHistory("witness budget")
    witnesses=[d.unpack("IIQQIQ") for _ in range(n)];d.end()
    if len(raw)<20 or not 20<=(raw[12]>>4)*4<=len(raw):raise InvalidHistory("TCP header length")
    ports=struct.unpack("!HH",raw[:4]);a,b=key["endpoints"]
    if ports!=((a[2],b[2]) if direction==0 else (b[2],a[2])):raise InvalidHistory("TCP port identity")
    before=decision.take(32);after=decision.take(32);assumption=decision.boolean();n=decision.integer("I")
    if n>h["limits"][5]*h["limits"][7]:raise InvalidHistory("placement budget")
    placements=[]
    for _ in range(n):
        g=decision.take(32);dr=decision.integer("B");start=decision.integer("q");selected=decision.boolean()
        if dr!=direction:raise InvalidHistory("placement direction mismatch")
        placements.append((g,dr,start,selected))
    if len(set(placements))!=len(placements):raise InvalidHistory("duplicate placement hypothesis")
    n=decision.integer("I")
    if n>32:raise InvalidHistory("reason budget")
    reasons=[decision.blob(256).decode("utf-8") for _ in range(n)];decision.end()
    return dict(raw=raw,payload=raw[(raw[12]>>4)*4:],witnesses=witnesses,placements=placements,
                before=before,after=after,policy_assumption=assumption,reasons=reasons)

def packet_row(raw):
    if len(raw)!=80:raise InvalidHistory("packet index width")
    values=struct.unpack("<QQQIIIIII32s",raw)
    if values[0]==0 or values[8]!=0:raise InvalidHistory("packet index fields")
    return values

def verify(source,workspace):
    source=Path(source);workspace=Path(workspace)
    if source.is_symlink() or any((workspace/n).is_symlink() for n in ("journal.bin","packets.idx","ranges.idx")):
        raise InvalidHistory("symlink evidence file")
    if not workspace.is_dir()or workspace.is_symlink()or not source.is_file()or any(not (workspace/n).is_file()for n in ("journal.bin","packets.idx","ranges.idx")):
        raise InvalidHistory("regular source and journal files required")
    with (workspace/"journal.bin").open("rb") as journal, source.open("rb") as capture, source.open("rb") as witness_file, (workspace/"packets.idx").open("rb") as packets:
        h=header(journal)
        if identity(source,h["limits"][0])!=h["source"]:raise InvalidHistory("source identity mismatch")
        source_hash=hashlib.sha256();source_bytes=0
        def independent_packets():
            nonlocal source_bytes
            for r in CaptureReader(capture).records():
                source_hash.update(r.raw);source_bytes+=len(r.raw)
                if r.packet:yield r
        oracle=iter(independent_packets());packet_count=tcp_count=notice_count=interval_count=0;seal=None
        prior_digest=h["hash"]
        for kind,seq,body,offset,digest in records(journal,h):
            if kind==1:
                r=next(oracle,None)
                if r is None:raise InvalidHistory("journal has extra packets")
                p=r.packet;d=Cursor(body);row_bytes=d.take(80);v=packet_row(row_bytes)
                wanted=(p.frame,r.offset,p.data_offset,len(p.data),p.original_length,p.section,p.interface,p.link,0,hashlib.sha256(p.data).digest())
                if v!=wanted:raise InvalidHistory("independent capture metadata differs")
                packets.seek((p.frame-1)*80)
                if exact(packets,80)!=row_bytes:raise InvalidHistory("packet index projection differs")
                if d.integer("Q")!=len(r.raw) or d.take(32)!=hashlib.sha256(r.raw).digest():raise InvalidHistory("raw capture record identity differs")
                ts=d.boolean()
                if ts!=(p.ticks is not None):raise InvalidHistory("timestamp presence differs")
                if ts and d.unpack("QBq")!=(p.ticks,p.resolution,p.offset):raise InvalidHistory("raw capture clock differs")
                d.end();packet_count+=1
            elif kind==2:
                item=decode_tcp(body,h);tcp_count+=1;cursor=0
                for start,end,frame,recoff,packet_start,source_offset in item["witnesses"]:
                    if start!=cursor or not start<end<=len(item["raw"]) or not 1<=frame<=packet_count:raise InvalidHistory("witness layout/frame")
                    packets.seek((frame-1)*80);p=packet_row(exact(packets,80))
                    if recoff!=p[1] or packet_start+end-start>p[3] or p[2]+packet_start!=source_offset:raise InvalidHistory("witness outside packet")
                    witness_file.seek(source_offset)
                    if exact(witness_file,end-start)!=item["raw"][start:end]:raise InvalidHistory("TCP bytes not witnessed in source")
                    cursor=end
                if cursor!=len(item["raw"]):raise InvalidHistory("incomplete witnesses")
                if item["payload"]:interval_count+=len(item["placements"])
            elif kind==3:
                d=Cursor(body);d.blob(2048).decode('utf-8');n=d.integer('I')
                if n>4096:raise InvalidHistory('notice witness budget')
                frames=d.unpack('Q'*n);d.end()
                if any(not 1<=f<=packet_count for f in frames):raise InvalidHistory('notice frame outside observed source')
                notice_count+=1
            elif kind==4:
                d=Cursor(body);n=d.integer('Q');consumed=d.integer('Q');checkpoint=d.take(32);d.end()
                if n!=packet_count or consumed!=source_bytes or checkpoint!=prior_digest:raise InvalidHistory('checkpoint prefix differs')
            elif kind==254:raise InvalidHistory("analysis aborted")
            elif kind==255:seal=body
            prior_digest=digest
        if seal is None:raise InvalidHistory("journal is an incomplete prefix")
        if next(oracle,None)is not None:raise InvalidHistory("source packets omitted from journal")
        if {"sha256":source_hash.hexdigest(),"bytes":source_bytes}!=h["source"]:raise InvalidHistory("source changed while verifying")
    d=Cursor(seal);counts=d.unpack("QQQQ");range_hash=d.take(32).hex();range_bytes=d.integer("Q");packet_hash=d.take(32).hex();packet_bytes=d.integer("Q");d.end()
    if counts!=(packet_count,tcp_count,notice_count,interval_count):raise InvalidHistory("seal counters differ")
    if identity(workspace/"packets.idx",h["limits"][1])!={"sha256":packet_hash,"bytes":packet_bytes} or packet_bytes!=packet_count*80:raise InvalidHistory("packet index seal differs")
    if identity(workspace/"ranges.idx",h["limits"][1])!={"sha256":range_hash,"bytes":range_bytes} or range_bytes!=interval_count*112:raise InvalidHistory("range index seal differs")
    # Validate sorted, unique membership without holding all intervals in RAM.
    previous=None
    with (workspace/"ranges.idx").open("rb")as index, (workspace/"journal.bin").open("rb")as journal:
        for _ in range(interval_count):
            d=Cursor(exact(index,112));g=d.take(32);direction=d.integer("B");selected=d.boolean()
            if d.take(6)!=b"\0"*6:raise InvalidHistory("range index reserved bytes")
            start,end,offset=d.unpack("qqQ");digest=d.take(32);ordinal=d.integer("Q")
            if d.integer("Q")!=0 or direction>1 or not 0<end-start<=65535 or offset<h['size']:raise InvalidHistory("range index fields")
            key=(g,direction,start,end,ordinal,offset,selected,digest)
            if previous is not None and previous>=key:raise InvalidHistory("range index unsorted or duplicated")
            previous=key;journal.seek(offset-32);prev=exact(journal,32);length=exact(journal,4);n=struct.unpack("<I",length)[0]
            if not 9<=n<=h['limits'][3]:raise InvalidHistory("indexed record budget")
            payload=exact(journal,n);stored=exact(journal,32)
            if stored!=digest or hashlib.sha256(DOMAIN+prev+length+payload).digest()!=digest:raise InvalidHistory("indexed bytes changed")
            if struct.unpack("<BQ",payload[:9])!=(2,ordinal):raise InvalidHistory("index targets wrong record")
            item=decode_tcp(payload[9:],h)
            if len(item['payload'])!=end-start or (g,direction,start,selected)not in item['placements']:raise InvalidHistory("index hypothesis differs")
    return {"schema":"pcap-evidence.history-independent-check.v1","status":"PASS",
            "source":h["source"],"packets":packet_count,"tcp_records":tcp_count,
            "intervals":interval_count,"source_witnesses_checked":True,
            "semantic_replay_verified":False,"endpoint_truth_established":False}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('workspace',type=Path);a=p.parse_args()
    try:print(json.dumps(verify(a.source,a.workspace),sort_keys=True));return 0
    except (OSError,ValueError,EOFError)as error:print(json.dumps({"status":"FAIL","error":str(error)}));return 1
if __name__=='__main__':raise SystemExit(main())
