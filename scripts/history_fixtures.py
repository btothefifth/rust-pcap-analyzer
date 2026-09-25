"""Independent byte construction for focused TCP-history acceptance cases.

RFC 9293 §§3.4, 3.6; RFC 791 §3.1. This builder does not import the Rust
encoder. Traffic is synthetic documentation-address traffic, never transmitted.
"""
from pathlib import Path
import hashlib
import json
import struct

def checksum(data):
    if len(data)%2:data+=b"\0"
    value=sum(struct.unpack("!"+"H"*(len(data)//2),data))
    while value>>16:value=(value&65535)+(value>>16)
    return (~value)&65535

def frame(seq,flags,payload=b"",src_port=12000):
    src=b"\xc0\x00\x02\x01";dst=b"\xc0\x00\x02\x02"
    tcp=struct.pack("!HHIIBBHHH",src_port,20000,seq,0,0x50,flags,4096,0,0)+payload
    value=checksum(src+dst+b"\0\x06"+struct.pack("!H",len(tcp))+tcp)
    tcp=tcp[:16]+struct.pack("!H",value)+tcp[18:]
    ip=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(tcp),1,0,64,6,0,src,dst)
    ip=ip[:10]+struct.pack("!H",checksum(ip))+ip[12:]
    return bytes.fromhex("0200000000020200000000010800")+ip+tcp

def capture(rows):
    out=bytearray(struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65535,1))
    for n,p in enumerate(rows):out.extend(struct.pack("<IIII",1,n,len(p),len(p)));out.extend(p)
    return bytes(out)

def generate(root):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    cases={
      "reorder":capture([frame(100,2),frame(104,16,b"def"),frame(101,16,b"abc"),frame(101,16,b"abc")]),
      "late-conflict":capture([frame(100,2),frame(101,16,b"abc"),frame(104,17),frame(102,16,b"X")]),
      "reuse":capture([frame(100,2),frame(101,20,b"old"),frame(100,2),frame(101,16,b"old")]),
      "interleaved":capture([frame(100,2,src_port=p) for p in range(12000,12020)]+[frame(101,16,bytes([p-12000]),p) for p in range(12000,12020)]),
      "missing-handshake":capture([frame(9000,16,b"abc"),frame(9003,16,b"def")]),
      "wrap":capture([frame(0xfffffffd,2),frame(0xfffffffe,16,b"ab"),frame(0,16,b"cd")]),
    }
    manifest={"schema":"pcap-evidence.history-fixtures.v1","sources":["https://www.rfc-editor.org/rfc/rfc9293.html#section-3.4","https://www.rfc-editor.org/rfc/rfc791.html#section-3.1"],"fixtures":{}}
    for name,data in cases.items():
        (root/(name+".pcap")).write_bytes(data);manifest["fixtures"][name]={"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data),"rights":"original synthetic test data","normative_review":"NOT_REVIEWED"}
    (root/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
if __name__=="__main__":generate(Path(__file__).resolve().parents[1]/"history"/"fixtures")
