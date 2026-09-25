"""Independent minimal byte constructors for framing contracts.

Synthetic documentation ranges only. These fixtures establish the documented
subset, not valid whole-device transactions or proof of every normative rule.
No parser under test or external analyzer supplies expected values.
"""
from __future__ import annotations
import json
import struct
from pathlib import Path

def checksum(data):
    data+=bytes(len(data)%2)
    n=sum(struct.unpack("!"+"H"*(len(data)//2),data))
    while n>>16:n=(n&65535)+(n>>16)
    return (~n)&65535

def crc(data,width,poly,initial,reflected,xor):
    c=initial;mask=(1<<width)-1
    for v in data:
        c^=v if reflected else v<<(width-8)
        for _ in range(8):
            c=((c>>1)^poly if c&1 else c>>1) if reflected else ((c<<1)^poly if c&(1<<(width-1))else c<<1)
            c&=mask
    return c^xor

def packet(payload,transport,seq=1001,ack=5001,flags=0x18,reverse=False,src_port=40000,dst_port=41000):
    a,b=bytes([192,0,2,1]),bytes([198,51,100,2])
    if reverse:a,b=b,a;src_port,dst_port=dst_port,src_port
    if transport=="tcp":proto=6;body=struct.pack("!HHIIBBHHH",src_port,dst_port,seq,ack,0x50,flags,32768,0,0)+payload;checkat=16
    else:proto=17;body=struct.pack("!HHHH",src_port,dst_port,8+len(payload),0)+payload;checkat=6
    check=checksum(a+b+struct.pack("!BBH",0,proto,len(body))+body)
    body=body[:checkat]+struct.pack("!H",check or 65535)+body[checkat+2:]
    h=struct.pack("!BBHHHBBH4s4s",0x45,0,len(body)+20,1,0x4000,64,proto,0,a,b)
    h=h[:10]+struct.pack("!H",checksum(h))+h[12:]
    return bytes.fromhex("0200000000020200000000010800")+h+body

def pcap(packets,link=1):
    out=bytearray(struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65535,link))
    for i,p in enumerate(packets):out+=struct.pack("<IIII",7,i,len(p),len(p))+p
    return bytes(out)

def tcp_capture(payload):
    return pcap([packet(b"","tcp",1000,0,2),packet(b"","tcp",5000,1001,0x12,True),
                 packet(b"","tcp",1001,5001,0x10),packet(payload,"tcp",1001,5001,0x18),
                 packet(b"","tcp",1001+len(payload),5001,0x11),
                 packet(b"","tcp",5001,1002+len(payload),0x11,True),
                 packet(b"","tcp",1002+len(payload),5002,0x10)])

def ber(tag,value):
    n=len(value)
    if n<128:length=bytes([n])
    else:width=(n.bit_length()+7)//8;length=bytes([128+width])+n.to_bytes(width,"big")
    return bytes([tag])+length+value

def examples():
    rows={}
    def put(name,variant,t,body,feature="extensions"):rows[name]=(variant,t,body,feature)
    put("netflow9","Netflow9","udp",struct.pack("!HHIIII",9,1,0,7,1,1)+struct.pack("!HHHHHH",0,12,256,1,8,4),"standard")
    put("bgp","Bgp","tcp",bytes([255])*16+struct.pack("!HB",19,4))
    binding=ber(0x30,ber(6,bytes.fromhex("2b06010201010100"))+ber(5,b""))
    snmp=ber(0x30,ber(2,b"\1")+ber(4,b"public")+ber(0xa0,ber(2,b"\1")+ber(2,b"\0")+ber(2,b"\0")+ber(0x30,binding)))
    put("snmp","Snmp","udp",snmp)
    for name,variant,body in [("ftp","Ftp",b"NOOP\r\n"),("pop3","Pop3",b"+OK ready\r\n"),("imap","Imap",b"A1 NOOP\r\n"),("telnet","Telnet",bytes([255,251,1]))]:put(name,variant,"tcp",body)
    put("tftp","Tftp","udp",b"\0\1example\0octet\0")
    put("sip","Sip","tcp",b"OPTIONS sip:example.test SIP/2.0\r\nVia: SIP/2.0/TCP example.test\r\nContent-Length: 0\r\n\r\n")
    put("rtp","Rtp","udp",struct.pack("!BBHII",0x80,96,1,1234,1))
    put("pptp","Pptp","tcp",struct.pack("!HHIHH",12,1,0x1a2b3c4d,5,0))
    put("bacnet_ip","BacnetIp","udp",bytes.fromhex("810a000801001008"),"industrial")
    put("enip_cip","Enip","tcp",struct.pack("<HHII8sI",0x65,4,0,0,bytes(8),0)+struct.pack("<HH",1,0),"industrial")
    put("mms","Mms","tcp",ber(0xa0,ber(2,b"\1")+ber(0xa1,b"")),"industrial")
    put("iec104","Iec104","tcp",bytes.fromhex("680407000000"),"industrial-full")
    s7=bytes.fromhex("32010000000100000000");put("s7","S7","tcp",struct.pack("!BBH",3,0,7+len(s7))+bytes.fromhex("02f080")+s7,"industrial-full")
    put("hart_ip","HartIp","tcp",struct.pack("!BBBBHH",1,0,1,0,1,8),"industrial-full")
    fins=bytes.fromhex("800002000100000200010101");put("fins_udp","FinsUdp","udp",fins,"industrial-full")
    put("fins_tcp","FinsTcp","tcp",b"FINS"+struct.pack("!III",8,0,0),"industrial-full")
    ams=bytearray(38);struct.pack_into("<I",ams,2,32);struct.pack_into("<H",ams,22,1);struct.pack_into("<I",ams,34,1)
    put("ads","Ads","tcp",bytes(ams),"industrial-full")
    put("opcua_tcp","OpcUa","tcp",b"ACKF"+struct.pack("<IIIIII",28,0,65536,65536,0,0),"industrial-full")
    melsec=bytes.fromhex("500000ffff0300")+struct.pack("<HHHH",6,16,0x0401,0)
    put("melsec_3e","Melsec","tcp",melsec,"industrial-full")
    c=bytes.fromhex("aa31")+struct.pack("!HHII",16,1,7,0);c+=struct.pack("!H",crc(c,16,0x1021,0xffff,False,0));put("c37118","Synchrophasor","tcp",c,"industrial-full")
    return rows

def links():
    header=bytes.fromhex("020000000002020000000001")
    body=bytes([0,1,2,0,0]);mstp=b"\x55\xff"+body+bytes([crc(body,8,0x81,255,True,255)])
    goose=ber(0x61,ber(0x80,b"example")+ber(0x81,b"\x03\xe8")+ber(0x82,b"dataset")+ber(0x83,b"goose")+ber(0x84,bytes(8))+ber(0x85,b"\1")+ber(0x86,b"\0")+ber(0x87,b"\0")+ber(0x88,b"\1")+ber(0x89,b"\0")+ber(0x8a,b"\0")+ber(0xab,b""))
    sv=ber(0x60,ber(0x80,b"\1")+ber(0xa2,ber(0x30,ber(0x80,b"example")+ber(0x82,bytes(2))+ber(0x83,bytes([0,0,0,1]))+ber(0x85,b"\0")+ber(0x87,b"\0\0\0\0"))))
    def iec(ty,body):return header+struct.pack("!H",ty)+struct.pack("!HHHH",1,len(body)+8,0,0)+body
    # EtherCAT NOP with zero data and explicit WKC.
    ethercat=struct.pack("<H",0x100c)+bytes(12)
    return {"bacnet_mstp":(mstp,165,"industrial"),"goose":(iec(0x88b8,goose),1,"industrial"),
            "sampled_values":(iec(0x88ba,sv),1,"industrial"),
            "ethercat":(header+b"\x88\xa4"+ethercat,1,"industrial-full"),
            "profinet_rt":(header+b"\x88\x92"+bytes.fromhex("800000018000"),1,"industrial-full"),
            "powerlink":(header+b"\x88\xab"+bytes([1,255,240]),1,"industrial-full"),
            "stp":(header+struct.pack("!H",7)+bytes.fromhex("42420300000080"),1,"standard")}

def generate(root):
    root=Path(root);folder=root/"product/tests/fixtures";folder.mkdir(parents=True,exist_ok=True)
    inventory=[]
    for name,(variant,t,body,feature) in examples().items():
        (folder/(name+".bin")).write_bytes(body)
        (folder/(name+".pcap")).write_bytes(tcp_capture(body)if t=="tcp"else pcap([packet(body,t)]))
        inventory.append({"protocol":name,"variant":variant,"transport":t,"feature":feature})
    for name,(body,link,feature)in links().items():
        (folder/(name+".pcap")).write_bytes(pcap([body],link))
    (folder/"inventory.json").write_text(json.dumps(inventory,indent=2)+"\n")
    return inventory
if __name__=="__main__":generate(Path(__file__).resolve().parents[1])
