"""Original minimal fixtures; no network, external captures, or Rust encoder use.

Modbus FC15/16 request bytes follow the published V1.1b3 worked examples.
DNP3 payloads are explicit project subset cases, not IEEE certification vectors.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct

ROOT = Path(__file__).resolve().parents[1]

def checksum(data):
    data = data + b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(data)//2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535

def tcp(payload, seq, ack, flags, *, reverse=False, port=502):
    src, dst = (bytes([192,0,2,1]),bytes([192,0,2,2]))
    sp, dp = 41000, port
    if reverse:
        src, dst, sp, dp = dst, src, dp, sp
    header=struct.pack('!HHIIBBHHH', sp,dp,seq,ack,0x50,flags,32768,0,0)
    packet=header+payload
    ck=checksum(src+dst+bytes([0,6])+struct.pack('!H',len(packet))+packet)
    packet=packet[:16]+struct.pack('!H',ck)+packet[18:]
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,len(packet)+20,1,0,64,6,0,src,dst)
    ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    return bytes.fromhex('0200000000020200000000010800')+ip+packet

def pcap(packets):
    out=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    for i, p in enumerate(packets):
        out.extend(struct.pack('<IIII',1700000000,i*1000,len(p),len(p)))
        out.extend(p)
    return bytes(out)

def adu(pdu):
    return struct.pack('!HHHB',42,0,len(pdu)+1,1)+pdu

def handshake(port):
    return [tcp(b'',1000,0,2,port=port), tcp(b'',5000,1001,0x12,reverse=True,port=port),
            tcp(b'',1001,5001,0x10,port=port)]

def dnp_crc(data):
    value=0
    for b in data:
        value ^= b
        for _ in range(8):
            value = (value>>1) ^ (0xa6bc if value&1 else 0)
    return value ^ 65535

def link(user, reverse=False):
    source,dest = (2,1) if reverse else (1,2)
    header=bytes([5,100,5+len(user),0x44 if reverse else 0xc4])+struct.pack('<HH',dest,source)
    out=header+struct.pack('<H',dnp_crc(header))
    for at in range(0,len(user),16):
        block=user[at:at+16]
        out += block+struct.pack('<H',dnp_crc(block))
    return out

def fixtures():
    result={}
    for name,last in [('modbus_bits_valid',1),('modbus_bits_bad_padding',0x81)]:
        request=adu(bytes.fromhex('0100000009'))
        response=adu(bytes([1,2,255,last]))
        packets=handshake(502)+[tcp(request,1001,5001,0x18),
            tcp(response[5:],5006,1001+len(request),0x18,reverse=True),
            tcp(response[:5],5001,1001+len(request),0x18,reverse=True)]
        result[name+'.pcap']=pcap(packets)
    req=link(bytes.fromhex('c0c0010101000009'))
    rsp=link(bytes.fromhex('c0c081000001010000094d03'),True)
    base=handshake(20000)+[tcp(req,1001,5001,0x18,port=20000)]
    for mode in ('valid','gap','conflict'):
        tail_start=11 if mode=='gap' else 10
        packets=base+[tcp(rsp[tail_start:],5001+tail_start,1001+len(req),0x18,reverse=True,port=20000),
                      tcp(rsp[:10],5001,1001+len(req),0x18,reverse=True,port=20000)]
        if mode=='valid':
            packets.append(tcp(rsp[:10],5001,1001+len(req),0x18,reverse=True,port=20000))
        elif mode=='conflict':
            bad=bytearray(rsp[:10]);bad[8]^=1
            packets.append(tcp(bytes(bad),5001,1001+len(req),0x18,reverse=True,port=20000))
        result['dnp3_split_'+mode+'.pcap']=pcap(packets)
    return result

def cases():
    # Expected named field values are immutable assertions, not copied tool output.
    raw=[
        ('dnp-read','dnp3','read','3c02063c03063c0406','decoded_subset',[],[]),
        ('dnp-packed','dnp3','response','01010000094d03','decoded_subset',
         [('value',0,True),('value',1,False),('point_index',9,'9')],[]),
        ('dnp-counter','dnp3','response','14020702010a00011400','decoded_subset',
         [('value',0,'10'),('value',1,'20')],[]),
        ('dnp-duplicate-index','dnp3','response','1402170205010a0005011400','decoded_subset',
         [('point_index',0,'5'),('point_index',1,'5'),('value',1,'20')],[]),
        ('dnp-signed','dnp3','response','1e0100010201feffffff0100000080','decoded_subset',
         [('value',0,'-2'),('value',1,'-2147483648')],[]),
        ('dnp-float-bits','dnp3','response','1e05000001010100c07f0100000080','decoded_subset',
         [('value',0,'7fc00001'),('value',1,'80000000')],[]),
        ('dnp-relative','dnp3','response','0203170104813412','decoded_subset',
         [('time',0,'4660')],[]),
        ('dnp-unknown','dnp3','response','63630701010200000081','unsupported',[],[]),
        ('dnp-truncated','dnp3','response','14020702010a0001','incomplete',[('value',0,'10')],[]),
        ('dnp-inverted','dnp3','response','0102000807','rejected',[],[]),
        ('modbus-fc15-example','modbus','request','0f0013000a02cd01','decoded_subset',
         [('starting_address_zero_based',0,'19'),('quantity',0,'10'),('address_zero_based',9,'28')],[]),
        ('modbus-fc16-example','modbus','request','100001000204000a0102','decoded_subset',
         [('register_u16',0,'10'),('register_u16',1,'258')],[]),
        ('modbus-read','modbus','request','030000007d','decoded_subset',[('quantity',0,'125')],[]),
        ('modbus-read-over','modbus','request','030000007e','rejected',[],[]),
        ('modbus-register-response','modbus','response','0304000a0102','decoded_subset',
         [('register_u16',0,'10'),('register_u16',1,'258')],['address_zero_based']),
        ('modbus-bit-response','modbus','response','0102ffff','decoded_subset',
         [('packed_lsb_first',0,'255')],['value','address_zero_based']),
        ('modbus-exception','modbus','response','8302','decoded_subset',[('exception_code',0,'2')],[]),
        ('modbus-unsupported','modbus','request','16000100ff0100','unsupported',[],[]),
    ]
    out=[]
    for ident,protocol,context,hex_data,status,fields,absent in raw:
        payload=bytes.fromhex(hex_data)
        if protocol=='modbus': payload=adu(payload)
        out.append(dict(id=ident,protocol=protocol,context=context,path=ident+'.bin',
            bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest(),hex=payload.hex(),
            expected=dict(status=status,fields=[dict(name=n,ordinal=i,value=v)for n,i,v in fields],absent_fields=absent),
            basis='modbus-v1.1b3' if protocol=='modbus' else 'dnp3-project-subset-cross-checked-reference',
            normative_review='NOT_RUN'))
    return out

def write(destination):
    destination.mkdir(parents=True,exist_ok=True)
    values=fixtures()
    cases_list=cases()
    for case in cases_list: values[case['path']]=bytes.fromhex(case['hex'])
    for name,data in values.items():
        path=destination/name
        if path.exists() and path.read_bytes()!=data:
            raise ValueError('refuse to overwrite differing fixture '+name)
        if not path.exists():path.write_bytes(data)
    manifest=dict(schema='pcap-evidence.semantic-cases.v1',cases=cases_list,
        captures=[dict(path=n,bytes=len(d),sha256=hashlib.sha256(d).hexdigest())for n,d in values.items()if n.endswith('.pcap')],
        rights='original synthetic test bytes; MIT project license',
        source='scripts/make_semantic_fixtures.py',
        qualified=False)
    path=destination/'manifest.json'
    data=(json.dumps(manifest,indent=2)+'\n').encode()
    if path.exists() and path.read_bytes()!=data:raise ValueError('differing manifest exists')
    if not path.exists():path.write_bytes(data)
    return manifest

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'fixtures/semantics');a=p.parse_args()
    print(json.dumps(dict(cases=len(write(a.output)['cases']),status='GENERATED_NOT_QUALIFIED')))
