#!/usr/bin/env python3
"""Generate independently built, public-safe parser differential cases.

No oracle output is used as a golden value. The catalog distinguishes normative
requirements, project policies and open research questions. Generation is explicit;
ordinary builds and research runs never change the committed vectors.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.product_fixtures import examples, links, pcap, packet, tcp_capture, checksum

ROOT=Path(__file__).resolve().parents[1]

def identity(b):return {"sha256":hashlib.sha256(b).hexdigest(),"bytes":str(len(b))}

def rfc(n,section,title):
    return {"id":"RFC"+str(n),"section":section,"title":title,
            "url":f"https://www.rfc-editor.org/rfc/rfc{n}.html",
            "basis":"normative_specification","review":"reference_identified_case_review_required"}

SPECS={
 "bgp":rfc(4271,"4.1–4.5; 5","BGP message headers and path attributes"),
 "bgp-errors":rfc(7606,"3–5; 7","Malformed attributes and UPDATE handling"),
 "tcp":rfc(9293,"3.3; 3.4; 3.10","TCP sequencing and segment processing"),
 "udp":rfc(768,"Format","UDP header and length"),
 "ipv4":rfc(791,"3.1; 3.2","IPv4 header and fragmentation"),
 "ipv6":rfc(8200,"3; 4.5","IPv6 header and fragmentation"),
 "arp":rfc(826,"Packet format","ARP packet fields"),
 "icmp":rfc(792,"Message formats","ICMP message envelope"),
 "icmpv6":rfc(4443,"2","ICMPv6 message format"),
 "dns":rfc(1035,"4.1; 4.1.4","DNS messages and compression"),
 "http1":rfc(9112,"2; 6","HTTP/1.1 message syntax and framing"),
 "tls":rfc(8446,"4.1.2; 5","TLS ClientHello and record envelope"),
 "quic":rfc(9000,"17","QUIC packet headers"),
 "dhcp":rfc(2131,"2","DHCP message format"),
 "dhcpv6":rfc(8415,"8–9","DHCPv6 message format"),
 "netflow9":rfc(3954,"5–7","NetFlow v9 packet and FlowSet format"),
 "snmp":rfc(3416,"4","SNMP protocol data units"),
 "ftp":rfc(959,"4.1; 4.2","FTP commands and replies"),
 "tftp":rfc(1350,"5","TFTP packet formats"),
 "pop3":rfc(1939,"3–5","POP3 responses and commands"),
 "imap":rfc(9051,"2.2; 6","IMAP commands and responses"),
 "telnet":rfc(854,"TELNET Commands","Telnet IAC commands"),
 "sip":rfc(3261,"7; 20","SIP message framing"),
 "rtp":rfc(3550,"5.1","RTP fixed header"),
 "pptp":rfc(2637,"2.1","PPTP control message header"),
 "sctp":rfc(9260,"3","SCTP common header and chunks"),
 "mpls":rfc(3032,"2.1","MPLS label stack"),
 "gre":rfc(2784,"2","GRE header"),
 "vxlan":rfc(7348,"5","VXLAN packet format"),
 "geneve":rfc(8926,"3","Geneve header and options"),
}
for name,title,section,url in [
 ("pcap","PCAP savefile specification","File header and packet records","https://www.tcpdump.org/manpages/pcap-savefile.5.html"),
 ("pcapng","PCAP Next Generation Dump File Format","Section/interface/packet blocks and timestamp options","https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-05.html"),
 ("ethernet","IEEE 802.3","Length/Type and LLC service boundary","https://standards.ieee.org/standard/802_3-2022.html"),
 ("vlan","IEEE 802.1Q","Tag control information and encapsulation",None),
 ("sll","LINKTYPE registry and Linux cooked capture","SLL and SLL2 pseudoheaders","https://www.tcpdump.org/linktypes.html"),
 ("loopback","LINKTYPE registry","NULL, LOOP, RAW, IPv4 and IPv6 link types","https://www.tcpdump.org/linktypes.html"),
 ("radiotap","Radiotap header specification","Length, alignment and presence fields","https://www.radiotap.org/"),
 ("wifi","IEEE 802.11","Data frame/LLC bounds",None),
 ("stp","IEEE 802.1D / IEEE 802.1Q","Configuration BPDU fields and timers",None),
 ("dnp3","IEEE 1815 / DNP3","Link CRC, transport/application framing",None),
 ("modbus","MODBUS Application Protocol V1.1b3 / Messaging on TCP/IP","MBAP and function-specific PDU shape","https://www.modbus.org/specs.php"),
 ("smb2","MS-SMB2","2.2.1 SMB2 packet header","https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/"),
 ("bacnet_ip","ANSI/ASHRAE 135 BACnet","Annex J BVLC; NPDU/APDU; edition review required",None),
 ("bacnet_mstp","ANSI/ASHRAE 135 BACnet","Clause 9 MS/TP header and data CRC; edition review required",None),
 ("enip_cip","ODVA CIP Networks Library","Volume 2 encapsulation/CPF; edition review required",None),
 ("goose","IEC 61850-8-1","GOOSE Ethernet/BER envelope; edition review required",None),
 ("sampled_values","IEC 61850-9-2","SV Ethernet/ASDU envelope; edition review required",None),
 ("mms","ISO 9506 / IEC 61850-8-1","MMS BER over ISO presentation; edition review required",None),
 ("iec104","IEC 60870-5-104","APCI I/S/U formats; edition review required",None),
 ("s7","S7 communication vendor documentation","TPKT/COTP/S7 envelope; primary-source review required",None),
 ("hart_ip","FieldComm HART-IP specification","Message header; primary-source review required",None),
 ("fins_udp","OMRON W342 Communications Commands","FINS header; revision review required",None),
 ("fins_tcp","OMRON W342 Communications Commands","FINS/TCP envelope; revision review required",None),
 ("ads","Beckhoff ADS/AMS documentation","AMS/TCP and AMS packet header","https://infosys.beckhoff.com/"),
 ("opcua_tcp","OPC UA Part 6","7.1 UA TCP message header","https://reference.opcfoundation.org/Core/Part6/"),
 ("melsec_3e","MELSEC MC Protocol Reference Manual","Binary 3E frame; revision review required",None),
 ("c37118","IEEE C37.118.2","Common frame/SYNC/CRC; edition review required",None),
 ("ethercat","EtherCAT specification / IEC 61158","EtherCAT frame/datagram header; edition review required",None),
 ("profinet_rt","PROFINET specification / IEC 61158","RT frame identification; edition review required",None),
 ("powerlink","Ethernet POWERLINK specification","Message/node envelope; edition review required",None),
]:
 SPECS[name]={"id":name,"section":section,"title":title,"url":url,"basis":"normative_specification",
              "review":"primary_edition_access_required" if url is None else "reference_identified_case_review_required"}
SPECS["evidence-policy"]={"id":"evidence-policy-v1","section":"docs/implementation/TRUST_ROOT.md; docs/streaming/CONTRACT.md",
 "title":"Independent evidence policy","url":None,"basis":"project_invariant","review":"documented_not_external_specification",
 "requirement":"Never bridge missing bytes, hide competing interpretations, invent clocks, or use parser votes as authority."}

# One independently constructed scalar KAT for each new decoder where exposed.
GOLDEN={"netflow9":("declared_record_count","1"),"bgp":("message_type","4"),"snmp":("version","1"),
        "tftp":("opcode","1"),"rtp":("version","2")}


def core_vectors():
    dns=bytes.fromhex("123401000001000000000000076578616d706c6504746573740000010001")
    eth=packet(dns,"udp");ip=eth[14:]
    vlan=eth[:12]+b"\x81\0\0\x2a"+eth[12:]
    qinq=eth[:12]+b"\x88\xa8\0\x07\x81\0\0\x2a"+eth[12:]
    arp=eth[:12]+b"\x08\x06"+struct.pack("!HHBBH",1,0x800,6,4,1)+bytes.fromhex("020000000001c0000201000000000000c0000202")
    ipv6=struct.pack("!IHBB16s16s",6<<28,8,17,64,bytes.fromhex("20010db8000000000000000000000001"),bytes.fromhex("20010db8000000000000000000000002"))+struct.pack("!HHHH",40000,41000,8,1)
    icmp=b"\x08\0\0\0\0\1\0\1";icmp=icmp[:2]+struct.pack("!H",checksum(icmp))+icmp[4:]
    def v4(body,proto):
        h=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(body),1,0,64,proto,0,bytes([192,0,2,1]),bytes([198,51,100,2]));h=h[:10]+struct.pack("!H",checksum(h))+h[12:];return eth[:12]+b"\x08\0"+h+body
    def outer_udp(body,port):
        base=packet(body,"udp");out=bytearray(base);out[36:38]=struct.pack("!H",port);out[40:42]=b"\0\0";return bytes(out) # IPv4 permits absent UDP checksum.
    wifi=bytes.fromhex("080000000200000000020200000000010200000000030000aaaa030000000800")+ip
    rtap=b"\0\0\x08\0\0\0\0\0"+wifi
    sll=struct.pack("!HHH8sH",0,1,6,bytes.fromhex("0200000000010000"),0x800)+ip
    sll2=struct.pack("!HHIHBB8s",0x800,0,1,1,0,6,bytes.fromhex("0200000000010000"))+ip
    return {"ethernet":(eth,1),"vlan":(vlan,1),"qinq":(qinq,1),"sll":(sll,113),"sll2":(sll2,276),
     "loopback":(struct.pack("<I",2)+ip,0),"raw_ip":(ip,101),"ipv4":(eth,1),"ipv6":(eth[:12]+b"\x86\xdd"+ipv6,1),
     "udp":(eth,1),"tcp":(packet(b"abc","tcp"),1),"arp":(arp,1),"icmp":(v4(icmp,1),1),
     "icmpv6":(eth[:12]+b"\x86\xdd"+ipv6[:6]+bytes([58])+ipv6[7:40]+b"\x80\0\0\0\0\1\0\1",1),
     "sctp":(v4(struct.pack("!HHII",40000,41000,1,0),132),1),
     "mpls":(eth[:12]+b"\x88\x47"+struct.pack("!I",(16<<12)|0x100|64)+ip,1),
     "gre":(v4(b"\0\0\x08\0"+ip,47),1),
     "vxlan":(outer_udp(b"\x08\0\0\0\0\0\x2a\0"+eth,4789),1),
     "geneve":(outer_udp(b"\0\0\x65\x58\0\0\x2a\0"+eth,6081),1),
     "radiotap":(rtap,127),"wifi":(wifi,105),"dns":(eth,1)}


def generate(root=ROOT):
    root=Path(root);folder=root/"product/research/fixtures";folder.mkdir(parents=True,exist_ok=True)
    cases=[];families=[]
    def store(name,b):
        rel="product/research/fixtures/"+name;(root/rel).write_bytes(b)
        return {"path":rel,"identity":identity(b)}
    def family(name,layer,conformance,adversarial,prop="all_protocol_mutations_are_deterministic",semantic=False):
        families.append({"id":name,"layer":layer,"conformance":conformance,"adversarial":adversarial,
          "properties":[{"path":"product/tests/research_properties.rs","selector":prop}],
          "fuzz":[{"path":"product/fuzz/fuzz_targets/research.rs","selector":"fuzz_target!"}],
          "differential":[{"adapter":"native-probe" if semantic else "product-events","status":"semantic_adapter_implemented" if semantic else "capture_fields_only"},
                          {"adapter":"tshark-fields","status":"capture_transport_fields_only"},
                          {"adapter":"attributed-normalized-import","status":"explicit_per_field_normalization_required"}],
          "normative_review":"pending","qualification_receipts":[],"support_depth":"see docs/PROTOCOL_MATRIX.md"})
    def add(name,layer,body,cap,protocol=None,spec=None):
        spec=spec or name; spec=spec if spec in SPECS else "evidence-policy"
        valid=name+".framing-kat";bad=name+".short-header"
        payload=store(name+".valid.bin",body);capture=store(name+".valid.pcap",cap)
        rules=[{"path":"/observation/result","op":"equals","value":"decoded","basis":"normative_specification"}]
        if name in GOLDEN:
            field,value=GOLDEN[name];rules.append({"path":"/observation/decoded/fields/"+field,"op":"equals","value":value,"basis":"normative_specification"})
        cases.append({"id":valid,"family":name,"layer":layer,"kind":"conformance","native_protocol":protocol,
          "payload":payload,"capture":capture,"specifications":[spec],"assertions":rules if protocol else [],
          "rationale":"Independently constructed header/envelope, not copied from another parser. Scope is the named framing subset, not whole-protocol conformance.",
          "state_witness":{"capture_time_driven":True,"port_is_not_identity":True,"raw_payload_sha256":payload["identity"]["sha256"]}})
        truncated=body[:1];bc=store(name+".short.bin",truncated)
        cases.append({"id":bad,"family":name,"layer":layer,"kind":"adversarial","native_protocol":protocol,
          "payload":bc,"capture":None,"specifications":[spec,"evidence-policy"],
          "assertions":[{"path":"/observation/result","op":"equals","value":"error","basis":"project_invariant"}] if protocol else [],
          "rationale":"A one-octet prefix cannot establish this supported frame. Preserve the bytes and fail/incomplete explicitly; do not speculate about endpoint action."})
        family(name,layer,[valid],[bad],semantic=protocol is not None)
    for name,(variant,transport,body,feature) in examples().items():
        add(name,"protocol_message",body,tcp_capture(body) if transport=="tcp" else pcap([packet(body,"udp")]),name)
    for name,(raw,link,feature) in links().items():add(name,"link_layer",raw,pcap([raw],link))
    for name,(raw,link) in core_vectors().items():
        add(name,"protocol_message" if name=="dns" else "transport_identity" if name in {"tcp","udp","sctp"} else "network_layer" if name in {"ipv4","ipv6","icmp","icmpv6"} else "link_layer",raw,pcap([raw],link),spec={"qinq":"vlan","sll2":"sll","raw_ip":"loopback"}.get(name,name))
    # Container byte-order and exact-timestamp cases are independent of all protocols.
    raw=packet(b"\0","udp")
    for endian in ("le","be"):
        for precision in ("us","ns"):
            e="<" if endian=="le" else ">";magic=0xa1b2c3d4 if precision=="us" else 0xa1b23c4d
            cap=struct.pack(e+"IHHIIII",magic,2,4,0,0,65535,1)+struct.pack(e+"IIII",7,123,len(raw),len(raw))+raw
            name="pcap_"+endian+"_"+precision;entry=store(name+".pcap",cap)
            good=name+".exact-clock";bad=name+".truncated-record"
            cases.append({"id":good,"family":name,"layer":"capture_record","kind":"conformance","capture":entry,"specifications":["pcap"],"assertions":[],
              "expected_container":{"packets":1,"unix_ns":str(7_000_000_000+123*(1000 if precision=="us" else 1)),"captured_length":len(raw)},
              "rationale":"All magic/order/precision variants independently encode 7 seconds plus 123 ticks."})
            short=store(name+".short.pcap",cap[:-1]);cases.append({"id":bad,"family":name,"layer":"capture_record","kind":"adversarial","capture":short,"specifications":["pcap"],"assertions":[],"expected_container":{"result":"error"},"rationale":"Captured length exceeds the remaining physical record bytes; never pad or synthesize the absent byte."})
            family(name,"capture_record",[good],[bad],"reader_chunking_preserves_record_bytes")
    # Inherited families get independent, minimal wire fixtures as research seeds.
    # Native whole-protocol qualification remains separate from container checks.
    from scripts.product_fixtures import crc
    dhcp=bytearray(240);dhcp[:4]=bytes([1,1,6,0]);dhcp[4:8]=bytes.fromhex("01020304");dhcp[236:240]=bytes.fromhex("63825363");dhcp+=bytes([53,1,1,255])
    hello=bytes.fromhex("0303")+bytes(32)+b"\0"+bytes.fromhex("0002c02f01000000")
    handshake=b"\1"+len(hello).to_bytes(3,"big")+hello
    tls=bytes.fromhex("160303")+len(handshake).to_bytes(2,"big")+handshake
    smb=bytes.fromhex("fe534d424000")+bytes(58);smb=len(smb).to_bytes(4,"big")+smb
    dnpheader=bytes.fromhex("056408c401000200");user=bytes.fromhex("c0c001")
    dnp=dnpheader+crc(dnpheader,16,0xa6bc,0,True,65535).to_bytes(2,"little")+user+crc(user,16,0xa6bc,0,True,65535).to_bytes(2,"little")
    inherited={"http1":b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", "tls":tls,
      "quic":bytes.fromhex("c00000000108000102030405060700000100"), "dhcp":bytes(dhcp),
      "dhcpv6":bytes.fromhex("01010203"),"smb2":smb,"dnp3":dnp,"modbus":bytes.fromhex("000100000006010300000001")}
    for name,body in inherited.items():
        cap=pcap([packet(body,"udp")]) if name in {"quic","dhcp","dhcpv6"} else tcp_capture(body)
        add(name,"protocol_message",body,cap)
    # PCAPNG exact timestamp and missing-time representations.
    raw=packet(b"x","udp")
    def block(ty,body):
        body+=bytes((-len(body))%4);n=12+len(body);return struct.pack("<II",ty,n)+body+struct.pack("<I",n)
    shb=block(0x0a0d0d0a,struct.pack("<IHHq",0x1a2b3c4d,1,0,-1));idb=block(1,struct.pack("<HHI",1,0,65535))
    ng=shb+idb+block(6,struct.pack("<IIIII",0,0,1000001,len(raw),len(raw))+raw)
    add("pcapng","capture_record",ng,ng)
    cases[-2]["expected_container"]={"packets":1,"unix_ns":"1000001000","captured_length":len(raw)}
    cases[-1]["capture"]=store("pcapng.bad-trailer.pcap",ng[:-1]+bytes([ng[-1]^1]));cases[-1]["expected_container"]={"result":"error"}
    llc=bytes.fromhex("aaaa030000000800")+raw[14:]
    ethernet=raw[:12]+len(llc).to_bytes(2,"big")+llc
    add("ieee8023_llc","link_layer",ethernet,pcap([ethernet]),spec="ethernet")
    segs=[packet(b"","tcp",1000,0,2),packet(b"ab","tcp",1001),packet(b"ef","tcp",1005),packet(b"cd","tcp",1003),packet(b"cd","tcp",1003)]
    tcp_cap=pcap(segs);add("tcp_reassembly","tcp_reconstruction",tcp_cap,tcp_cap,spec="tcp")
    families[-1]["properties"]=[{"path":"product/tests/research_properties.rs","selector":"tcp_sequence_wrap_reordering_and_duplicate_invariants"}]
    cases[-2]["state_witness"]={"stream_hex":"616263646566","duplicate_bytes":2,"ordering":"sequence_not_capture_time","handshake_incomplete":True}
    # Nonoverlapping two-fragment IPv4 datagram; header checksum is recomputed.
    raw=packet(bytes(range(32)),"udp");h=raw[14:34];payload=raw[34:]
    frags=[]
    for off,data,more in [(0,payload[:16],True),(16,payload[16:],False)]:
        ip=bytearray(h);ip[2:4]=(20+len(data)).to_bytes(2,"big");ip[6:8]=((0x2000 if more else 0)|off//8).to_bytes(2,"big");ip[10:12]=b"\0\0";ip[10:12]=checksum(bytes(ip)).to_bytes(2,"big")
        frags.append(raw[:14]+bytes(ip)+data)
    fragcap=pcap(frags);add("ip_fragments","fragment_set",fragcap,fragcap,spec="ipv4")
    catalog={"schema":"pcap-evidence.research-catalog.v1","objective":"parser_differentials_are_first_class_security_research_targets",
      "authority":"source_bytes_primary_specs_explicit_state_not_consensus","case_coverage_is_not_qualification":True,
      "specifications":SPECS,"families":families,"cases":cases}
    (root/"product/research/catalog.json").write_text(json.dumps(catalog,indent=2)+"\n",encoding="utf-8")
    return catalog

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--root",type=Path,default=ROOT);a=p.parse_args()
    result=generate(a.root);print(json.dumps({"families":len(result["families"]),"cases":len(result["cases"])}))
