"""Independent history-format witnesses; these do not execute the Rust producer."""
from __future__ import annotations
import hashlib
import io
import struct
import tempfile
import unittest
from pathlib import Path
from tools import history_native as h


def blob(b):return struct.pack('<I',len(b))+b

def capture():
    # Classic little-endian PCAP, raw IPv4/TCP, one explicitly witnessed payload.
    tcp=struct.pack('!HHIIHHHH',40000,502,100,0,0x5018,4096,0,0)+b'abc'
    ip=bytes.fromhex('4500002b0000000040060000c0000201c0000202')
    packet=ip+tcp
    global_header=bytes.fromhex('d4c3b2a1020004000000000000000000ffff000065000000')
    record=struct.pack('<IIII',1,123,len(packet),len(packet))+packet
    return global_header+record,record,packet,tcp


def build_fixture(root,*,mutate_row=False,mutate_witness=False,placement_duplicates=False):
    raw,record,packet,tcp=capture();source=root/'source.pcap';source.write_bytes(raw)
    work=root/'history';work.mkdir()
    limits=[1024**4,1024**4,20_000_000_000,2*1024*1024,64,128,2048,16,16*1024*1024,32768,16,65536,4096,128*1024*1024,10000]
    config=blob(h.ENGINE)+struct.pack('<'+'Q'*15,*limits)+b'\0'
    body=hashlib.sha256(raw).digest()+struct.pack('<Q',len(raw))+blob(config)
    prefix=h.MAGIC+struct.pack('<I',len(body))+body;previous=hashlib.sha256(prefix).digest();journal=bytearray(prefix+previous);sequence=0
    def emit(kind,body):
        nonlocal previous,sequence
        at=len(journal);sequence+=1
        payload=struct.pack('<BQ',kind,sequence)+body;length=struct.pack('<I',len(payload))
        previous=hashlib.sha256(h.DOMAIN+previous+length+payload).digest();journal.extend(length+payload+previous)
        return at,previous,sequence
    row=struct.pack('<QQQIIIIII32s',1,24,40+(1 if mutate_row else 0),len(packet),len(packet),0,0,101,0,hashlib.sha256(packet).digest())
    emit(1,row+struct.pack('<Q',len(record))+hashlib.sha256(record).digest()+b'\1'+struct.pack('<QBq',1000123,6,0))
    key=struct.pack('<II',0,0)+b'\0\0'+b'\4'+bytes([192,0,2,1])+struct.pack('<H',40000)+b'\4'+bytes([192,0,2,2])+struct.pack('<H',502)
    witness=struct.pack('<IIQQIQ',0,len(tcp),1,24,20,60+(1 if mutate_witness else 0))
    inp=blob(key)+b'\0'+struct.pack('<Q',1)+b'\1'+(1_000_123_000).to_bytes(16,'little',signed=True)+blob(tcp)+struct.pack('<I',1)+witness
    gen=hashlib.sha256(b'not-a-normative-generation;fixture-only').digest()
    placement=gen+b'\0'+struct.pack('<q',0)+b'\1'
    decision=b'\0'*64+b'\0'+struct.pack('<I',2 if placement_duplicates else 1)+placement*(2 if placement_duplicates else 1)+struct.pack('<I',0)
    at,digest,seq=emit(2,blob(inp)+blob(decision))
    index=gen+b'\0\1'+b'\0'*6+struct.pack('<qqQ',0,3,at)+digest+struct.pack('<QQ',seq,0)
    emit(255,struct.pack('<QQQQ',1,1,0,1)+hashlib.sha256(index).digest()+struct.pack('<Q',len(index))+hashlib.sha256(row).digest()+struct.pack('<Q',len(row)))
    (work/'journal.bin').write_bytes(journal);(work/'packets.idx').write_bytes(row);(work/'ranges.idx').write_bytes(index)
    return source,work

class IndependentJournal(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def test_source_witness_and_membership(self):
        source,work=build_fixture(self.root);r=h.verify(source,work)
        self.assertEqual((r['packets'],r['tcp_records'],r['intervals']),(1,1,1))
        self.assertTrue(r['source_witnesses_checked']);self.assertFalse(r['semantic_replay_verified'])
    def test_torn_terminal(self):
        s,w=build_fixture(self.root);p=w/'journal.bin';p.write_bytes(p.read_bytes()[:-7])
        with self.assertRaises(h.TruncatedHistory):h.verify(s,w)
    def test_missing_terminal(self):
        s,w=build_fixture(self.root);p=w/'journal.bin'
        with p.open('rb')as f:hd=h.header(f);rows=list(h.records(f,hd))
        p.write_bytes(p.read_bytes()[:rows[-1][3]])
        with self.assertRaisesRegex(h.InvalidHistory,'incomplete'):h.verify(s,w)
    def test_rehashed_false_packet_metadata(self):
        s,w=build_fixture(self.root,mutate_row=True)
        with self.assertRaisesRegex(h.InvalidHistory,'metadata'):h.verify(s,w)
    def test_rehashed_false_source_witness(self):
        s,w=build_fixture(self.root,mutate_witness=True)
        with self.assertRaisesRegex(h.InvalidHistory,'witness'):h.verify(s,w)
    def test_rehashed_duplicate_hypotheses(self):
        s,w=build_fixture(self.root,placement_duplicates=True)
        with self.assertRaisesRegex(h.InvalidHistory,'duplicate'):h.verify(s,w)
    def test_interior_corruption(self):
        s,w=build_fixture(self.root);p=w/'journal.bin';raw=bytearray(p.read_bytes());raw[-250]^=1;p.write_bytes(raw)
        with self.assertRaises(h.InvalidHistory):h.verify(s,w)
    def test_changed_source(self):
        s,w=build_fixture(self.root);raw=bytearray(s.read_bytes());raw[-1]^=1;s.write_bytes(raw)
        with self.assertRaisesRegex(h.InvalidHistory,'source identity'):h.verify(s,w)
    def test_extra_bytes_after_terminal(self):
        s,w=build_fixture(self.root);p=w/'journal.bin';p.write_bytes(p.read_bytes()+b'\0'*4)
        with self.assertRaisesRegex(h.InvalidHistory,'after terminal'):h.verify(s,w)
    def test_index_tamper(self):
        s,w=build_fixture(self.root);p=w/'ranges.idx';raw=bytearray(p.read_bytes());raw[40]^=1;p.write_bytes(raw)
        with self.assertRaisesRegex(h.InvalidHistory,'range index seal'):h.verify(s,w)
    def test_short_reads(self):
        class Short(io.BytesIO):
            def read(self,n=-1):return super().read(min(3,n))
        s,w=build_fixture(self.root);f=Short((w/'journal.bin').read_bytes());hd=h.header(f)
        self.assertEqual([r[0]for r in h.records(f,hd)],[1,2,255])
    def test_all_header_truncations_fail(self):
        s,w=build_fixture(self.root);raw=(w/'journal.bin').read_bytes();head=h.header(io.BytesIO(raw))
        for end in range(head['size']):
            with self.subTest(end=end),self.assertRaises((ValueError,EOFError)):h.header(io.BytesIO(raw[:end]))
    def test_bound_config_before_allocating(self):
        s,w=build_fixture(self.root);raw=(w/'journal.bin').read_bytes();f=io.BytesIO(raw);hd=h.header(f)
        d=bytearray(raw[:hd['size']]);start=12+32+8+4+4+len(h.ENGINE)
        d[start+5*8:start+6*8]=struct.pack('<Q',2**63)
        d[-32:]=hashlib.sha256(d[:-32]).digest()
        with self.assertRaisesRegex(h.InvalidHistory,'configuration'):h.header(io.BytesIO(d))
    def test_symlink_source_rejected(self):
        s,w=build_fixture(self.root);link=self.root/'link.pcap'
        try:link.symlink_to(s)
        except (OSError,NotImplementedError):self.skipTest('symlinks unavailable')
        with self.assertRaisesRegex(h.InvalidHistory,'symlink'):h.verify(link,w)

if __name__=='__main__':unittest.main()
