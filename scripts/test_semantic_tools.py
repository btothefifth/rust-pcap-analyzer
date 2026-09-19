"""Portable fixture/tool contracts. These do not execute the Rust implementation."""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
import unittest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE))
import make_semantic_fixtures as maker
import semantic_case_runner as runner

class SemanticTools(unittest.TestCase):
    def test_fixture_generation_is_deterministic(self):
        self.assertEqual(maker.fixtures(),maker.fixtures());self.assertEqual(maker.cases(),maker.cases())
    def test_manifest_identity_and_no_clobber(self):
        with tempfile.TemporaryDirectory()as t:
            root=Path(t);maker.write(root);manifest=runner.audit(root)
            self.assertEqual(len(manifest['cases']),18)
            maker.write(root)
            (root/'dnp-read.bin').write_bytes(b'bad')
            with self.assertRaises(ValueError):runner.audit(root)
            with self.assertRaises(ValueError):maker.write(root)
    def test_missing_native_is_blocked_not_pass(self):
        with tempfile.TemporaryDirectory()as t:
            maker.write(Path(t));receipt,code=runner.run(t)
            self.assertEqual(code,2);self.assertEqual(receipt['native_execution'],'BLOCKED')
            self.assertEqual(receipt['cases'],[])
    def test_modbus_examples_match_specification_octets(self):
        cases={c['id']:c for c in maker.cases()}
        self.assertEqual(bytes.fromhex(cases['modbus-fc15-example']['hex'])[7:],bytes.fromhex('0f0013000a02cd01'))
        self.assertEqual(bytes.fromhex(cases['modbus-fc16-example']['hex'])[7:],bytes.fromhex('100001000204000a0102'))
    def test_pcap_record_and_checksum_integrity(self):
        for name,raw in maker.fixtures().items():
            self.assertEqual(struct.unpack('<I',raw[:4])[0],0xa1b2c3d4)
            at=24;frames=0
            while at<len(raw):
                _,_,cap,orig=struct.unpack('<IIII',raw[at:at+16]);self.assertEqual(cap,orig)
                p=raw[at+16:at+16+cap];self.assertEqual(len(p),cap)
                ip=p[14:34];tcp=p[34:]
                self.assertEqual(maker.checksum(ip),0,name)
                self.assertEqual(maker.checksum(ip[12:20]+b'\0\x06'+struct.pack('!H',len(tcp))+tcp),0,name)
                at+=16+cap;frames+=1
            self.assertEqual(at,len(raw));self.assertGreaterEqual(frames,6)
    def test_dnp_crc_independent_published_check_value(self):
        self.assertEqual(maker.dnp_crc(b'123456789'),0xea82)
    def test_single_byte_mutation_breaks_crc(self):
        source=bytes.fromhex('c0c081000001010000094d03')
        raw=maker.link(source,True)
        self.assertEqual(maker.dnp_crc(raw[:8]),int.from_bytes(raw[8:10],'little'))
        bad=bytearray(raw[:8]);bad[3]^=1
        self.assertNotEqual(maker.dnp_crc(bad),int.from_bytes(raw[8:10],'little'))
    def test_primitive_witness_reconstructed_from_bytes(self):
        payload=b'\x34\x12';case={'expected':{'status':'decoded_subset','fields':[{'name':'value','ordinal':0,'value':'4660'}],'absent_fields':[]}}
        report={'input_sha256':runner.sha(payload),'status':'decoded_subset','consumed':'2','records':[{'fields':[
            {'name':'value','value':'4660','range':{'start':'0','end':'2'},'evidence':{
                'sha256':runner.sha(payload),'spans':[{'frame':'1','record_offset':'0','packet_start':'0','start':'0','end':'2'}]}}]}]}
        self.assertEqual(runner.validate_report(report,case,payload),[])
        report['records'][0]['fields'][0]['evidence']['spans'][0]['packet_start']='1'
        with self.assertRaises(ValueError):runner.validate_report(report,case,payload)
    def test_semantic_mismatch_is_failure_not_consensus(self):
        c={'expected':{'status':'decoded_subset','fields':[],'absent_fields':[]}}
        r={'input_sha256':runner.sha(b''),'status':'unsupported','consumed':'0','records':[]}
        self.assertEqual(runner.validate_report(r,c,b''),['status'])
    def test_native_process_error_is_operational_failure(self):
        with self.assertRaises(ValueError):runner.execute([sys.executable,'-c','raise SystemExit(7)'])
    def test_native_process_output_is_bounded(self):
        with self.assertRaisesRegex(ValueError,'output limit'):
            runner.execute([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"x"*5000000)'])
    def test_native_process_timeout_is_separate(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            runner.execute([sys.executable,'-c','import time;time.sleep(10)'],timeout=0.02)
    def test_successful_process_is_not_implicitly_native_qualification(self):
        data,err=runner.execute([sys.executable,'-c','print("tool-test")'])
        self.assertEqual(data.strip(),b'tool-test');self.assertEqual(err,b'')
    def test_no_private_reference_identity_in_fixtures(self):
        self.assertNotIn('customer',json.dumps(maker.cases()).lower())
    def test_all_claimed_fixture_payloads_are_small(self):
        for c in maker.cases():
            self.assertEqual(len(bytes.fromhex(c['hex'])),c['bytes']);self.assertLess(c['bytes'],100)
            self.assertEqual(c['normative_review'],'NOT_RUN')

if __name__=='__main__':unittest.main()
