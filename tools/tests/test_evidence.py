from __future__ import annotations
import copy
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evidence.common import InvalidEvidence, canonical, load_json, signed, unsigned, time_key, bounded_lines
from evidence.containers import Reader
from evidence.index import build, query, ChainReader, connect_read, read_meta, DOMAIN, replay_args
from evidence.benchmark import generate, dns_packet
from evidence.minimize import ddmin, write_subset, minimize
from evidence.corpus import destination, validate_url, verify_entry, entries
from evidence.differential import first_difference
from evidence.process import run
from evidence.qualify import aggregate


def pcap(data=b"abc", *, endian="<", exponent=6, seconds=1700000000, fraction=123456):
    return struct.pack(endian+"IHHIIII", 0xa1b2c3d4 if exponent==6 else 0xa1b23c4d,2,4,0,0,65535,1) + struct.pack(endian+"IIII",seconds,fraction,len(data),len(data)) + data


def block(kind, body, endian="<"):
    body += bytes((-len(body)) % 4)
    length=len(body)+12
    return struct.pack(endian+"II",kind,length)+body+struct.pack(endian+"I",length)


def pcapng(*, endian="<", simple=False, binary=False, offset=0, ticks=1000):
    shb=block(0x0A0D0D0A,struct.pack(endian+"IHHq",0x1A2B3C4D,1,0,-1),endian)
    opts=struct.pack(endian+"HH",9,1)+bytes([0x8a if binary else 6])+bytes(3)
    opts+=struct.pack(endian+"HHq",14,8,offset)+bytes(4)
    idb=block(1,struct.pack(endian+"HHI",1,0,65535)+opts,endian)
    epb=block(3,struct.pack(endian+"I",3)+b"abc",endian) if simple else block(6,struct.pack(endian+"IIIII",0,ticks>>32,ticks&0xffffffff,3,3)+b"abc",endian)
    return shb+idb+epb


def event(kind,data,*,session=None,protocol=None,evidence=None,related=None,status="observed"):
    return dict(schema="pcap-evidence.event.v1",run_id="test",sequence="0",kind=kind,status=status,
        source_binding="requires_capture_complete",session=session,direction=None,protocol=protocol,
        stream_range=None,related_events=related or [],evidence=evidence or dict(byte_length="0",reconstructed_sha256=None,packets=[],spans=[]),data=data)


def event_fixture(source):
    packet=list(Reader(io.BytesIO(source)).packets())[0]
    data=packet.row();data.pop("ticks");data.pop("resolution");data.pop("offset_seconds");data["raw_timestamp"]={"ticks":str(packet.ticks),"resolution_code":packet.resolution,"offset_seconds":str(packet.offset)}
    ref=dict(frame="1",record_offset="24")
    ev=dict(byte_length=str(len(packet.data)),reconstructed_sha256=hashlib.sha256(packet.data).hexdigest(),packets=[ref],spans=[dict(frame="1",record_offset="24",packet_start="0",start="0",end=str(len(packet.data)))])
    config=dict(max_event_bytes=8*1024*1024)
    result=[event("capture.start",dict(config=config,implementation="test-fixture-not-native")),
            event("packet.observed",data,evidence=dict(byte_length="0",reconstructed_sha256=None,packets=[ref],spans=[])),
            event("flow.start",dict(key=dict(transport="udp",source_ip="10.0.0.1",source_port=50000,destination_ip="10.0.0.2",destination_port=53000)),session="1"),
            event("stream.chunk",dict(),session="1",evidence=ev),
            event("protocol.message",dict(questions=[dict(name="example.test",type=1)],transaction_id=7),session="1",protocol="dns",evidence=ev,related=["4"],status="candidate"),
            event("transaction.candidate",dict(reason="matching_identifiers_not_causality"),session="1",protocol="dns",related=["5"],status="candidate"),
            event("flow.end",dict(reason="eof"),session="1"),
            event("capture.complete",dict(events="8",packets="1",source_bytes=str(len(source)),source_sha256=hashlib.sha256(source).hexdigest()))]
    return result


def chain(events):
    out=bytearray();previous=bytes(32)
    for i,e in enumerate(events,1):
        e=copy.deepcopy(e);e["sequence"]=str(i)
        digest=hashlib.sha256(DOMAIN+previous+canonical(e)).digest()
        out+=canonical(dict(event=e,previous_sha256=previous.hex(),event_sha256=digest.hex()))+b"\n";previous=digest
    return bytes(out)


class ContainerTests(unittest.TestCase):
    def test_four_classic_magic_variants(self):
        for endian in ("<",">"):
            for exponent in (6,9):
                with self.subTest(endian=endian,exponent=exponent):
                    row=list(Reader(io.BytesIO(pcap(endian=endian,exponent=exponent))).packets())[0].row()
                    self.assertEqual(row["frame"],"1");self.assertEqual(row["data_offset"],"40")
                    self.assertEqual(row["timestamp_ns"],str(1700000000*10**9+123456*10**(9-exponent)))
    def test_short_read_adapter(self):
        class Short(io.BytesIO):
            def read(self,n=-1):return super().read(min(n,3))
        self.assertEqual(len(list(Reader(Short(pcap())).packets())),1)
    def test_both_pcapng_orders(self):
        for e in ("<",">"):
            rows=list(Reader(io.BytesIO(pcapng(endian=e,offset=-2))).packets())
            self.assertEqual(rows[0].row()["timestamp_ns"],"-1999000000")
    def test_mixed_sections(self):
        rows=list(Reader(io.BytesIO(pcapng()+pcapng(endian=">"))).packets())
        self.assertEqual([p.section for p in rows],[0,1]);self.assertEqual([p.frame for p in rows],[1,2])
    def test_simple_packet_time_remains_absent(self):
        self.assertIsNone(next(Reader(io.BytesIO(pcapng(simple=True))).packets()).row()["timestamp_ns"])
    def test_binary_time_inexact_is_unknown(self):
        self.assertIsNone(next(Reader(io.BytesIO(pcapng(binary=True,ticks=1))).packets()).row()["timestamp_ns"])
    def test_binary_time_exact_is_retained(self):
        self.assertEqual(next(Reader(io.BytesIO(pcapng(binary=True,ticks=1024))).packets()).row()["timestamp_ns"],"1000000000")
    def test_truncated_classic_payload(self):
        with self.assertRaises(InvalidEvidence):list(Reader(io.BytesIO(pcap()[:-1])).packets())
    def test_bad_trailer(self):
        b=bytearray(pcapng());b[-1]^=1
        with self.assertRaises(InvalidEvidence):list(Reader(io.BytesIO(b)).packets())
    def test_packet_limit(self):
        with self.assertRaises(InvalidEvidence):list(Reader(io.BytesIO(pcap()),packet_limit=2).packets())
    def test_invalid_time_strict_and_evidence(self):
        b=pcap(fraction=1000000)
        with self.assertRaises(InvalidEvidence):list(Reader(io.BytesIO(b)).packets())
        self.assertIsNone(next(Reader(io.BytesIO(b),evidence=True).packets()).ticks)
    def test_reader_is_single_pass(self):
        r=Reader(io.BytesIO(pcap()));list(r.packets())
        with self.assertRaises(InvalidEvidence):list(r.packets())
    def test_empty_file_is_not_success(self):
        with self.assertRaises(InvalidEvidence):list(Reader(io.BytesIO(b"")).packets())
    def test_record_subset_preserves_selected_bytes(self):
        b=pcapng()+pcapng(endian=">"); records=list(Reader(io.BytesIO(b)).records())
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"x.pcapng";write_subset(records,{2},p)
            with p.open("rb") as f:packets=list(Reader(f).packets())
            self.assertEqual([p.data for p in packets],[b"abc"])


class EncodingTests(unittest.TestCase):
    def test_duplicate_json_members_rejected(self):
        with self.assertRaises(InvalidEvidence):load_json('{"x":1,"x":2}')
    def test_float_and_nan_rejected(self):
        for s in ("1.1","NaN","Infinity"):
            with self.assertRaises(InvalidEvidence):load_json(s)
    def test_unsigned_canonical(self):
        for s in ("01","-1","+1"," 1","１",str(1<<64),1):
            with self.subTest(s=s),self.assertRaises(InvalidEvidence):unsigned(s)
        self.assertEqual(unsigned(str((1<<64)-1)),(1<<64)-1)
    def test_signed_canonical(self):
        for s in ("-0","00","+1"," 1",str(1<<127)):
            with self.subTest(s=s),self.assertRaises(InvalidEvidence):signed(s)
        self.assertEqual(signed(str(-(1<<127))),-(1<<127))
    def test_exact_sort_keys(self):
        values=[-(1<<127),-5,-1,0,1,1<<100,(1<<127)-1]
        self.assertEqual(sorted(values,key=lambda x:time_key(str(x))),values)
    def test_utf8_and_controls_roundtrip(self):
        value={"value":"é💡\n\r\t\b\f\x00\\\""}
        self.assertEqual(load_json(canonical(value)),value)
    def test_line_budget_and_terminal_newline(self):
        for value,limit in ((b"abc",5),(b"abc\n",3)):
            with self.assertRaises(InvalidEvidence):list(bounded_lines(io.BytesIO(value),limit))


class ChainTests(unittest.TestCase):
    def setUp(self):self.source=pcap();self.events=event_fixture(self.source)
    def test_valid_chain(self):self.assertEqual(len(list(ChainReader(io.BytesIO(chain(self.events))))),8)
    def test_missing_completion_is_not_success(self):
        with self.assertRaises(InvalidEvidence):list(ChainReader(io.BytesIO(chain(self.events[:-1]))))
    def test_reordered_events_rejected(self):
        b=chain(self.events).splitlines(keepends=True);b[3],b[4]=b[4],b[3]
        with self.assertRaises(InvalidEvidence):list(ChainReader(io.BytesIO(b"".join(b))))
    def test_content_tampering_rejected(self):
        b=chain(self.events).replace(b"example.test",b"forgery.test")
        with self.assertRaises(InvalidEvidence):list(ChainReader(io.BytesIO(b)))
    def test_mixed_run_even_rehashed_rejected(self):
        self.events[4]["run_id"]="different"
        with self.assertRaises(InvalidEvidence):list(ChainReader(io.BytesIO(chain(self.events))))
    def test_aborted_cannot_be_indexed(self):
        self.events[-1]["kind"]="capture.aborted"
        with self.assertRaises(InvalidEvidence):list(ChainReader(io.BytesIO(chain(self.events))))
    def test_events_after_complete_rejected(self):
        self.events.append(event("diagnostic",{}))
        with self.assertRaises(InvalidEvidence):list(ChainReader(io.BytesIO(chain(self.events))))
    def test_completion_count_is_checked(self):
        self.events[-1]["data"]["events"]="7"
        with self.assertRaises(InvalidEvidence):list(ChainReader(io.BytesIO(chain(self.events))))


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.capture=self.root/"source.pcap";self.capture.write_bytes(pcap());self.db=self.root/"analysis.sqlite"
        self.events=event_fixture(self.capture.read_bytes())
    def tearDown(self):self.tmp.cleanup()
    def make(self):return build(io.BytesIO(chain(self.events)),self.db,source=self.capture)
    def test_build_and_protocol_query(self):
        metadata=self.make();self.assertFalse(metadata["semantic_replay_verified"])
        self.assertEqual([e["kind"] for e in query(self.db,protocol="dns")],["protocol.message","transaction.candidate"])
    def test_time_exact_above_javascript_integer_limit(self):
        self.make();ns=self.events[1]["data"]["timestamp_ns"]
        self.assertEqual(len(list(query(self.db,protocol="dns",start_ns=ns,end_ns=ns))),2)
        self.assertEqual(list(query(self.db,protocol="dns",start_ns=str(int(ns)+1))),[])
    def test_tuple_filter_keeps_ip_and_port_on_same_endpoint(self):
        self.make()
        self.assertTrue(list(query(self.db,ip="10.0.0.1",port=50000)))
        self.assertFalse(list(query(self.db,ip="10.0.0.1",port=53000)))
    def test_metadata_secondary_lookup(self):
        self.make();self.assertEqual(len(list(query(self.db,metadata=("questions.name","example.test")))),1)
    def test_transaction_relations_inherit_packet_provenance(self):
        self.make();db=connect_read(self.db)
        try:self.assertEqual(db.execute("SELECT frame FROM event_packets WHERE seq='6'").fetchall(),[("1",)])
        finally:db.close()
    def test_sql_payload_is_a_value_not_a_query(self):
        self.make();self.assertEqual(list(query(self.db,protocol="dns' OR 1=1 --")),[])
    def test_no_clobber(self):
        self.make();before=self.db.read_bytes()
        with self.assertRaises(FileExistsError):self.make()
        self.assertEqual(self.db.read_bytes(),before)
    def test_packet_source_hash_checked(self):
        self.events[1]["data"]["packet_sha256"]="0"*64
        with self.assertRaises(InvalidEvidence):self.make()
        self.assertFalse(self.db.exists())
    def test_rehashed_source_span_forgery_rejected(self):
        self.events[4]["evidence"]["spans"][0]["packet_start"]="1"
        with self.assertRaises(InvalidEvidence):self.make()
    def test_reconstructed_byte_hash_checked(self):
        self.events[4]["evidence"]["reconstructed_sha256"]="0"*64
        with self.assertRaises(InvalidEvidence):self.make()
    def test_duplicate_packet_reference_rejected(self):
        self.events[1]["evidence"]["packets"]*=2
        with self.assertRaises(InvalidEvidence):self.make()
    def test_missing_source_reference_rejected(self):
        self.events[4]["evidence"]["packets"][0]["frame"]="2"
        with self.assertRaises(InvalidEvidence):self.make()
    def test_forward_event_reference_rejected(self):
        self.events[4]["related_events"]=["6"]
        with self.assertRaises(InvalidEvidence):self.make()
    def test_final_source_hash_checked(self):
        self.events[-1]["data"]["source_sha256"]="0"*64
        with self.assertRaises(InvalidEvidence):self.make()
    def test_small_disk_budget_fails_without_publication(self):
        with self.assertRaises(InvalidEvidence):build(io.BytesIO(chain(self.events)),self.db,source=self.capture,max_disk=1)
        self.assertFalse(self.db.exists())
    def test_schema_injection_rejected(self):
        self.make();db=sqlite3.connect(self.db);db.execute("CREATE VIEW unsafe_extra AS SELECT 1");db.commit();db.close()
        with self.assertRaises(InvalidEvidence):list(query(self.db))
    def test_semantic_forgery_is_explicitly_not_verified_by_self_hash(self):
        self.events[4]["data"]["questions"][0]["name"]="fabricated.example"
        meta=self.make();self.assertFalse(meta["semantic_replay_verified"])
        self.assertEqual(meta["verification"],"source_bytes_and_spans_checked")
    def test_missing_completion_removes_temporary_files(self):
        self.events.pop()
        with self.assertRaises(InvalidEvidence):self.make()
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),["source.pcap"])
    def test_projection_roundtrip_uses_exact_json(self):
        self.make();self.assertEqual(list(query(self.db,kind="protocol.message"))[0]["data"],self.events[4]["data"])


class OperationalTests(unittest.TestCase):
    def test_ddmin_finds_single_bad_packet(self):
        result,calls,minimal=ddmin(list(range(20)),lambda x:13 in x)
        self.assertEqual(result,[13]);self.assertTrue(minimal);self.assertLessEqual(calls,100)
    def test_ddmin_empty_failure(self):
        result,_,_=ddmin([1,2],lambda x:True);self.assertEqual(result,[])
    def test_ddmin_requires_initial_reproduction(self):
        with self.assertRaises(InvalidEvidence):ddmin([1],lambda x:False)
    def test_ddmin_budget_not_a_minimality_claim(self):
        _,calls,minimal=ddmin(list(range(20)),lambda x:13 in x,max_calls=1)
        self.assertEqual(calls,1);self.assertFalse(minimal)
    def test_operational_predicate_error_is_not_a_semantic_result(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/"in.pcap";source.write_bytes(pcap())
            with self.assertRaises(InvalidEvidence):minimize(source,Path(d)/"out.pcap",[sys.executable,"-c","import sys;sys.exit(2)","{capture}"])
    def test_generator_and_oracle(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"capture.pcap";receipt=generate(p,100,7)
            with p.open("rb") as f:self.assertEqual(len(list(Reader(f).packets())),100)
            self.assertFalse(receipt["representative_production_mix"])
            with self.assertRaises(FileExistsError):generate(p,100,7)
    def test_corpus_path_traversal(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("../escape","/absolute","a\\b"):
                with self.subTest(name=name),self.assertRaises(InvalidEvidence):destination(Path(d),name)
    def test_corpus_network_hosts_are_restricted(self):
        for url in ("http://raw.githubusercontent.com/a","https://127.0.0.1/a","https://user:pass@raw.githubusercontent.com/a","https://raw.githubusercontent.com:8443/a"):
            with self.subTest(url=url),self.assertRaises(InvalidEvidence):validate_url(url)
    def test_missing_corpus_is_blocked(self):
        with tempfile.TemporaryDirectory() as d:self.assertEqual(verify_entry(Path(d)/"missing",{"name":"test"})["status"],"BLOCKED")
    def test_layer_comparison_stops_at_first_disagreement(self):
        r=first_difference([{"frame":"1"},{"frame":"2"}],[{"frame":"1"},{"frame":"4"}],("frame",))
        self.assertEqual(r["frame"],2);self.assertEqual(r["status"],"FAIL")
    def test_different_packet_counts(self):
        self.assertEqual(first_difference([{"frame":"1"}],[],("frame",))["reason"],"packet_count_disagreement")
    def test_missing_compiler_is_blocked_not_pass(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run(["definitely-no-such-compiler-for-test"],Path(d),"missing")["status"],"BLOCKED")
    def test_process_timeout_is_not_pass(self):
        with tempfile.TemporaryDirectory() as d:
            result=run([sys.executable,"-c","import time;time.sleep(2)"],Path(d),"slow",timeout=0.05)
            self.assertEqual(result["status"],"FAIL");self.assertEqual(result["reason"],"timeout")
    def test_gate_aggregation(self):
        self.assertEqual(aggregate([{"status":"PASS"},{"status":"BLOCKED"}]),"BLOCKED")
        self.assertEqual(aggregate([{"status":"FAIL"},{"status":"BLOCKED"}]),"FAIL")

if __name__=="__main__":unittest.main()
