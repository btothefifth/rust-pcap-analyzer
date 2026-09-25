"""Replay/index integrity tests with an explicitly MOCKED producer, not native Rust."""
import copy
import io
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from evidence.index import build,verify
from evidence.common import InvalidEvidence
from test_evidence import pcap,event_fixture,chain


def config():
    return dict(max_active_keys=256,max_active_payload=33554432,window_payload=262144,window_packets=2048,
        idle_frames="100000",max_tunnel_contexts=32,max_tunnel_depth=4,fragment_payload=8388608,max_event_bytes=8388608,
        max_plugin_bytes=1048576,max_plugin_events=4096,max_detectors=16,max_probe_bytes=4096,max_source_bytes=str((2**64-1)//8),
        include_payload=False,allow_port_hints=False,parse_mode="strict",overlap="reject_conflict",checksums="Observe",
        idle_timeout_ns="120000000000",dnp3_ports=[20000],modbus_ports=[502],container_limits=dict(
            max_block_bytes=16777216,max_packet_bytes=1048576,max_interfaces=1024,max_options=4096,max_stream_span=4194304,
            max_fragment_sets=1024,max_fragments_per_set=1024,fragment_frame_lifetime="100000",max_protocol_messages=100000,
            max_application_bytes=1048576,max_correlation_checks=5000000))

class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.source=self.root/"source.pcap";self.source.write_bytes(pcap())
        self.binary=self.root/"mock-binary";self.binary.write_bytes(b"NOT AN EXECUTABLE; subprocess is mocked in these tests")
        self.database=self.root/"index.sqlite"
        self.events=event_fixture(self.source.read_bytes());self.events[0]["data"]["config"]=config()
        self.raw=chain(self.events);self.meta=build(io.BytesIO(self.raw),self.database,source=self.source)
    def tearDown(self):self.temp.cleanup()
    def mock(self,argv,**kwargs):
        self.assertEqual(argv[1],"analyze");self.assertIn("--run-id",argv);self.assertIn("--window-packets",argv)
        kwargs["stdout"].write(self.raw);return SimpleNamespace(returncode=0)
    def test_identical_replay_and_all_projections(self):
        with patch("evidence.index.subprocess.run",side_effect=self.mock):
            receipt=verify(self.database,self.source,self.binary)
        self.assertEqual(receipt["status"],"PASS")
    def test_secondary_index_row_tampering_is_detected_even_with_original_chain(self):
        db=sqlite3.connect(self.database);db.execute("UPDATE facts SET value='tampered' WHERE key='questions.name'");db.commit();db.close()
        with patch("evidence.index.subprocess.run",side_effect=self.mock),self.assertRaises(InvalidEvidence):
            verify(self.database,self.source,self.binary)
    def test_forged_timestamp_rehashed_log_disagrees_with_canonical_producer(self):
        self.database.unlink();forged=copy.deepcopy(self.events);forged[1]["data"]["timestamp_ns"]="123"
        build(io.BytesIO(chain(forged)),self.database,source=self.source)
        with patch("evidence.index.subprocess.run",side_effect=self.mock),self.assertRaises(InvalidEvidence):
            verify(self.database,self.source,self.binary)
    def test_trusted_config_policy_rejects_other_analysis(self):
        with self.assertRaises(InvalidEvidence):verify(self.database,self.source,self.binary,expected_config_sha256="0"*64)
    def test_replay_failure_is_not_a_verified_database(self):
        with patch("evidence.index.subprocess.run",return_value=SimpleNamespace(returncode=4)),self.assertRaises(InvalidEvidence):
            verify(self.database,self.source,self.binary)
    def test_changed_source_stops_before_replay(self):
        self.source.write_bytes(pcap(b"xyz"))
        with patch("evidence.index.subprocess.run") as run,self.assertRaises(InvalidEvidence):
            verify(self.database,self.source,self.binary)
        run.assert_not_called()

if __name__=="__main__":unittest.main()
