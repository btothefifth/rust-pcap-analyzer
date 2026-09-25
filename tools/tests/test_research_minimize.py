"""Synthetic comparison predicate tests, not execution of an external parser."""
import copy
from pathlib import Path
import tempfile
import unittest
from scripts.product_fixtures import pcap,packet
from tools.evidence.containers import Reader
from tools.research.adapters import container_normalize
from tools.research.contract import compare_fields,InvalidResearch
from tools.research.minimize import reduce_capture,fingerprint


def evaluate(path):
    left=container_normalize(path);right=copy.deepcopy(left)
    right['producer']['id']='synthetic-reducer-predicate';right['producer']['origin']='manual_research'
    with path.open('rb')as f:frames=[p.frame for p in Reader(f).packets()if b'retain-me'in p.data]
    # Alter a synthetic normalized field, not actual packet bytes or engine truth.
    if frames:
        row=next(r for r in right['observations']if r['key']=='frame:'+str(frames[0])and r['layer']=='packet_bytes')
        row['value']['sha256']='f'*64
    return compare_fields(left,right)


class ReductionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.source=self.root/'input.pcap'
        self.source.write_bytes(pcap([packet(x,'udp')for x in [b'a',b'retain-me',b'c',b'd']]))
    def tearDown(self):self.tmp.cleanup()
    def test_preserves_exact_fingerprint_and_original(self):
        original=self.source.read_bytes();r=reduce_capture(self.source,self.root/'result',evaluate,max_calls=80)
        self.assertEqual(self.source.read_bytes(),original);self.assertEqual(len(r['frame_map']),1)
        self.assertEqual(r['frame_map'][0]['original_frame'],'2');self.assertTrue(r['single_deletion_minimal_for_this_predicate'])
        self.assertEqual(fingerprint(evaluate(self.source)),fingerprint(evaluate(self.root/'result/reduced.pcap')))
    def test_no_difference_is_not_success(self):
        with self.assertRaises(InvalidResearch):reduce_capture(self.source,self.root/'nope',lambda p:compare_fields(container_normalize(p),container_normalize(p)))
        self.assertFalse((self.root/'nope').exists())
    def test_operational_failure_aborts_not_reproduces(self):
        def error(p):raise TimeoutError('synthetic tool timeout')
        with self.assertRaises(TimeoutError):reduce_capture(self.source,self.root/'nope',error)
    def test_no_clobber(self):
        d=self.root/'exists';d.mkdir()
        with self.assertRaises(FileExistsError):reduce_capture(self.source,d,evaluate)
    def test_budget_exhaustion_is_not_minimality(self):
        r=reduce_capture(self.source,self.root/'limited',evaluate,max_calls=2)
        self.assertFalse(r['single_deletion_minimal_for_this_predicate']);self.assertTrue(r['budget_exhausted'])
    def test_input_packet_budget(self):
        with self.assertRaises(InvalidResearch):reduce_capture(self.source,self.root/'nope',evaluate,max_packets=2)
    def test_invalid_evaluation_budget(self):
        with self.assertRaises(ValueError):reduce_capture(self.source,self.root/'nope',evaluate,max_calls=1)


if __name__=='__main__':unittest.main()
