"""Executable lifecycle tests; not native Rust or Windows packaging evidence."""
from pathlib import Path
import copy, hashlib, json, os, subprocess, sys, tempfile, time, unittest
from unittest.mock import patch
from tools.desktop.resources import ResourceGuard, WorkerStopped, publish_state
from tools.desktop import worker, store
from tools.research import adapters, bundle, contract
from scripts.history_fixtures import capture, frame

class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def test_state_replace_retries_without_stale_temporary_files(self):
        target=self.root/'state.json';real=os.replace;attempts=[]
        def replace(a,b):
            attempts.append(str(a))
            if len(attempts)<3:raise PermissionError('simulated sharing violation')
            return real(a,b)
        with patch('tools.desktop.resources.os.replace',side_effect=replace):
            publish_state(target,{'state':'running'},retry_delay=0)
        self.assertEqual(json.loads(target.read_text())['state'],'running');self.assertEqual(len(attempts),3);self.assertEqual(len(list(self.root.glob('*.next'))),0)
    def test_failed_publish_does_not_clobber_previous_state(self):
        target=self.root/'state.json';publish_state(target,{'state':'old'})
        with patch('tools.desktop.resources.os.replace',side_effect=PermissionError('held')):
            with self.assertRaises(PermissionError):publish_state(target,{'state':'new'},attempts=2,retry_delay=0)
        self.assertEqual(json.loads(target.read_text())['state'],'old');self.assertFalse(list(self.root.glob('*.next')))
    def test_state_rejects_nonfinite_and_excessive_data(self):
        for v in ({'x':float('nan')},{'x':'a'*65536}):
            with self.assertRaises(ValueError):publish_state(self.root/'state.json',v)
    def test_disk_guard_stops_when_measured_budget_exceeded(self):
        (self.root/'events').write_bytes(b'x'*70000)
        with ResourceGuard(self.root,65536)as guard:
            with self.assertRaises(WorkerStopped):guard.check()
            self.assertGreater(guard.peak,65536)
    def test_cancel_marker_stops_native_child(self):
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
        try:
            with ResourceGuard(self.root,1024*1024)as guard:
                guard.attach(child);(self.root/'cancel.request').write_bytes(b'cancel');guard.sample()
                child.wait(timeout=3)
                with self.assertRaises(WorkerStopped):guard.check()
        finally:
            if child.poll()is None:child.kill();child.wait()
    def test_timeout_is_operational_not_a_capture_timestamp(self):
        with ResourceGuard(self.root,1024*1024,timeout_seconds=.01)as guard:
            time.sleep(.02);guard.sample()
            with self.assertRaises(WorkerStopped):guard.check()
            self.assertEqual(guard.reason,'worker_lifetime_budget')
    def test_invalid_limits_rejected(self):
        for value in (True,0,1,65*1024**4):
            with self.assertRaises(ValueError):ResourceGuard(self.root,value)
    def test_container_mode_actual_source_binding_and_closed_database(self):
        source=self.root/'capture.pcap';source.write_bytes(capture([frame(100,2)]));directory=self.root/'run';directory.mkdir()
        self.assertEqual(worker.run(directory,source,'container'),0)
        result=json.loads((directory/'state.json').read_text());self.assertEqual(result['source_sha256'],hashlib.sha256(source.read_bytes()).hexdigest());self.assertFalse(result['semantic_replay_verified'])
        self.assertEqual(store.overview(directory/'events.sqlite')['kinds']['packet.observed'],1)
        os.replace(directory/'events.sqlite',directory/'closed.sqlite')
    def test_pre_cancelled_worker_cannot_publish_complete(self):
        source=self.root/'capture.pcap';source.write_bytes(capture([frame(100,2)]));directory=self.root/'run';directory.mkdir();(directory/'cancel.request').write_bytes(b'cancel')
        self.assertEqual(worker.run(directory,source,'container'),1)
        state=json.loads((directory/'state.json').read_text());self.assertEqual(state['state'],'cancelled');self.assertEqual(state['source_binding'],'provisional_prefix')
    def test_missing_native_engine_does_not_fallback(self):
        source=self.root/'capture.pcap';source.write_bytes(capture([frame(100,2)]));directory=self.root/'run';directory.mkdir()
        self.assertEqual(worker.run(directory,source,'rust'),1)
        state=json.loads((directory/'state.json').read_text());self.assertEqual(state['state'],'failed');self.assertEqual(state['mode'],'rust')

class ComparisonV2(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.source=self.root/'a.pcap';self.source.write_bytes(capture([frame(100,2),frame(101,16,b'x')]));self.a=adapters.container_normalize(self.source)
    def tearDown(self):self.temp.cleanup()
    def test_same_layer_prior_field_gap_blocks_strong_claim(self):
        b=copy.deepcopy(self.a);first=next(r for r in b['observations']if r['layer']=='capture_record');del first['value']['captured_length'];first['value']['original_length']='999'
        result=contract.compare_fields(self.a,b)['first_semantic_divergence'];self.assertFalse(result['earliest_within_declared_coverage']);self.assertTrue(result['earlier_unresolved_observations'])
    def test_partial_current_layer_blocks_strong_claim(self):
        b=copy.deepcopy(self.a);b['coverage']['capture_record']='partial';next(r for r in b['observations']if r['layer']=='capture_record')['value']['captured_length']='1'
        self.assertFalse(contract.compare_fields(self.a,b)['first_semantic_divergence']['earliest_within_declared_coverage'])
    def test_old_algorithm_remains_exactly_available(self):
        self.assertEqual(contract.compare_fields_v1(self.a,self.a)['schema'],'pcap-evidence.research-differential.v1');self.assertEqual(contract.compare_fields(self.a,self.a)['schema'],'pcap-evidence.research-differential.v2')
    def test_v1_bundle_still_verifies(self):
        path=self.root/'legacy.zip'
        with patch('tools.research.bundle.compare_fields',contract.compare_fields_v1):bundle.create(path,self.source,self.a,self.a,specifications=[])
        self.assertEqual(bundle.verify(path)['status'],'PASS')
    def test_v2_bundle_verifies_without_authentication_claim(self):
        path=self.root/'case.zip';bundle.create(path,self.source,self.a,self.a,specifications=[]);proof=bundle.verify(path);self.assertEqual(proof['status'],'PASS');self.assertFalse(proof['authorship_authenticated'])
    def test_noninteger_comparison_budget_rejected(self):
        for n in (True,2.5,'3'):
            with self.assertRaises(ValueError):contract.compare_fields(self.a,self.a,maximum=n)
    def test_unknown_future_policy_is_not_replayed_as_current(self):
        with self.assertRaises(ValueError):contract.recompute_differential(self.a,self.a,'future')
    def test_reordering_ordered_alternatives_is_still_a_difference(self):
        a=copy.deepcopy(self.a);b=copy.deepcopy(a);a['observations'][0]['value']['x']=['a','b','a'];b['observations'][0]['value']['x']=['a','a','b'];self.assertIsNotNone(contract.compare_fields(a,b)['first_semantic_divergence'])
