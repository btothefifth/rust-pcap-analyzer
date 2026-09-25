"""Executed tests for research, byte archives, TLV and indexed GUI boundaries."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile
from scripts.product_fixtures import pcap,packet,examples,links,generate
from tools.product import comparison,tlv,history
from tools.research import contract,adapters,bundle,cases
from tools.desktop import worker,store
ROOT=Path(__file__).resolve().parents[2]

class Temp(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.source=self.root/'source.pcap';self.source.write_bytes(pcap([packet(b'abc','udp')]))
    def tearDown(self):self.temp.cleanup()
    def snapshot(self):return adapters.container_normalize(self.source)

class ResearchTests(Temp):
    def test_matching_independent_container_and_events(self):
        left=self.snapshot();raw=b''.join(worker.inspection_lines(self.source,'sample'));right=adapters.event_normalize(raw,contract.file_identity(self.source),'1',origin='independent_fixture')
        result=contract.compare_fields(left,right);self.assertIsNone(result['first_semantic_divergence']);self.assertFalse(result['consensus_used'])
    def test_earliest_packet_divergence_has_source_witness(self):
        left=self.snapshot();right=copy.deepcopy(left);right['observations'][1]['value']['sha256']='f'*64
        r=contract.compare_fields(left,right);self.assertEqual(r['first_semantic_divergence']['layer'],'packet_bytes');self.assertTrue(r['first_semantic_divergence']['earliest_within_declared_coverage']);self.assertIsNone(r['first_semantic_divergence']['correct_implementation'])
    def test_prior_unknown_layers_prevent_strong_earliest_claim(self):
        a=self.snapshot();a['observations']=[contract.observation('protocol_message','frame:1',{'function':'1'},frames=['1'])];a['coverage']={k:'not_collected'for k in comparison.LAYERS};a['coverage']['protocol_message']='partial';b=copy.deepcopy(a);b['observations'][0]['value']['function']='2'
        first=contract.compare_fields(a,b)['first_semantic_divergence'];self.assertFalse(first['earliest_within_declared_coverage']);self.assertIn('capture_record',first['earlier_unresolved_layers'])
    def test_status_difference_not_hidden_by_equal_value(self):
        a=self.snapshot();b=copy.deepcopy(a);b['observations'][1]['status']='ambiguous';first=contract.compare_fields(a,b)['first_semantic_divergence'];self.assertEqual(first['field'],'/status')
    def test_array_order_and_duplicates_not_laundered(self):
        a=self.snapshot();a['observations'][0]['value']['alternatives']=['a','b','a'];b=copy.deepcopy(a);b['observations'][0]['value']['alternatives']=['a','a','b'];self.assertIsNotNone(contract.compare_fields(a,b)['first_semantic_divergence'])
    def test_missing_normalized_field_is_not_absence_claim(self):
        a=self.snapshot();b=copy.deepcopy(a);del b['observations'][0]['value']['link_type'];r=contract.compare_fields(a,b);self.assertIsNone(r['first_semantic_divergence']);self.assertTrue(any(x['result']=='not_comparable'for x in r['rows']))
    def test_source_identity_mismatch_rejected(self):
        a=self.snapshot();b=copy.deepcopy(a);b['source']['sha256']='0'*64
        with self.assertRaises(ValueError):contract.compare_fields(a,b)
    def test_duplicate_anchor_rejected(self):
        a=self.snapshot();a['observations'].append(a['observations'][0])
        with self.assertRaises(ValueError):comparison.validate(a)
    def test_duplicate_json_key_rejected(self):
        with self.assertRaises(ValueError):contract.decode_json(b'{"a":1,"a":2}')
    def test_deep_json_rejected_before_recursive_parser(self):
        with self.assertRaises(ValueError):contract.decode_json(b'['*30+b'0'+b']'*30)
    def test_nan_rejected(self):
        with self.assertRaises(ValueError):contract.decode_json(b'{"a":NaN}')
    def test_packet_span_must_be_nonempty(self):
        a=self.snapshot();a['observations'][0]['evidence']['spans'][0]['end']='0'
        with self.assertRaises(ValueError):comparison.validate(a)
    def test_safe_file_paths(self):
        for path in ('../secret','/etc/passwd','a\\b','x:foo','./source.pcap'):
            with self.subTest(path=path),self.assertRaises(ValueError):contract.safe_file(self.root,path)
    @unittest.skipUnless(os.name=='posix','symlink platform test')
    def test_safe_file_symlink(self):
        (self.root/'alias').symlink_to(self.source)
        with self.assertRaises(ValueError):contract.safe_file(self.root,'alias')
    def test_assertions_distinguish_missing(self):
        r=contract.assertions({'a':1},[{'path':'/a','op':'equals','value':1},{'path':'/b','op':'equals','value':1}]);self.assertEqual([x['status']for x in r],['PASS','NOT_COVERED'])
    def test_numeric_frame_order_not_lexical(self):
        a=self.snapshot();a['observations']=[contract.observation('packet_bytes','frame:'+str(n),{'length':'1'},frames=[n])for n in (10,2)];b=copy.deepcopy(a)
        for r in b['observations']:r['value']['length']='2'
        self.assertEqual(contract.compare_fields(a,b)['first_semantic_divergence']['key'],'frame:2')
    def test_unsupported_semantics_not_a_vote(self):
        a=self.snapshot();b=copy.deepcopy(a);b['observations'][0]['status']='unsupported';self.assertIsNone(contract.compare_fields(a,b)['first_semantic_divergence'])
    def test_bundle_roundtrip_and_no_clobber(self):
        a=self.snapshot();b=copy.deepcopy(a);b['observations'][0]['value']['captured_length']='100';p=self.root/'case.zip'
        bundle.create(p,self.source,a,b,specifications=[dict(id='policy',section='1',requirement='Do not invent bytes',basis='project_invariant')])
        result=bundle.verify(p);self.assertEqual(result['status'],'PASS');self.assertFalse(result['semantic_correctness_proven'])
        with self.assertRaises(FileExistsError):bundle.create(p,self.source,a,b,specifications=[])
    def test_bundle_detects_rehashed_forged_differential(self):
        a=self.snapshot();p=self.root/'case.zip';bundle.create(p,self.source,a,a,specifications=[])
        with zipfile.ZipFile(p)as z:members={n:z.read(n)for n in z.namelist()}
        members['differential.json']=members['differential.json'].replace(b'"consensus_used":false',b'"consensus_used":true')
        m=json.loads(members['manifest.json']);m['files']['differential.json']={'bytes':len(members['differential.json']),'sha256':hashlib.sha256(members['differential.json']).hexdigest()};members['manifest.json']=contract.canonical(m)+b'\n'
        tampered=self.root/'tampered.zip'
        with zipfile.ZipFile(tampered,'w')as z:
            for n,data in members.items():z.writestr(n,data)
        with self.assertRaises(ValueError):bundle.verify(tampered)
    def test_bundle_out_of_packet_span_rejected(self):
        a=self.snapshot();b=copy.deepcopy(a);b['observations'][0]['value']['captured_length']='100';b['observations'][0]['evidence']['spans'][0]['end']='999999'
        with self.assertRaises(ValueError):bundle.create(self.root/'bad.zip',self.source,a,b,specifications=[])
    def test_catalog_actual_maintenance_not_qualification(self):
        a=cases.audit(ROOT);self.assertEqual(a['maintenance_status'],'PASS');self.assertEqual(a['family_count'],68);self.assertEqual(a['qualification_status'],'BLOCKED')
    def test_native_case_without_executable_blocked(self):
        case,_=cases.select(ROOT,'bgp.framing-kat');self.assertEqual(cases.run_probe_case(ROOT,case,None)['status'],'BLOCKED')
    def test_missing_external_tool_blocked(self):self.assertEqual(adapters.run_adapter('product',self.source,None)['status'],'BLOCKED')
    def test_process_output_bounded(self):
        r=adapters.execute([sys.executable,'-c','print("a"*100000)'],output_limit=100);self.assertEqual(r.status,'OUTPUT_LIMIT');self.assertLessEqual(len(r.stdout),100)
    def test_group_kill_permission_falls_back_to_owned_child(self):
        class Child:
            pid=123
            killed=False
            def poll(self):return -9 if self.killed else None
            def kill(self):self.killed=True
        child=Child()
        def denied(_pid,_signal):raise PermissionError('synthetic runner denial')
        self.assertTrue(adapters._stop_owned_process(child,posix=True,kill_group=denied));self.assertTrue(child.killed)
    def test_exited_group_leader_does_not_skip_descendant_cleanup(self):
        class Child:
            pid=123
            def poll(self):return 0
        called=[]
        self.assertTrue(adapters._stop_owned_process(Child(),posix=True,kill_group=lambda pid,sig:called.append((pid,sig))))
        self.assertEqual(called[0][0],123)
    def test_exited_child_group_permission_race_is_already_stopped(self):
        class Child:
            pid=123
            def poll(self):return 0
        def denied(_pid,_signal):raise PermissionError('synthetic exited-group race')
        self.assertTrue(adapters._stop_owned_process(Child(),posix=True,kill_group=denied))
    def test_process_timeout_bounded(self):
        r=adapters.execute([sys.executable,'-c','import time;time.sleep(10)'],timeout=.05);self.assertEqual(r.status,'TIMEOUT')
    def test_process_nonzero_is_not_pass(self):self.assertEqual(adapters.execute([sys.executable,'-c','raise SystemExit(3)']).status,'TOOL_ERROR')
    def test_relative_executable_rejected(self):self.assertEqual(adapters.execute(['python','--version']).status,'BLOCKED')
    def test_tshark_mismatched_header_rejected(self):
        with self.assertRaises(ValueError):adapters.tshark_normalize(b'bad\n',contract.file_identity(self.source),'x')
    def test_external_exact_timestamp(self):
        self.assertEqual(adapters.epoch_ns('-0.000000001'),'-1');self.assertIsNone(adapters.epoch_ns('1.0000000001'))

class TlvTests(Temp):
    def test_typed_roundtrip(self):
        value={'a':[None,True,False,258,'µ'],'integer_string':'18446744073709551615'};self.assertEqual(tlv.decode(tlv.encode(value)),value)
    def test_u64_golden(self):self.assertEqual(tlv.encode(258),bytes.fromhex('02000000080000000000000102'))
    def test_unknown_tag_preserved(self):self.assertEqual(tlv.decode(bytes.fromhex('ef000000020102')),tlv.Opaque(239,b'\1\2'))
    def test_unknown_tag_roundtrip(self):v=tlv.Opaque(55,b'xyz');self.assertEqual(tlv.decode(tlv.encode(v)),v)
    def test_all_truncations_fail(self):
        raw=tlv.encode({'a':[1,'hello']})
        for n in range(len(raw)):
            with self.subTest(n=n),self.assertRaises(ValueError):tlv.decode(raw[:n])
    def test_duplicate_object_keys_rejected(self):
        item=tlv.encode('key')+tlv.encode(1);raw=b'\5'+struct.pack('!I',len(item)*2)+item*2
        with self.assertRaises(ValueError):tlv.decode(raw)
    def test_tree_budget(self):
        v=0
        for _ in range(30):v=[v]
        with self.assertRaises(ValueError):tlv.encode(v)
    def test_negative_integer_not_implicitly_unsigned(self):
        with self.assertRaises(ValueError):tlv.encode(-1)
    def test_encoded_output_budget(self):
        with self.assertRaises(ValueError):tlv.encode('x'*100,limit=50)
    def test_binary_event_chain(self):
        vals=[json.loads(line)['event']for line in worker.inspection_lines(self.source,'binary')];out=io.BytesIO();tlv.write_events(out,vals);self.assertEqual(list(tlv.events(io.BytesIO(out.getvalue()))),vals)
    def test_binary_integrity_failure(self):
        vals=[json.loads(line)['event']for line in worker.inspection_lines(self.source,'binary')];out=io.BytesIO();tlv.write_events(out,vals);raw=bytearray(out.getvalue());raw[-1]^=1
        with self.assertRaises(ValueError):list(tlv.events(io.BytesIO(raw)))
    def test_completion_not_optional_by_default(self):
        first=json.loads(next(worker.inspection_lines(self.source,'binary')))['event'];out=io.BytesIO();tlv.write_events(out,[first])
        with self.assertRaises(ValueError):list(tlv.events(io.BytesIO(out.getvalue())))

class HistoryTests(Temp):
    def test_archive_and_replay(self):
        out=self.root/'archive';history.archive(self.source,out);self.assertEqual(history.verify_archive(out)['status'],'PASS');raw=io.BytesIO();history.replay_archive(out,raw);self.assertEqual(raw.getvalue(),self.source.read_bytes())
    def test_archive_chunk_tamper(self):
        out=self.root/'archive';history.archive(self.source,out);p=out/'0000000000000000.chunk';p.write_bytes(p.read_bytes()+b'x')
        with self.assertRaises(ValueError):history.verify_archive(out)
    def test_archive_no_clobber(self):
        out=self.root/'archive';out.mkdir()
        with self.assertRaises(FileExistsError):history.archive(self.source,out)
    def test_archive_disk_budget(self):
        out=self.root/'archive'
        with self.assertRaises(ValueError):history.archive(self.source,out,disk_budget=20)
        self.assertFalse(out.exists())
    def test_archive_manifest_needed_for_recovery(self):
        out=self.root/'archive';history.archive(self.source,out);(out/'manifest.json').unlink()
        with self.assertRaises(OSError):history.verify_archive(out)
    def test_archive_index_tamper(self):
        out=self.root/'archive';history.archive(self.source,out);(out/'chunks.ndjson').write_bytes(b'')
        with self.assertRaises(ValueError):history.verify_archive(out)
    def test_stream_conflict_policies_and_provenance(self):
        source=self.root/'bytes';source.write_bytes(b'abcXYZdef');db=history.StreamStore(self.root/'s.db',source,create=True)
        try:
            db.append('hypothesis-A',0,0,0,3);db.append('hypothesis-A',0,1,3,3);db.append('hypothesis-A',0,6,6,3)
            rows=list(db.reconstruct('hypothesis-A',0));self.assertTrue(any(x['status']=='conflict'and x['bytes_hex']is None for x in rows));self.assertTrue(any(x['status']=='gap'for x in rows))
            first=list(db.reconstruct('hypothesis-A',0,policy='first'));last=list(db.reconstruct('hypothesis-A',0,policy='last'));self.assertNotEqual([r['bytes_hex']for r in first],[r['bytes_hex']for r in last]);self.assertTrue(any(len(x['alternatives'])==2 for x in first))
        finally:db.close()
    def test_stream_scope_and_direction_isolation(self):
        db=history.StreamStore(self.root/'s.db',self.source,create=True)
        try:db.append('one',0,0,0,3);self.assertEqual(list(db.reconstruct('two',0)),[]);self.assertEqual(list(db.reconstruct('one',1)),[])
        finally:db.close()
    def test_stream_reopen_checks_source(self):
        db=history.StreamStore(self.root/'s.db',self.source,create=True);db.close();self.source.write_bytes(b'changed')
        with self.assertRaises(ValueError):history.StreamStore(self.root/'s.db',self.source)
    def test_stream_changed_segment_rejected(self):
        db=history.StreamStore(self.root/'s.db',self.source,create=True)
        try:
            db.append('one',0,0,0,3)
            with self.source.open('r+b')as f:f.write(b'xxx')
            with self.assertRaises(ValueError):list(db.reconstruct('one',0))
        finally:db.close()
    def test_stream_work_budget(self):
        db=history.StreamStore(self.root/'s.db',self.source,create=True)
        try:
            db.append('one',0,0,0,3)
            with self.assertRaises(ValueError):list(db.reconstruct('one',0,max_work=1))
        finally:db.close()

class DesktopStoreTests(Temp):
    def setUp(self):
        super().setUp();self.job=self.root/'job';self.job.mkdir();self.assertEqual(worker.run(self.job,self.source,'container'),0);self.database=self.job/'events.sqlite'
    def test_real_worker_source_binding(self):
        state=json.loads((self.job/'state.json').read_text());self.assertEqual(state['state'],'complete');self.assertEqual(state['source_sha256'],hashlib.sha256(self.source.read_bytes()).hexdigest());self.assertFalse(state['semantic_replay_verified'])
    def test_keyset_pagination(self):
        page=store.query(self.database,{'limit':1});second=store.query(self.database,{'limit':1,'after':page['next']});self.assertNotEqual(page['rows'][0]['sequence'],second['rows'][0]['sequence'])
    def test_protocol_filters_do_not_invent_decoding(self):self.assertEqual(store.query(self.database,{'protocol':'dns'})['rows'],[])
    def test_query_injection_is_not_sql(self):self.assertEqual(store.query(self.database,{'protocol':"dns' OR 1=1 --"})['rows'],[])
    def test_page_limit(self):
        with self.assertRaises(ValueError):store.query(self.database,{'limit':99999})
    def test_unknown_filter(self):
        with self.assertRaises(ValueError):store.query(self.database,{'sql':'DROP TABLE events'})
    def test_original_bytes_on_demand(self):
        p=store.packet_bytes(self.database,self.source,'1',0,14);self.assertTrue(p['packet_hash_checked']);self.assertEqual(len(bytes.fromhex(p['hex'])),14)
    def test_packet_tamper_detected(self):
        raw=bytearray(self.source.read_bytes());raw[-1]^=1;self.source.write_bytes(raw)
        with self.assertRaises(ValueError):store.packet_bytes(self.database,self.source,'1')
    def test_unknown_time_not_zero(self):self.assertNotEqual(store.overview(self.database)['first_ns'],'0')
    def test_time_filter_exact(self):self.assertEqual(len(store.query(self.database,{'kind':'packet.observed','start_ns':'7000000000','end_ns':'7000000000'})['rows']),1)
    def test_timeline_counts(self):self.assertEqual(sum(x['count']for x in store.timeline(self.database)['buckets']),1)
    def test_detail_references(self):
        row=store.query(self.database,{'kind':'packet.observed'})['rows'][0];detail=store.detail(self.database,row['sequence']);self.assertEqual(detail['event']['evidence']['packets'][0]['frame'],'1')
    def test_missing_native_engine_is_blocked_not_fallback(self):
        other=self.root/'native';other.mkdir();self.assertEqual(worker.run(other,self.source,'rust'),1);s=json.loads((other/'state.json').read_text());self.assertEqual(s['mode'],'rust');self.assertEqual(s['state'],'failed')

if __name__=='__main__':unittest.main()
