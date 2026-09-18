"""Real local HTTP and process integration tests (independent container mode)."""
import copy
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from scripts.product_fixtures import pcap,packet
from tools.desktop.server import Manager,Server
from tools.research.adapters import container_normalize
from tools.research.bundle import verify

class HttpTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.captures=self.root/'captures';self.captures.mkdir();self.source=self.captures/'test.pcap';self.source.write_bytes(pcap([packet(b'test','udp')]))
        self.manager=Manager(self.captures,self.root/'workspace');self.server=Server(('127.0.0.1',0),self.manager);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):self.server.shutdown();self.manager.close();self.server.server_close();self.thread.join();self.temp.cleanup()
    def request(self,path,data=None,auth=True,headers=None,raw=False):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_address[1],timeout=5);h={}
        if auth:h['Authorization']='Bearer '+self.server.token
        if data is not None:h['Content-Type']='application/json'
        h.update(headers or {});conn.request('POST'if data is not None else 'GET',path,None if data is None else json.dumps(data),h);r=conn.getresponse();value=r.read();result=(r.status,value if raw else json.loads(value));conn.close();return result
    def job(self):
        status,data=self.request('/api/start',dict(capture='test.pcap',mode='container',profile='ics-full'));self.assertEqual(status,200)
        job=data['id']
        # Windows process creation can be delayed by endpoint scanning; keep
        # this a bounded functional timeout without turning startup latency
        # into a flaky correctness failure.
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            status,data=self.request('/api/status?job='+job)
            if data['state']not in {'queued','running'}:break
            time.sleep(.02)
        self.assertEqual(data['state'],'complete');return job
    def test_missing_token_denied(self):self.assertEqual(self.request('/api/config',auth=False)[0],403)
    def test_wrong_host_denied(self):self.assertEqual(self.request('/api/config',headers={'Host':'attacker.invalid'})[0],403)
    def test_cross_origin_denied(self):self.assertEqual(self.request('/api/config',headers={'Origin':'https://attacker.invalid'})[0],403)
    def test_local_config(self):status,v=self.request('/api/config');self.assertEqual(status,200);self.assertFalse(v['engine_available'])
    def test_traversal_rejected(self):self.assertEqual(self.request('/api/start',dict(capture='../secret',mode='container',profile='ics-full'))[0],400)
    def test_no_implicit_native_fallback(self):self.assertEqual(self.request('/api/start',dict(capture='test.pcap',mode='rust',profile='ics-full'))[0],400)
    def test_real_worker_query_and_hex(self):
        job=self.job();status,d=self.request('/api/query?job='+job+'&kind=packet.observed');self.assertEqual(status,200);self.assertEqual(len(d['rows']),1)
        status,p=self.request('/api/packet?job='+job+'&frame=1');self.assertEqual(status,200);self.assertTrue(p['packet_hash_checked'])
    def test_catalog_and_audit(self):self.assertEqual(self.request('/api/audit')[1]['maintenance_status'],'PASS')
    def test_research_compare_export_verified(self):
        job=self.job();_,a=self.request('/api/research/run',dict(job=job,adapter='container'));self.assertEqual(a['status'],'PASS')
        b=container_normalize(self.source);b['producer']['id']='deliberately-altered-test';b['producer']['origin']='manual_research';b['observations'][1]['value']['sha256']='f'*64
        _,r=self.request('/api/research/import',dict(job=job,interpretation=b));self.assertEqual(r['status'],'IMPORTED_UNTRUSTED_INTERPRETATION')
        _,diff=self.request('/api/research/compare',dict(job=job,left=a['id'],right=r['id']));self.assertEqual(diff['first_semantic_divergence']['layer'],'packet_bytes')
        self.assertEqual(self.request('/api/research/export',dict(job=job,left=a['id'],right=r['id']))[0],400)
        _,e=self.request('/api/research/export',dict(job=job,left=a['id'],right=r['id'],include_raw_capture=True))
        code,data=self.request('/api/research/download?job='+job+'&name='+e['name'],raw=True);self.assertEqual(code,200);out=self.root/'export.zip';out.write_bytes(data);self.assertEqual(verify(out)['status'],'PASS')
    def test_workspace_exclusive(self):
        with self.assertRaises(FileExistsError):Manager(self.captures,self.root/'workspace')
    @unittest.skipUnless(os.name=='posix','process-group cancellation tested on POSIX')
    def test_cancel_owns_worker_group_and_keeps_source(self):
        self.source.write_bytes(pcap([packet(b'test','udp')for _ in range(20000)]));before=self.source.read_bytes();_,j=self.request('/api/start',dict(capture='test.pcap',mode='container',profile='ics-full'));code,s=self.request('/api/cancel',dict(job=j['id']));self.assertEqual(code,200);self.assertIn(s['state'],{'cancelled','complete'});self.assertEqual(self.source.read_bytes(),before)

if __name__=='__main__':unittest.main()
