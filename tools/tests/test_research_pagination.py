"""Bounded deterministic listing; index construction and payload reads are separate."""
import json
import http.client
import threading
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools.desktop.server import Manager, Server
from tools.desktop.storage import StorageDenied, MAX_RESEARCH
from tools.research.contract import read_json

class ResearchPaginationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='pcap-research-page-')
        self.root=Path(self.temp.name);self.capture=self.root/'captures';self.capture.mkdir()
        self.workspace=self.root/'workspace';self.job='a'*32
        (self.workspace/'runs'/self.job).mkdir(parents=True);self.manager=None
    def tearDown(self):
        if self.manager:self.manager.close()
        self.temp.cleanup()
    def receipt(self,index,raw=None):
        rid=f'{index:032x}';p=self.workspace/'runs'/self.job/'research'/rid;p.mkdir(parents=True)
        (p/'receipt.json').write_text(json.dumps({'id':rid,'status':'IMPORTED_UNTRUSTED_INTERPRETATION'})if raw is None else raw)
        return rid
    def start(self):
        self.manager=Manager(self.capture,self.workspace,disk_budget=1024*1024)
        return self.manager
    def test_bad_receipt_beyond_page_is_not_read_or_vetoed(self):
        for i in range(100):self.receipt(i)
        bad=self.receipt(100,'{');manager=self.start();reads=[]
        def counted(path,limit):reads.append(Path(path).parent.name);return read_json(path,limit)
        with patch('tools.desktop.server.read_json',side_effect=counted):page=manager.research_page(self.job)
        self.assertEqual(len(page['interpretations']),100);self.assertEqual(page['examined'],100)
        self.assertTrue(page['has_more']);self.assertFalse(page['errors']);self.assertNotIn(bad,reads)
        second=manager.research_page(self.job,page['next'])
        self.assertEqual(second['interpretations'],[]);self.assertEqual(second['errors'][0]['id'],bad)
        self.assertEqual(second['next'],bad);self.assertEqual(second['examined'],1);self.assertFalse(second['has_more'])
    def test_page_boundaries_stable_order_and_bounded_no_directory_discovery(self):
        for i in reversed(range(203)):self.receipt(i)
        manager=self.start();pages=[];cursor=''
        # Once the bounded startup census is built, listing never enumerates dirs.
        with patch('tools.desktop.storage.os.scandir',side_effect=AssertionError('listing enumerated workspace')):
            for _ in range(3):
                page=manager.research_page(self.job,cursor);pages.append(page);cursor=page['next']
        ids=[row['id']for page in pages for row in page['interpretations']]
        self.assertEqual(ids,[f'{i:032x}'for i in range(203)])
        self.assertEqual([page['examined']for page in pages],[100,100,3])
        self.assertEqual([page['has_more']for page in pages],[True,True,False])
        self.assertEqual(manager.research_page(self.job,cursor)['examined'],0)
    def test_selected_missing_receipt_advances_cursor_with_explicit_error(self):
        first=self.receipt(1);second=self.receipt(2);manager=self.start()
        (manager.research_path(self.job,first)/'receipt.json').unlink()
        page=manager.research_page(self.job,limit=1)
        self.assertEqual(page['interpretations'],[]);self.assertEqual(page['next'],first)
        self.assertEqual(page['errors'][0]['id'],first);self.assertTrue(page['has_more'])
        self.assertEqual(manager.research_page(self.job,page['next'],1)['interpretations'][0]['id'],second)
    def test_restarted_index_and_new_successful_publication_visible(self):
        first=self.receipt(1);manager=self.start();manager.close();self.manager=None
        manager=self.start();self.assertEqual(manager.list_research(self.job)[0]['id'],first)
        saved=manager.save_research(self.job,{'status':'PROBE'})
        ids=[row['id']for row in manager.research_page(self.job)['interpretations']]
        self.assertEqual(ids,sorted([first,saved['id']]))
    def test_tiny_high_cardinality_has_bounded_payload_reads_and_admission(self):
        for i in range(MAX_RESEARCH):self.receipt(i)
        manager=self.start();reads=[]
        def counted(path,limit):reads.append(path);return read_json(path,limit)
        with patch('tools.desktop.server.read_json',side_effect=counted):page=manager.research_page(self.job,limit=7)
        self.assertEqual(len(reads),7);self.assertEqual(page['examined'],7)
        with self.assertRaises(StorageDenied):manager.save_research(self.job,{'status':'PROBE'})
        self.assertEqual(len(manager.budget.research[self.job]),MAX_RESEARCH)
    def test_http_cursor_endpoint_preserves_rows_and_exposes_work_bound(self):
        for i in range(3):self.receipt(i)
        manager=self.start();server=Server(('127.0.0.1',0),manager)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            connection=http.client.HTTPConnection('127.0.0.1',server.server_address[1],timeout=3)
            connection.request('GET','/api/research/list?job='+self.job+'&limit=2',headers={'Authorization':'Bearer '+server.token})
            response=connection.getresponse();page=json.loads(response.read());connection.close()
            self.assertEqual(response.status,200);self.assertEqual(page['examined'],2)
            self.assertEqual(page['next'],f'{1:032x}');self.assertTrue(page['has_more'])
            connection=http.client.HTTPConnection('127.0.0.1',server.server_address[1],timeout=3)
            connection.request('GET','/api/research/list?job='+self.job+'&limit=2&after='+page['next'],headers={'Authorization':'Bearer '+server.token})
            response=connection.getresponse();page=json.loads(response.read());connection.close()
            self.assertEqual(response.status,200);self.assertEqual(page['interpretations'][0]['id'],f'{2:032x}')
            self.assertEqual(page['examined'],1);self.assertFalse(page['has_more'])
        finally:server.shutdown();server.server_close();thread.join(3)

    def test_invalid_cursor_limit_and_receipt_identity_are_typed(self):
        rid=self.receipt(1,json.dumps({'id':'f'*32}));manager=self.start()
        for after,limit in [('bad',100),('',0),('',101),('',True),('','9999')]:
            with self.assertRaises(ValueError):manager.research_page(self.job,after,limit)
        page=manager.research_page(self.job,limit='1')
        self.assertEqual(page['errors'][0]['id'],rid);self.assertEqual(page['examined'],1)

if __name__=='__main__':unittest.main()
