"""Logical admission/lifecycle proof with tiny retained evidence and real workers."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from scripts.product_fixtures import pcap, packet
from tools.desktop.resources import ResourceGuard
from tools.desktop.server import Manager
from tools.desktop.storage import WorkspaceBudget, StorageDenied, MIN_JOB_BUDGET, census
from tools.research.adapters import container_normalize

class WorkspaceBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='pcap-admission-')
        self.root=Path(self.temp.name);self.captures=self.root/'captures';self.captures.mkdir()
        self.source=self.captures/'tiny.pcap';self.source.write_bytes(pcap([packet(b'x','udp')]))
        self.managers=[]
    def tearDown(self):
        for manager in self.managers:
            try:manager.close()
            except StorageDenied:pass
        self.temp.cleanup()
    def manager(self,limit=1024*1024):
        manager=Manager(self.captures,self.root/'workspace',disk_budget=limit)
        self.managers.append(manager);return manager
    def job(self,manager):
        job='a'*32;(manager.workspace/'runs'/job).mkdir()
        (manager.path(job)/'job.json').write_text(json.dumps({'source':'tiny.pcap'}))
        return job
    def controlled_live_job(self,manager):
        """Only replace the process leaf; retain real Manager admission/lifecycle.

        The actual child announces readiness and blocks on an open stdin pipe.
        It cannot complete before cancellation owns and stops it. This tests the
        Manager seam, not analyzer decoding or a probabilistic startup interval.
        """
        real_popen=subprocess.Popen;children=[]
        def launch(command,**kwargs):
            options=dict(kwargs);options.update(stdin=subprocess.PIPE,stdout=subprocess.PIPE)
            child=real_popen([sys.executable,'-c',
                'import sys; print("READY", flush=True); sys.stdin.buffer.read(1)'],**options)
            children.append(child)
            return child
        with patch('tools.desktop.server.subprocess.Popen',side_effect=launch):
            job=manager.start('tiny.pcap','container','ics-full')['id']
        child=manager.children[job];self.assertIs(child,children[0])
        def cleanup():
            if child.poll()is None:child.kill();child.wait(timeout=2)
            child.stdin.close();child.stdout.close()
        self.addCleanup(cleanup)
        # Force a wait at the previously flaky after-start cut. The child remains
        # blocked because this fixture retains the pipe's sole open writer.
        with self.assertRaises(subprocess.TimeoutExpired):child.wait(timeout=0)
        ready=threading.Event();observed=[]
        def read_ready():
            observed.append(child.stdout.read(6));ready.set()
        reader=threading.Thread(target=read_ready,daemon=True);reader.start()
        self.assertTrue(ready.wait(5),'controlled child did not reach its blocking leaf')
        reader.join(1);self.assertFalse(reader.is_alive());self.assertEqual(observed,[b'READY\n'])
        with self.assertRaises(subprocess.TimeoutExpired):child.wait(timeout=0)
        self.assertIsNone(child.poll())
        return job

    def test_recursive_retention_exact_limit_and_one_over(self):
        root=self.root/'logical';(root/'old-job'/'research').mkdir(parents=True)
        (root/'old-job'/'research'/'raw').write_bytes(b'x'*70000)
        owner=WorkspaceBudget(root,80000)
        claim=owner.reserve(root/'new',10000)
        self.assertEqual(owner.status()['admitted_peak_bytes'],'80000')
        with self.assertRaises(StorageDenied):owner.reserve(root/'over',1)
        claim.release()
        with self.assertRaises(StorageDenied):owner.reserve(root/'over',10001)
        self.assertEqual((root/'old-job'/'research'/'raw').stat().st_size,70000)
    def test_nested_worker_monitor_sees_previous_escape(self):
        root=self.root/'guard';(root/'nested').mkdir(parents=True);(root/'nested'/'raw').write_bytes(b'x'*70000)
        guard=ResourceGuard(root,65536);guard.sample()
        self.assertEqual(guard.reason,'observed_workspace_disk_budget')
        self.assertEqual(guard.peak,70000)
    def test_concurrent_reserved_writer_progress_and_rejection_at_barrier(self):
        root=self.root/'logical';root.mkdir();owner=WorkspaceBudget(root,65536)
        admitted=threading.Event();finish=threading.Event();completed=threading.Event();errors=[]
        def writer():
            try:
                claim=owner.reserve(root/'first',40000)
                try:
                    admitted.set();self.assertTrue(finish.wait(3))
                    (root/'first').write_bytes(b'x'*40000);completed.set()
                finally:claim.release()
            except BaseException as error:errors.append(error)
        thread=threading.Thread(target=writer);thread.start()
        try:
            self.assertTrue(admitted.wait(3))
            with self.assertRaises(StorageDenied):owner.reserve(root/'second',25537)
            claim=owner.reserve(root/'valid',25536)
            (root/'valid').write_bytes(b'x'*25536);claim.release()
            # The first claimant is still paused; valid concurrent writer progressed.
            self.assertFalse(completed.is_set());self.assertEqual(owner.status()['admitted_peak_bytes'],'65536')
        finally:finish.set();thread.join(3)
        self.assertFalse(errors);self.assertTrue(completed.is_set());self.assertEqual(census(root).bytes,65536)
    def test_manager_writer_progress_while_other_admission_is_paused(self):
        manager=self.manager(65536);job=self.job(manager)
        ready=threading.Event();finish=threading.Event();results=[];errors=[];real=Path.open
        def pause(path,*args,**kwargs):
            if path.name=='stdout.bin' and threading.current_thread().name=='admitted-research':
                ready.set();self.assertTrue(finish.wait(3))
            return real(path,*args,**kwargs)
        def writer():
            try:results.append(manager.save_research(job,{'artifacts':{'stdout':b'x'*40000}}))
            except BaseException as error:errors.append(error)
        with patch('pathlib.Path.open',pause):
            thread=threading.Thread(target=writer,name='admitted-research');thread.start()
            try:
                self.assertTrue(ready.wait(3))
                with self.assertRaises(StorageDenied):manager.save_research(job,{'artifacts':{'stdout':b'x'*26000}})
                valid=manager.save_research(job,{'artifacts':{'stdout':b'x'*1000}})
                self.assertIn(valid['id'],[row['id']for row in manager.list_research(job)])
                self.assertFalse(results)
            finally:finish.set();thread.join(3)
        self.assertFalse(errors);self.assertEqual(len(results),1)
        self.assertEqual(len(manager.list_research(job)),2)
        self.assertLessEqual(census(manager.workspace).bytes,65536)

    def test_existing_nested_data_and_restart_deny_growth_preserve_evidence(self):
        manager=self.manager(65536);job=self.job(manager)
        accepted=[]
        while True:
            try:accepted.append(manager.save_research(job,{'status':'PROBE','artifacts':{'stdout':b'x'*8192}}))
            except StorageDenied:break
        self.assertTrue(accepted);self.assertLessEqual(census(manager.workspace).bytes,65536)
        retained=census(manager.workspace).bytes;manager.close();self.managers.remove(manager)
        restarted=self.manager(65536)
        self.assertEqual(len(restarted.list_research(job)),len(accepted))
        with self.assertRaises(StorageDenied):restarted.save_research(job,{'artifacts':{'stdout':b'x'*8192}})
        self.assertEqual(census(restarted.workspace).bytes,retained)
    def test_invalid_artifact_is_rejected_before_creating_directory(self):
        manager=self.manager();job=self.job(manager);before=census(manager.workspace)
        with self.assertRaises(ValueError):manager.save_research(job,{'artifacts':{'wrong':b'x'}})
        self.assertEqual(census(manager.workspace),before)
    def test_partial_write_failure_is_retained_and_charged_after_release_and_restart(self):
        manager=self.manager(65536);job=self.job(manager);real=Path.open
        def fail_receipt(path,*args,**kwargs):
            if path.name=='receipt.json':raise OSError('injected publication failure')
            return real(path,*args,**kwargs)
        with patch('pathlib.Path.open',fail_receipt):
            with self.assertRaises(OSError):manager.save_research(job,{'artifacts':{'stdout':b'x'*40000}})
        self.assertEqual(len(manager.budget.reservations),0)
        self.assertEqual(len(list(manager.path(job).glob('research/*/stdout.bin'))),1)
        self.assertGreaterEqual(census(manager.workspace).bytes,40000)
        with self.assertRaises(StorageDenied):manager.save_research(job,{'artifacts':{'stdout':b'x'*26000}})
        manager.close();self.managers.remove(manager);restarted=self.manager(65536)
        self.assertGreaterEqual(int(restarted.budget.status()['retained_bytes']),40000)
        with self.assertRaises(StorageDenied):restarted.save_research(job,{'artifacts':{'stdout':b'x'*26000}})
    def test_retained_entry_and_job_cardinality_denies_without_deletion(self):
        root=self.root/'bounded';root.mkdir()
        for i in range(8):(root/str(i)).write_bytes(b'')
        owner=WorkspaceBudget(root,65536,max_entries=8)
        with self.assertRaises(StorageDenied):owner.reserve(root/'new',0)
        self.assertEqual(len(list(root.iterdir())),8)
        manager=self.manager();job=self.job(manager)
        for i in range(127):(manager.workspace/'runs'/f'{i:032x}').mkdir(exist_ok=True)
        with patch('tools.desktop.server.subprocess.Popen')as launch:
            with self.assertRaises(StorageDenied):manager.start('tiny.pcap','container','ics-full')
        launch.assert_not_called()
    def test_job_minimum_exact_boundary_and_repeated_real_progress(self):
        manager=self.manager(MIN_JOB_BUDGET+131072)
        # Independent old retained file uses the remaining headroom down to exact minimum.
        old=manager.workspace/'old.bin'
        old.write_bytes(b'x'*(manager.budget.available()-MIN_JOB_BUDGET))
        status=manager.start('tiny.pcap','container','ics-full');job=status['id']
        self.assertEqual(json.loads((manager.path(job)/'job.json').read_text())['disk_budget'],str(MIN_JOB_BUDGET))
        proc=manager.children[job];self.assertEqual(proc.wait(timeout=10),0)
        self.assertEqual(manager.status(job)['state'],'complete')
        self.assertEqual(len(manager.budget.reservations),0)
        before=census(manager.workspace)
        with patch('tools.desktop.server.subprocess.Popen')as launch:
            with self.assertRaises(StorageDenied):manager.start('tiny.pcap','container','ics-full')
        launch.assert_not_called();self.assertEqual(census(manager.workspace),before)
    def test_real_worker_retention_and_second_job_reuse_available_space(self):
        manager=self.manager(2*1024*1024)
        first=manager.start('tiny.pcap','container','ics-full')['id']
        self.assertEqual(manager.children[first].wait(timeout=10),0);manager.status(first)
        retained=census(manager.workspace).bytes
        second=manager.start('tiny.pcap','container','ics-full')['id']
        self.assertEqual(json.loads((manager.path(second)/'job.json').read_text())['disk_budget'],str(2*1024*1024-retained))
        self.assertEqual(manager.children[second].wait(timeout=10),0);self.assertEqual(manager.status(second)['state'],'complete')
        self.assertTrue((manager.path(first)/'events.ndjson').is_file())
        self.assertLessEqual(census(manager.workspace).bytes,manager.disk_budget)
    def test_terminal_label_keeps_claim_until_physical_exit(self):
        manager=self.manager();job=self.job(manager)
        (manager.path(job)/'state.json').write_text(json.dumps({'id':job,'state':'complete'}))
        claim=manager.budget.reserve(manager.path(job),manager.budget.available());manager.claims[job]=claim
        class Child:
            code=None
            def poll(self):return self.code
            def wait(self,timeout):raise subprocess.TimeoutExpired('owned worker',timeout)
        child=Child();manager.children[job]=child
        with self.assertRaises(StorageDenied):manager.save_research(job,{'status':'PROBE'})
        self.assertTrue(claim.active);child.code=0
        manager.save_research(job,{'status':'PROBE'})
        self.assertFalse(claim.active)
    def test_terminal_handoff_progresses_at_real_exit_without_retry(self):
        manager=self.manager();job=self.job(manager)
        (manager.path(job)/'state.json').write_text(json.dumps({'id':job,'state':'complete'}))
        claim=manager.budget.reserve(manager.path(job),manager.budget.available());manager.claims[job]=claim
        test=self
        class Child:
            code=None
            def poll(self):return self.code
            def wait(self,timeout):
                test.assertTrue(claim.active)
                self.code=0
                return 0
        manager.children[job]=Child()
        result=manager.save_research(job,{'status':'PROBE'})
        self.assertIn(result['id'],[row['id']for row in manager.list_research(job)])
        self.assertFalse(claim.active)

    def test_child_launch_exception_reconciles_partial_metadata_base_exception_keeps_owner(self):
        manager=self.manager()
        with patch('tools.desktop.server.subprocess.Popen',side_effect=OSError('exec failed')):
            with self.assertRaises(OSError):manager.start('tiny.pcap','container','ics-full')
        self.assertFalse(manager.budget.reservations)
        self.assertEqual(len(list((manager.workspace/'runs').glob('*/job.json'))),1)
        with patch('tools.desktop.server.subprocess.Popen',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):manager.start('tiny.pcap','container','ics-full')
        self.assertEqual(len(manager.budget.reservations),1)
        with self.assertRaises(StorageDenied):manager.close()
        self.assertTrue(manager.owner.exists())
        # The fixture knows no process was created; production does not assume it.
        for claim in list(manager.budget.reservations):claim.release()
        manager.claims.clear()

    def test_failed_cleanup_preserves_owner_and_reservation(self):
        manager=self.manager();job=self.job(manager)
        claim=manager.budget.reserve(manager.path(job),1000);manager.claims[job]=claim
        class Child:
            def poll(self):return None
        manager.children[job]=Child()
        with patch.object(manager,'cancel',side_effect=OSError('injected cleanup failure')):
            with self.assertRaises(OSError):manager.close()
        self.assertTrue(manager.owner.exists());self.assertTrue(claim.active)
        with self.assertRaises(FileExistsError):Manager(self.captures,manager.workspace,disk_budget=manager.disk_budget)
        manager.children.clear();claim.release();manager.claims.clear()
    def test_cancel_postexit_write_keeps_peak_then_next_job_progresses_before_caller_returns(self):
        manager=self.manager(1048576)
        first=self.controlled_live_job(manager)
        proc=manager.children[first];real_wait=proc.wait;real_status=manager.status
        exited=threading.Event();publish_allowed=threading.Event()
        published=threading.Event();return_allowed=threading.Event();errors=[];results=[]
        def pause_wait(timeout):
            result=real_wait(timeout=timeout)
            exited.set();self.assertTrue(publish_allowed.wait(5))
            return result
        def pause_status(job):
            if threading.current_thread().name=='owned-cancel':
                published.set();self.assertTrue(return_allowed.wait(5))
            return real_status(job)
        def cancel():
            try:results.append(manager.cancel(first))
            except BaseException as error:errors.append(error)
        class NextChild:
            code=None
            returncode=None
            def poll(self):return self.code
        child=NextChild();second=None
        def fill_admitted_job(command,**kwargs):
            folder=Path(command[3]);effective=int(command[command.index('--disk-budget')+1])
            (folder/'bounded-output').write_bytes(b'x'*(effective-census(folder).bytes))
            return child
        with patch.object(proc,'wait',side_effect=pause_wait),patch.object(manager,'status',side_effect=pause_status):
            thread=threading.Thread(target=cancel,name='owned-cancel');thread.start()
            try:
                self.assertTrue(exited.wait(5));self.assertIsNotNone(proc.poll())
                claim=manager.claims[first];self.assertTrue(claim.active)
                denied_child=NextChild();denied_child.code=0;denied_child.returncode=0
                with patch('tools.desktop.server.subprocess.Popen',return_value=denied_child)as launch:
                    with self.assertRaises(StorageDenied):manager.start('tiny.pcap','container','ics-full')
                launch.assert_not_called()
                self.assertTrue(claim.active);self.assertEqual(manager.budget.status()['admitted_peak_bytes'],'1048576')
                publish_allowed.set();self.assertTrue(published.wait(5))
                self.assertTrue(thread.is_alive());self.assertFalse(claim.active)
                self.assertEqual(json.loads((manager.path(first)/'state.json').read_text())['state'],'cancelled')
                with patch('tools.desktop.server.subprocess.Popen',side_effect=fill_admitted_job):
                    second=manager.start('tiny.pcap','container','ics-full')['id']
                # Valid next job owns and physically fills the complete remaining
                # envelope while the cancellation caller is still paused.
                self.assertTrue(thread.is_alive());self.assertEqual(census(manager.workspace).bytes,1048576)
                return_allowed.set();thread.join(5)
                self.assertFalse(errors);self.assertEqual(results[0]['state'],'cancelled')
                self.assertEqual(census(manager.workspace).bytes,1048576)
            finally:
                publish_allowed.set();return_allowed.set();thread.join(5)
                if second is not None:
                    child.code=0;manager.children.pop(second);manager.claims.pop(second).release()
        self.assertFalse(manager.terminal_writers)

    def test_cancel_failed_terminal_publication_releases_only_after_failure(self):
        manager=self.manager();job=self.controlled_live_job(manager)
        real_state=__import__('tools.desktop.server',fromlist=['state']).state
        claim=manager.claims[job];observed=[]
        def fail_terminal(path,value):
            if value.get('state')=='cancelled':
                observed.append((claim.active,job in manager.terminal_writers))
                raise OSError('terminal publication rejected')
            return real_state(path,value)
        with patch('tools.desktop.server.state',side_effect=fail_terminal):
            with self.assertRaises(OSError):manager.cancel(job)
        self.assertEqual(observed,[(True,True)])
        self.assertIsNotNone(manager.children[job].poll());self.assertFalse(claim.active)
        self.assertFalse(manager.terminal_writers)
        self.assertTrue((manager.path(job)/'job.json').is_file())
        self.assertLessEqual(census(manager.workspace).bytes,manager.disk_budget)

    def test_stale_status_cannot_replace_concurrent_terminal_state(self):
        manager=self.manager();job=self.job(manager)
        target=manager.path(job)/'state.json'
        target.write_text(json.dumps({'id':job,'state':'queued'}))
        class Child:
            returncode=-15
            def poll(self):return -15
        manager.children[job]=Child()
        ready=threading.Event();finish=threading.Event();errors=[];results=[]
        real=__import__('tools.desktop.server',fromlist=['read_workspace_state']).read_workspace_state
        def stale_read(path,**kwargs):
            value=real(path,**kwargs)
            if not ready.is_set() and threading.current_thread().name=='stale-status':
                ready.set();self.assertTrue(finish.wait(5))
            return value
        def observe():
            try:results.append(manager.status(job))
            except BaseException as error:errors.append(error)
        with patch('tools.desktop.server.read_workspace_state',side_effect=stale_read):
            thread=threading.Thread(target=observe,name='stale-status');thread.start()
            try:
                self.assertTrue(ready.wait(5))
                # A producer's newer terminal commits while the older observer
                # is paused after its initial state sample.
                with manager.lock:
                    claim=manager.budget.reserve(manager.path(job),65536)
                    try:real_state=__import__('tools.desktop.server',fromlist=['state']).state;real_state(target,{'id':job,'state':'cancelled'})
                    finally:claim.release()
                finish.set();thread.join(5)
            finally:finish.set();thread.join(5)
        self.assertFalse(errors);self.assertEqual(results[0]['state'],'cancelled')
        self.assertEqual(json.loads(target.read_text())['state'],'cancelled')

    def test_research_run_denies_before_adapter_and_releases_on_base_exception(self):
        manager=self.manager();job=self.job(manager)
        with patch('tools.desktop.server.adapters.run_adapter')as adapter:
            with self.assertRaises(StorageDenied):manager.run_research(job,'container')
        adapter.assert_not_called()
        manager.disk_budget=64*1024*1024;manager.budget.limit=manager.disk_budget
        with patch('tools.desktop.server.adapters.run_adapter',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):manager.run_research(job,'container')
        self.assertFalse(manager.budget.reservations);self.assertFalse(manager.research_lock.locked())
    def test_import_export_envelopes_and_failed_zip_cleanup_retained(self):
        manager=self.manager(1024*1024);job=self.job(manager);value=container_normalize(self.source)
        a=manager.import_research(job,value);b=manager.import_research(job,value)
        with patch('tools.desktop.server.bundle.create')as create:
            with self.assertRaises(StorageDenied):manager.export_bundle(job,a['id'],b['id'],True)
        create.assert_not_called()
        manager.disk_budget=256*1024*1024;manager.budget.limit=manager.disk_budget
        def failed_zip(path,*args,**kwargs):
            (Path(path).parent/'.research-owned-partial').write_bytes(b'x'*40000)
            raise OSError('cleanup failed')
        with patch('tools.desktop.server.bundle.create',side_effect=failed_zip):
            with self.assertRaises(OSError):manager.export_bundle(job,a['id'],b['id'],True)
        self.assertFalse(manager.budget.reservations)
        self.assertGreaterEqual(int(manager.budget.status()['retained_bytes']),40000)

if __name__=='__main__':unittest.main()
