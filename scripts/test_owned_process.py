"""Small native Python witnesses for the qualification process owner.

No Rust, cargo-fuzz, downloads or large fixtures. The oracle is actual retained
byte size and independent child liveness, rather than a cleanup-call spy.
"""
from pathlib import Path
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT))
from scripts import owned_process
import fuzz_campaign
from tools.evidence import process as evidence_process
from tools.research import adapters


def gone(pid):
    # A zombie has physically stopped executing; only its parent/init can reap
    # an orphan. The runner must itself reap the directly launched child.
    stat=Path('/proc')/str(pid)/'stat'
    if stat.is_file():
        try:return stat.read_text().rsplit(')',1)[1].split()[0]=='Z'
        except (FileNotFoundError, ProcessLookupError):return True
    try:os.kill(pid,0)
    except ProcessLookupError:return True
    return False


class OwnedProcess(unittest.TestCase):
    def setUp(self):
        # Each lifecycle fixture owns its own outer runner. Nested runner calls
        # still inherit the marker created by that runner's real exec boundary.
        environment = dict(os.environ)
        environment.pop(owned_process._GROUP_ENV, None)
        owner = mock.patch.dict(os.environ, environment, clear=True)
        owner.start()
        self.addCleanup(owner.stop)

    @unittest.skipUnless(os.name == 'posix', 'outer runner ownership is POSIX')
    def test_lifecycle_fixtures_pass_inside_the_real_outer_runner(self):
        cases = (
            'test_timeout_kills_descendant_after_leader_exit_and_drains',
            'test_outer_validator_timeout_owns_nested_runner_child',
            'test_clean_leader_cannot_leave_child_without_inherited_pipes',
            'test_adapter_keyboard_interrupt_reaps_child_and_descendant',
        )
        command = [sys.executable, '-m', 'unittest',
                   *('scripts.test_owned_process.OwnedProcess.' + case for case in cases)]
        result = owned_process.run(command, cwd=ROOT, timeout=20, max_output_bytes=32768)
        self.assertIsNone(result.reason)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertIn(b'Ran 4 tests', result.stderr)

    def test_exact_terminal_output_cap_and_fast_exit(self):
        with tempfile.TemporaryDirectory(prefix='pcap-terminal-cap-') as temporary:
            for count in (1,2,4096):
                name='bytes-'+str(count)
                result=evidence_process.run([sys.executable,'-c',f'import os;os.write(1,b"x"*{count})'],
                                            Path(temporary),name,max_log_bytes=1,timeout=3)
                self.assertEqual(result['status'],'PASS' if count==1 else 'FAIL')
                self.assertEqual(result['reason'],None if count==1 else 'output_budget')
                retained=sum(Path(result[key]).stat().st_size for key in ('stdout','stderr'))
                self.assertEqual(retained,1)

    def test_cap_conserves_both_streams_and_keeps_exact_limit_valid(self):
        for cap,reason in ((8,None),(7,'output_budget')):
            out,err=io.BytesIO(),io.BytesIO()
            result=owned_process.run([sys.executable,'-c','import os;os.write(1,b"1234");os.write(2,b"5678")'],
                                     timeout=3,max_output_bytes=cap,stdout=out,stderr=err)
            self.assertEqual(result.reason,reason)
            self.assertEqual(len(out.getvalue())+len(err.getvalue()),cap)

    @unittest.skipUnless(os.name=='posix','process-group ownership is POSIX')
    def test_timeout_kills_descendant_after_leader_exit_and_drains(self):
        with tempfile.TemporaryDirectory(prefix='pcap-owned-descendant-') as temporary:
            marker=Path(temporary)/'child.pid'
            code='import subprocess,sys,pathlib;p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"]);pathlib.Path(sys.argv[1]).write_text(str(p.pid))'
            result=owned_process.run([sys.executable,'-c',code,str(marker)],timeout=.8,max_output_bytes=64)
            self.assertEqual(result.reason,'timeout')
            pid=int(marker.read_text())
            deadline=time.monotonic()+2
            while not gone(pid) and time.monotonic()<deadline:time.sleep(.01)
            self.assertTrue(gone(pid),'descendant remains alive after group cleanup')

    @unittest.skipUnless(os.name=='posix','nested process-group ownership is POSIX')
    def test_outer_validator_timeout_owns_nested_runner_child(self):
        with tempfile.TemporaryDirectory(prefix='pcap-nested-runner-') as temporary:
            marker=Path(temporary)/'child.json';parents=[]
            real_popen=owned_process.subprocess.Popen
            def create(*args,**kwargs):
                proc=real_popen(*args,**kwargs);parents.append(proc);return proc
            child='import os,sys,json,pathlib,time;pathlib.Path(sys.argv[1]).write_text(json.dumps([os.getpid(),os.getpgrp()]));time.sleep(30)'
            outer='import sys;sys.path.insert(0,sys.argv[1]);import owned_process;owned_process.run([sys.executable,"-c",sys.argv[2],sys.argv[3]],timeout=30,max_output_bytes=64)'
            with mock.patch.object(owned_process.subprocess,'Popen',create):
                result=owned_process.run([sys.executable,'-c',outer,str(ROOT/'scripts'),child,str(marker)],
                                         timeout=1,max_output_bytes=128)
            self.assertEqual(result.reason,'timeout')
            pid,group=json.loads(marker.read_text())
            self.assertEqual(group,parents[0].pid,'nested runner must retain the outer group')
            deadline=time.monotonic()+2
            while not gone(pid) and time.monotonic()<deadline:time.sleep(.01)
            self.assertTrue(gone(pid),'nested child escaped validator cleanup')

    @unittest.skipUnless(os.name=='posix','process-group ownership is POSIX')
    def test_clean_leader_cannot_leave_child_without_inherited_pipes(self):
        with tempfile.TemporaryDirectory(prefix='pcap-closed-pipe-child-') as temporary:
            marker=Path(temporary)/'child.pid'
            code='import subprocess,sys,pathlib;p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);pathlib.Path(sys.argv[1]).write_text(str(p.pid))'
            result=owned_process.run([sys.executable,'-c',code,str(marker)],timeout=3,max_output_bytes=64)
            self.assertEqual((result.returncode,result.reason),(0,None))
            pid=int(marker.read_text());deadline=time.monotonic()+2
            while not gone(pid) and time.monotonic()<deadline:time.sleep(.01)
            self.assertTrue(gone(pid))

    @unittest.skipUnless(os.name=='posix','process-group ownership is POSIX')
    def test_adapter_keyboard_interrupt_reaps_child_and_descendant(self):
        with tempfile.TemporaryDirectory(prefix='pcap-interrupted-adapter-') as temporary:
            marker=Path(temporary)/'child.pid';parents=[]
            real_popen=owned_process.subprocess.Popen;real_sleep=time.sleep
            interrupted = False
            def create(*args,**kwargs):
                proc=real_popen(*args,**kwargs);parents.append(proc);return proc
            def interrupt(_):
                nonlocal interrupted
                if interrupted:
                    return real_sleep(_)
                deadline=time.monotonic()+3
                while not marker.is_file() and time.monotonic()<deadline:real_sleep(.005)
                self.assertTrue(marker.is_file(),'child must reach the owning boundary')
                interrupted = True
                raise KeyboardInterrupt()
            code='import subprocess,sys,pathlib,time;p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"]);pathlib.Path(sys.argv[1]).write_text(str(p.pid));time.sleep(30)'
            with mock.patch.object(owned_process.subprocess,'Popen',create),mock.patch.object(owned_process.time,'sleep',interrupt):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    adapters.execute([sys.executable,'-c',code,str(marker)],timeout=4,output_limit=64)
            self.assertEqual(caught.exception.process_result.reason,'interrupted')
            self.assertIsNotNone(parents[0].returncode)
            self.assertTrue(parents[0].stdout.closed and parents[0].stderr.closed)
            pid=int(marker.read_text());deadline=time.monotonic()+2
            while not gone(pid) and time.monotonic()<deadline:real_sleep(.01)
            self.assertTrue(gone(pid))

    @unittest.skipUnless(os.name=='posix','process-group ownership is POSIX')
    def test_partial_pump_startup_failure_stops_and_reaps_actual_child(self):
        real_popen=owned_process.subprocess.Popen;parents=[]
        real_start=owned_process.threading.Thread.start;starts=0
        def create(*args,**kwargs):
            proc=real_popen(*args,**kwargs);parents.append(proc);return proc
        def start(thread):
            nonlocal starts
            starts+=1
            if starts==2:raise RuntimeError('injected second pump startup failure')
            return real_start(thread)
        with mock.patch.object(owned_process.subprocess,'Popen',create),mock.patch.object(owned_process.threading.Thread,'start',start):
            with self.assertRaisesRegex(RuntimeError,'second pump startup') as caught:
                adapters.execute([sys.executable,'-c','import time;time.sleep(30)'],timeout=3,output_limit=64)
        self.assertEqual(caught.exception.process_result.reason,'runner_exception')
        self.assertIsNotNone(parents[0].returncode)
        self.assertTrue(parents[0].stdout.closed and parents[0].stderr.closed)

    def test_fuzz_source_closure_detects_nested_bytes_locks_and_membership(self):
        with tempfile.TemporaryDirectory(prefix='pcap-fuzz-source-') as temporary:
            root=Path(temporary)
            (root/'fuzz').mkdir();(root/'src/semantics').mkdir(parents=True);(root/'src/correlate').mkdir()
            (root/'fuzz/Cargo.toml').write_text('[dependencies]\nengine={path=".."}\n')
            (root/'Cargo.toml').write_text('[package]\nname="engine"\nversion="0.1.0"\n')
            paths=('src/semantics/dnp3.rs','src/correlate/bgp.rs','fuzz/Cargo.lock','.cargo/config.toml')
            for name in paths:
                path=root/name;path.parent.mkdir(exist_ok=True);path.write_bytes(b'original')
            for name in paths:
                before=fuzz_campaign.source_identity(root)
                (root/name).write_bytes(b'changed')
                self.assertNotEqual(before,fuzz_campaign.source_identity(root),name)
            before=fuzz_campaign.source_identity(root)
            (root/'src/semantics/new.rs').write_bytes(b'new member')
            self.assertNotEqual(before,fuzz_campaign.source_identity(root))
            after=fuzz_campaign.source_identity(root)
            (root/'src/semantics/new.rs').unlink()
            self.assertNotEqual(after,fuzz_campaign.source_identity(root))

    def test_campaign_selector_equals_actual_eligible_manifest_targets(self):
        import tomllib
        manifest=tomllib.loads((ROOT/'fuzz/Cargo.toml').read_text())
        eligible={item['name'] for item in manifest['bin'] if (ROOT/'fuzz'/item['path']).is_file()}
        self.assertEqual(set(fuzz_campaign.TARGETS),eligible)
        self.assertIn('semantics',eligible)

    def test_fuzz_interruption_preserves_terminal_receipt_and_attempt(self):
        with tempfile.TemporaryDirectory(prefix='pcap-fuzz-interrupted-') as temporary:
            output=Path(temporary)/'campaign'
            def interrupt(*args):
                error=KeyboardInterrupt()
                error.campaign_step={'status':'INTERRUPTED','log':'attempt.log','command':['fake-tool']}
                raise error
            with mock.patch.object(sys,'argv',['fuzz_campaign.py','--output',str(output),'--toolchain','nightly']),mock.patch.object(fuzz_campaign.shutil,'which',return_value='/unused'),mock.patch.object(fuzz_campaign,'execute',interrupt),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(fuzz_campaign.main(),130)
            receipt=json.loads((output/'receipt.json').read_text())
            self.assertEqual(receipt['status'],'INTERRUPTED')
            self.assertEqual(receipt['steps'][0]['status'],'INTERRUPTED')
            self.assertIn('finished_utc',receipt)
            self.assertTrue(receipt['source_unchanged'])

    def test_successful_fuzz_steps_cannot_qualify_changed_source(self):
        with tempfile.TemporaryDirectory(prefix='pcap-fuzz-post-source-') as temporary:
            output=Path(temporary)/'campaign'
            def execute(command,cwd,log,timeout):
                log.write_text('nightly\n')
                return dict(status='PASS',returncode=0,timed_out=False,command=command)
            def generate(destination):
                destination.mkdir();(destination/'MANIFEST.json').write_text('{}')
            with mock.patch.object(sys,'argv',['fuzz_campaign.py','--output',str(output),'--toolchain','nightly','--targets','semantics']),mock.patch.object(fuzz_campaign.shutil,'which',return_value='/unused'),mock.patch.object(fuzz_campaign,'execute',execute),mock.patch.object(fuzz_campaign,'generate',generate),mock.patch.object(fuzz_campaign,'source_identity',side_effect=[{'source':'initial'},{'source':'changed'}]),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(fuzz_campaign.main(),1)
            receipt=json.loads((output/'receipt.json').read_text())
            self.assertEqual(receipt['status'],'SOURCE_CHANGED')
            self.assertFalse(receipt['source_unchanged'])


if __name__=='__main__':unittest.main()
