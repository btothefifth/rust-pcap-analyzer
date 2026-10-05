#!/usr/bin/env python3
"""Run the follow-up's real portable and native gates, without installing tools.

Native failure is FAIL; unavailable native tooling is BLOCKED. This deliberately
returns 2 for an otherwise-green receipt with required blocked gates.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import tempfile
try:
    from .validation_frontier import (portable_commands, native_commands, native_artifact, source_snapshot, EXCLUDED_PROOF, EXCLUDED_WORKSPACES, semantic_case_command)
except ImportError:
    from validation_frontier import (portable_commands, native_commands, native_artifact, source_snapshot, EXCLUDED_PROOF, EXCLUDED_WORKSPACES, semantic_case_command)
try:
    from .owned_process import run as run_owned
except ImportError:
    from owned_process import run as run_owned
ROOT=Path(__file__).resolve().parents[1]

def artifact_name(manifest):
    return Path(manifest).parent.as_posix().replace('/','-').replace('.','core')

def run(output,portable_only=False):
    output=Path(output).resolve();output.mkdir()
    before=source_snapshot(ROOT)
    gates=[]
    def command(name,argv,required=True,reason=None,expected=0):
        if reason:
            gates.append({'name':name,'status':'BLOCKED','required':required,'reason':reason,'argv':argv});return
        entry={'name':name,'argv':argv,'required':required};started=time.monotonic()
        outpath=output/(name+'.stdout');errpath=output/(name+'.stderr')
        try:
            with outpath.open('xb') as out,errpath.open('xb') as err:
                result=run_owned(argv,cwd=ROOT,stdout=out,stderr=err,timeout=600,
                                 max_output_bytes=64*1024*1024,
                                 env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONHASHSEED='0'))
            entry.update(status='PASS' if result.returncode==expected and not result.reason else 'FAIL',
                         returncode=result.returncode,expected_returncode=expected)
            if result.reason:entry['reason']=result.reason
        except BaseException as error:
            result=getattr(error,'process_result',None)
            entry.update(status='BLOCKED' if isinstance(error,FileNotFoundError) else 'FAIL',
                         reason=result.reason if result else 'gate_interrupted' if isinstance(error,KeyboardInterrupt) else str(error))
            if result:entry['returncode']=result.returncode
            if isinstance(error,(KeyboardInterrupt,SystemExit)):
                entry.update(seconds=round(time.monotonic()-started,3),stdout=outpath.name,stderr=errpath.name)
                gates.append(entry)
                raise
        entry.update(seconds=round(time.monotonic()-started,3),stdout=outpath.name,stderr=errpath.name)
        gates.append(entry)
    try:
        for name, argv in portable_commands(sys.executable):command(name,argv)
        node=shutil.which('node');command('gui-model',[node or 'node','--test','desktop/web/model.test.mjs'],reason=None if node else 'Node unavailable')
        command('catalog',[sys.executable,'-m','tools.research','audit'])
        preflight_ok=all(gate['status']=='PASS' for gate in gates)
        if not portable_only and preflight_ok:
            cargo=shutil.which('cargo')
            for name, tail in native_commands():
                command(name,[cargo or 'cargo',*tail],reason=None if cargo else 'Cargo unavailable')
            command('native-semantic-cases',semantic_case_command(ROOT,sys.executable,output),
                    reason=None if any(g['name']=='root-build' and g['status']=='PASS' for g in gates) else 'successful root all-target build required')
            binary=native_artifact(ROOT,'product/Cargo.toml','pcap-product.exe' if os.name=='nt' else 'pcap-product')
            command('semantic-projection-parity',[sys.executable,'scripts/validate_semantic_product.py','--binary',str(binary),
                    '--output-dir',str(output/'semantic-parity')],reason=None if any(g['name']=='product-build' and g['status']=='PASS' for g in gates) else 'successful product build required')
            # C helper emits its own precise BLOCKED/FAIL/PASS receipt.
            abi=output/'linked-abi'
            suffix='pcap_evidence_ffi.dll.lib' if os.name=='nt' else 'libpcap_evidence_ffi.dylib' if sys.platform=='darwin' else 'libpcap_evidence_ffi.so'
            command('linked-abi',[sys.executable,'scripts/check_linked_abi.py','--output',str(abi),
                    '--library',str(native_artifact(ROOT,'product/ffi/Cargo.toml',suffix))],
                    reason=None if any(g['name']=='ffi-build' and g['status']=='PASS' for g in gates) else 'successful FFI build required')
            if (abi/'receipt.json').is_file():
                value=json.loads((abi/'receipt.json').read_text())
                gate=gates[-1]
                if value['status']=='BLOCKED' and not gate.get('reason') and gate.get('returncode')==2:
                    gate.update(status='BLOCKED',reason=value.get('reason'))
                elif value['status']!=gate['status']:
                    gate.update(status='FAIL',reason=gate.get('reason') or 'ABI receipt/exit status disagreement')
            if sys.platform.startswith('linux'):
                cc=shutil.which('cc')
                with tempfile.TemporaryDirectory(prefix='pcap-followup-denial-') as temporary:
                    binary=Path(temporary)/'denied'
                    command('live-denial-compile',[cc or 'cc','-std=c11','-Wall','-Wextra','-Werror',
                            '-DPCAP_TEST_DENY_SOCKET','product/live/capture_linux.c','-o',str(binary)],
                            reason=None if cc else 'Linux C compiler unavailable')
                    if gates[-1]['status']=='PASS':
                        target=Path(temporary)/'must-not-exist.pcap'
                        command('live-denial-run',[str(binary),'--allow-live-capture','--interface','test0','--output',str(target)],expected=3)
                        if target.exists():gates[-1].update(status='FAIL',reason='denial created capture output')
            else:gates.append({'name':'live-denial','status':'NOT_APPLICABLE','required':False,'reason':'Linux-only injected socket denial'})
        elif not portable_only:
            for name, tail in native_commands():command(name,['cargo',*tail],reason='portable preflight did not pass')
            for name in ['native-semantic-cases','semantic-projection-parity','linked-abi','live-denial']:
                command(name,[],reason='portable preflight did not pass')
    except KeyboardInterrupt:
        if not gates or gates[-1].get('reason') not in {'interrupted','gate_interrupted'}:
            gates.append(dict(name='validation-interrupted',status='FAIL',required=True,reason='interrupted'))
    for name in EXCLUDED_PROOF:
        gates.append({'name':name,'status':'NOT_RUN','required':False,'reason':'independent qualification class; not established by this driver'})
    statuses=[g['status']for g in gates if g['required']]
    status='FAIL'if 'FAIL'in statuses else 'BLOCKED'if 'BLOCKED'in statuses else 'PASS'
    tracked=before
    source_unchanged=source_snapshot(ROOT)==before
    if not source_unchanged:status='FAIL';gates.append({'name':'source-generation','status':'FAIL','required':True,'reason':'source changed during validation'})
    report={'schema':'pcap-evidence.followup-validation.v1','status':status,'scope':'portable_only'if portable_only else 'portable_and_native_requested','platform':platform.platform(),'python':sys.version,'gates':gates,'source_files_sha256':tracked,'source_unchanged':source_unchanged,'native_claims_require_execution':True,'excluded_workspaces':EXCLUDED_WORKSPACES,
            'independent_qualification':{'schema':'BLOCKED','catalog':'BLOCKED','reason':'structural checks only; independent qualification remains open'}}
    (output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':status,'receipt':str(output/'receipt.json')}))
    return {'PASS':0,'FAIL':1,'BLOCKED':2}[status]
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--portable-only',action='store_true',help='select only the explicitly portable gates; native proof is excluded');a=p.parse_args();raise SystemExit(run(a.output,a.portable_only))
