#!/usr/bin/env python3
"""Run the follow-up's real portable and native gates, without installing tools.

Native failure is FAIL; unavailable native tooling is BLOCKED. This deliberately
returns 2 for an otherwise-green receipt with required blocked gates.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parents[1]

def artifact_name(manifest):
    return Path(manifest).parent.as_posix().replace('/','-').replace('.','core')

def run(output):
    output=Path(output).resolve();output.mkdir()
    gates=[]
    def command(name,argv,required=True,reason=None):
        if reason:
            gates.append({'name':name,'status':'BLOCKED','required':required,'reason':reason,'argv':argv});return
        entry={'name':name,'argv':argv,'required':required};started=time.monotonic()
        try:
            with (output/(name+'.stdout')).open('xb')as out,(output/(name+'.stderr')).open('xb')as err:
                result=subprocess.run(argv,cwd=ROOT,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=600,check=False,shell=False)
            entry.update(status='PASS'if result.returncode==0 else 'FAIL',returncode=result.returncode)
        except (OSError,subprocess.TimeoutExpired)as error:entry.update(status='FAIL',reason=str(error))
        entry['seconds']=round(time.monotonic()-started,3);gates.append(entry)
    command('python',[sys.executable,'-m','unittest','discover','-s','tools/tests','-v'])
    node=shutil.which('node');command('gui-model',[node or 'node','--test','desktop/web/model.test.mjs'],reason=None if node else 'Node unavailable')
    command('catalog',[sys.executable,'-m','tools.research','audit'])
    cargo=shutil.which('cargo')
    for manifest in ['Cargo.toml','streaming/Cargo.toml','product/Cargo.toml','product/ffi/Cargo.toml','history/Cargo.toml']:
        name=artifact_name(manifest)
        reason=None if cargo and (ROOT/manifest).is_file() else 'Cargo or required baseline manifest unavailable'
        for task,options in [('fmt',['fmt','--all','--','--check']),('test',['test','--locked','--offline','--all-targets']),('release',['test','--locked','--offline','--release','--all-targets']),('clippy',['clippy','--locked','--offline','--all-targets','--','-D','warnings'])]:
            argv=[cargo or 'cargo',options[0],'--manifest-path',manifest]+options[1:]
            command(name+'-'+task,argv,reason=reason)
    command('history-example-build',[cargo or 'cargo','build','--manifest-path','history/Cargo.toml','--locked','--offline'],reason=None if cargo else 'Cargo unavailable')
    command('ffi-library-build',[cargo or 'cargo','build','--manifest-path','product/ffi/Cargo.toml','--locked','--offline'],reason=None if cargo else 'Cargo unavailable')
    # C helper emits its own precise BLOCKED/FAIL/PASS receipt.
    abi=output/'linked-abi'
    command('linked-abi',[sys.executable,'scripts/check_linked_abi.py','--output',str(abi)])
    if (abi/'receipt.json').is_file():
        value=json.loads((abi/'receipt.json').read_text());gates[-1]['status']=value['status'];gates[-1]['reason']=value.get('reason')
    for name in ['browser-to-native','sustained-fuzz','50-to-500-GB-scale','normative-review','Windows-install-upgrade-uninstall','actual-authorized-NIC-capture']:
        gates.append({'name':name,'status':'NOT_RUN','required':False,'reason':'independent qualification class; not established by this driver'})
    statuses=[g['status']for g in gates if g['required']]
    status='FAIL'if 'FAIL'in statuses else 'BLOCKED'if 'BLOCKED'in statuses else 'PASS'
    tracked={}
    for root in ['history','product/src/protocols','tools/research','tools/desktop']:
        for p in (ROOT/root).rglob('*'):
            if p.is_file() and p.suffix in {'.rs','.py','.toml'} and not any(x in p.parts for x in ('target','__pycache__')):tracked[str(p.relative_to(ROOT))]=hashlib.sha256(p.read_bytes()).hexdigest()
    report={'schema':'pcap-evidence.followup-validation.v1','status':status,'platform':platform.platform(),'python':sys.version,'gates':gates,'source_files_sha256':tracked,'native_claims_require_execution':True}
    (output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':status,'receipt':str(output/'receipt.json')}))
    return {'PASS':0,'FAIL':1,'BLOCKED':2}[status]
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();raise SystemExit(run(a.output))
