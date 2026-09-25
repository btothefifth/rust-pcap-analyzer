#!/usr/bin/env python3
"""Compile and LINK the public C harness against an explicitly built native ABI.

Missing compiler/library is BLOCKED. Compiling an object alone is never reported
as linked execution. No build-time downloads, shell invocation, or mock library.
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
import time
ROOT=Path(__file__).resolve().parents[1]

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb')as f:
        while b:=f.read(65536):h.update(b)
    return h.hexdigest()

def check(destination,compiler=None,library=None):
    destination=Path(destination);destination.mkdir()
    result={'schema':'pcap-evidence.linked-abi-receipt.v1','platform':platform.platform(),
            'compiler':None,'library_sha256':None,'commands':[], 'status':'BLOCKED'}
    compiler=compiler or shutil.which('cl' if os.name=='nt' else 'cc')
    suffix='pcap_evidence_ffi.dll.lib' if os.name=='nt' else 'libpcap_evidence_ffi.dylib' if platform.system()=='Darwin' else 'libpcap_evidence_ffi.so'
    library=Path(library)if library else ROOT/'product/ffi/target/debug'/suffix
    def finish():
        (destination/'receipt.json').write_text(json.dumps(result,indent=2)+'\n')
        return 0 if result['status']=='PASS' else 2 if result['status']=='BLOCKED' else 1
    if not compiler or not library.is_file():
        result['reason']='C compiler or native Rust ABI library unavailable';return finish()
    compiler=shutil.which(str(compiler))or str(Path(compiler).resolve(strict=True));library=library.resolve(strict=True)
    result.update(compiler=compiler,library_sha256=sha(library),header_sha256=sha(ROOT/'product/ffi/pcap_evidence.h'))
    executable=destination.resolve()/('linked-contract.exe' if os.name=='nt' else 'linked-contract')
    harness=ROOT/'product/ffi/tests/linked_contract.c'
    if Path(compiler).name.lower()in {'cl','cl.exe','clang-cl','clang-cl.exe'}:
        command=[compiler,'/nologo','/W4','/WX','/std:c11',str(harness),str(library),'/Fe:'+str(executable),'/Fo:'+str(destination.resolve()/'linked-contract.obj')]
        if os.name=='nt':command+=['/link','ws2_32.lib','userenv.lib','ntdll.lib']
    else:
        command=[compiler,'-std=c11','-Wall','-Wextra','-Werror',str(harness),str(library),'-o',str(executable)]
        if os.name!='nt':command+=['-pthread','-Wl,-rpath,'+str(library.parent)]
    env=dict(os.environ)
    env['PATH']=str(library.parent)+os.pathsep+env.get('PATH','')
    try:
        for name,argv in [('link',command),('execute',[str(executable)])]:
            started=time.monotonic()
            with (destination/(name+'.stdout')).open('xb')as out,(destination/(name+'.stderr')).open('xb')as err:
                proc=subprocess.run(argv,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=60,check=False,shell=False)
            result['commands'].append({'name':name,'argv':argv,'returncode':proc.returncode,'seconds':round(time.monotonic()-started,3)})
            if proc.returncode:result.update(status='FAIL',reason=name+' failed');return finish()
        receipt=json.loads((destination/'execute.stdout').read_text())
        if receipt.get('status')!='PASS' or receipt.get('abi')!=1:raise ValueError('ABI harness did not emit a valid success receipt')
        result.update(status='PASS',execution=receipt,executable_sha256=sha(executable))
    except (OSError,ValueError,subprocess.TimeoutExpired)as error:
        result.update(status='FAIL',reason=str(error))
    return finish()

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--compiler');p.add_argument('--library',type=Path);a=p.parse_args()
    raise SystemExit(check(a.output,a.compiler,a.library))
