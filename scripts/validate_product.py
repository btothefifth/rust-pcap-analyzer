#!/usr/bin/env python3
"""Run distinct product qualification gates; absent tools are BLOCKED, not PASS.

Default requires native Rust gates as well as portable checks. No dependency
installation, automatic downloads, real live capture or remote writes occur.
"""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--portable-only',action='store_true',help='do not require native/C gates; reports scope explicitly')
    parser.add_argument('--gui-render',action='store_true',help='optional offline Chromium renderer with recorded responses')
    args=parser.parse_args(argv);root=args.root.resolve(strict=True);out=args.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    rows=[]
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONHASHSEED='0')
    def blocked(name,category,reason,command):
        rows.append(dict(name=name,category=category,status='BLOCKED',reason=reason,command=command))
    def run(name,category,command,timeout=600,expected=0):
        started=time.monotonic();log=out/(name+'.log')
        try:
            with log.open('xb')as output:
                result=subprocess.run(command,cwd=root,stdout=output,stderr=subprocess.STDOUT,
                                      env=env,timeout=timeout,check=False)
            status='PASS'if result.returncode==expected else 'FAIL'
            row=dict(name=name,category=category,status=status,returncode=result.returncode,
                     expected_returncode=expected,elapsed_seconds=round(time.monotonic()-started,3),
                     command=command,log=log.name,log_sha256=digest(log))
        except FileNotFoundError as e:
            row=dict(name=name,category=category,status='BLOCKED',reason=str(e),command=command)
        except subprocess.TimeoutExpired:
            row=dict(name=name,category=category,status='FAIL',reason='gate_timeout',command=command)
        rows.append(row);return row
    run('python-tests','python_tools',[sys.executable,'-m','unittest','discover','-s','tools/tests','-v'])
    run('catalog-audit','case_maintenance',[sys.executable,'-m','tools.research','audit','--root',str(root)])
    node=shutil.which('node')
    cmd=[node or 'node','--test','desktop/web/model.test.mjs']
    if node:run('gui-model-tests','javascript_models',cmd)
    else:blocked('gui-model-tests','javascript_models','Node is unavailable',cmd)
    if args.gui_render:
        run('gui-render','offline_renderer',[sys.executable,'scripts/gui_render_smoke.py','--receipts',str(out/'gui-render')],120)
    if not args.portable_only:
        native=[]
        for label,manifest in [('root','Cargo.toml'),('streaming','streaming/Cargo.toml'),('product','product/Cargo.toml'),('ffi','product/ffi/Cargo.toml')]:
            native.extend([
                (label+'-format',['fmt','--manifest-path',manifest,'--all','--','--check']),
                (label+'-tests',['test','--manifest-path',manifest,'--locked','--offline','--all-targets']),
                (label+'-release-tests',['test','--manifest-path',manifest,'--locked','--offline','--release','--all-targets']),
                (label+'-clippy',['clippy','--manifest-path',manifest,'--locked','--offline','--all-targets','--','-D','warnings']),
                (label+'-build',['build','--manifest-path',manifest,'--locked','--offline','--release','--all-targets']),
            ])
        for features in ['', 'standard', 'extensions', 'industrial', 'industrial-full', 'binary']:
            cmd=['test','--manifest-path','product/Cargo.toml','--locked','--offline','--all-targets','--no-default-features']
            if features:cmd+=['--features',features]
            native.append(('features-'+(features or 'none'),cmd))
        cargo=shutil.which('cargo')
        for name,tail in native:
            command=[cargo or 'cargo',*tail]
            if cargo and (root/'Cargo.toml').is_file():run(name,'native_rust',command)
            else:blocked(name,'native_rust','Cargo unavailable or source not integrated into the parent repo',command)
        cc=shutil.which('cc')
        with tempfile.TemporaryDirectory(prefix='pcap-c-check-')as temp:
            obj=str(Path(temp)/'ffi-harness.o')
            cmd=[cc or 'cc','-std=c11','-Wall','-Wextra','-Werror','-c','product/ffi/harness.c','-o',obj]
            if cc:run('ffi-header-compile','c_header_only',cmd)
            else:blocked('ffi-header-compile','c_header_only','C compiler unavailable',cmd)
            if sys.platform.startswith('linux') and cc:
                binary=str(Path(temp)/'capture-denied')
                command=[cc,'-std=c11','-Wall','-Wextra','-Werror','-DPCAP_TEST_DENY_SOCKET','product/live/capture_linux.c','-o',binary]
                if run('live-denial-compile','injected_live_failure',command)['status']=='PASS':
                    target=str(Path(temp)/'must-not-exist.pcap')
                    row=run('live-denial-run','injected_live_failure',[binary,'--allow-live-capture','--interface','test0','--output',target],expected=3)
                    if Path(target).exists():row['status']='FAIL';row['reason']='denial created capture output'
            else:blocked('live-denial','injected_live_failure','Linux and cc required',[])
            library=root/'product/ffi/target/release'
            if cc and sys.platform.startswith('linux') and any(r['name']=='ffi-build' and r['status']=='PASS' for r in rows):
                harness=str(Path(temp)/'ffi-client')
                command=[cc,'-std=c11','-Wall','-Wextra','-Werror','product/ffi/harness.c',
                         '-L'+str(library),'-lpcap_evidence_ffi','-Wl,-rpath,'+str(library),'-o',harness]
                if run('ffi-client-link','native_abi',command)['status']=='PASS':
                    run('ffi-client-run','native_abi',[harness])
            else:
                blocked('ffi-client-link-and-run','native_abi','requires successful native FFI build and Linux C toolchain; see platform instructions',[])
        if (root/'scripts/validate.py').is_file() and cargo:
            run('baseline-validator','baseline_regression',[sys.executable,'scripts/validate.py'],1800)
        else:
            blocked('baseline-validator','baseline_regression','integrated baseline and Cargo required',[sys.executable,'scripts/validate.py'])
    summary={'schema':'pcap-evidence.product-qualification.v1','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
             'scope':'portable_only'if args.portable_only else 'portable_and_native_requested',
             'platform':platform.platform(),'python':platform.python_version(),
             'results':rows,'sustained_fuzz_campaign':'NOT_RUN','representative_large_capture_benchmark':'NOT_RUN',
             'full_browser_to_native':'NOT_RUN','normative_protocol_qualification':'NOT_ESTABLISHED',
             'full_history_automatic_tcp':'NOT_IMPLEMENTED'}
    summary['status']='FAIL'if any(r['status']=='FAIL'for r in rows)else 'BLOCKED'if any(r['status']=='BLOCKED'for r in rows)else 'PASS'
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':summary['status'],'scope':summary['scope'],'receipt':str(out/'summary.json')},indent=2))
    return {'PASS':0,'FAIL':1,'BLOCKED':2}[summary['status']]


if __name__=='__main__':raise SystemExit(main())
