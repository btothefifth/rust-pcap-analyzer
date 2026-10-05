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
try:
    from .validation_frontier import (EXCLUDED_PROOF, EXCLUDED_WORKSPACES, portable_commands, native_commands,
                                     native_artifact, source_snapshot, semantic_case_command)
except ImportError:
    from validation_frontier import (EXCLUDED_PROOF, EXCLUDED_WORKSPACES, portable_commands, native_commands,
                                    native_artifact, source_snapshot, semantic_case_command)

try:
    from .owned_process import run as run_owned
except ImportError:
    from owned_process import run as run_owned


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def failure_diagnostics(rows, output):
    """Finite gate names/reasons and bounded failed-log tails for CI terminals."""
    issues = []
    remaining = 8000
    for row in rows:
        if row['status'] not in {'FAIL', 'BLOCKED'}:continue
        issue = {key: row[key] for key in ('name', 'status', 'reason', 'returncode', 'log') if key in row}
        if row['status']=='FAIL' and row.get('log') and remaining:
            log = output/row['log']
            if log.is_file():
                with log.open('rb') as handle:
                    count = min(2000, remaining)
                    handle.seek(max(0, log.stat().st_size-count))
                    tail = handle.read(count)
                remaining -= len(tail)
                issue['log_tail'] = tail.decode('utf-8', errors='replace')
        issues.append(issue)
    return issues


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--portable-only',action='store_true',help='do not require native/C gates; reports scope explicitly')
    parser.add_argument('--gui-render',action='store_true',help='optional offline Chromium renderer with recorded responses')
    args=parser.parse_args(argv);root=args.root.resolve(strict=True);out=args.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    before=source_snapshot(root)
    rows=[]
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONHASHSEED='0')
    def blocked(name,category,reason,command):
        rows.append(dict(name=name,category=category,status='BLOCKED',reason=reason,command=command))
    def run(name,category,command,timeout=600,expected=0):
        started=time.monotonic();log=out/(name+'.log')
        row=dict(name=name,category=category,command=command,expected_returncode=expected)
        try:
            with log.open('xb') as output:
                result=run_owned(command,cwd=root,stdout=output,stderr=output,
                                 env=env,timeout=timeout,max_output_bytes=64*1024*1024)
            row.update(status='PASS' if result.returncode==expected and not result.reason else 'FAIL',
                       returncode=result.returncode)
            if result.reason:row['reason']=result.reason
        except BaseException as error:
            result=getattr(error,'process_result',None)
            row.update(status='BLOCKED' if isinstance(error,FileNotFoundError) else 'FAIL',
                       reason=result.reason if result else 'gate_interrupted' if isinstance(error,KeyboardInterrupt) else str(error))
            if result:row['returncode']=result.returncode
            if isinstance(error,(KeyboardInterrupt,SystemExit)):
                row.update(elapsed_seconds=round(time.monotonic()-started,3),log=log.name,
                           log_sha256=digest(log) if log.is_file() else None)
                rows.append(row)
                raise
        row['elapsed_seconds']=round(time.monotonic()-started,3)
        if log.is_file():row.update(log=log.name,log_sha256=digest(log))
        rows.append(row);return row
    try:
        for name, command in portable_commands(sys.executable):
            run(name, 'portable_contracts', command)
        run('catalog-audit','case_maintenance',[sys.executable,'-m','tools.research','audit','--root',str(root)])
        node=shutil.which('node')
        cmd=[node or 'node','--test','desktop/web/model.test.mjs','desktop/web/app.test.mjs']
        if node:run('gui-model-tests','javascript_models',cmd)
        else:blocked('gui-model-tests','javascript_models','Node is unavailable',cmd)
        if args.gui_render:
            run('gui-render','offline_renderer',[sys.executable,'scripts/gui_render_smoke.py','--receipts',str(out/'gui-render')],120)
        preflight_ok=all(row['status']=='PASS' for row in rows)
        if not args.portable_only and preflight_ok:
            native=list(native_commands())
            cargo=shutil.which('cargo')
            for name,tail in native:
                command=[cargo or 'cargo',*tail]
                if cargo and (root/'Cargo.toml').is_file():run(name,'native_rust',command)
                else:blocked(name,'native_rust','Cargo unavailable or source not integrated into the parent repo',command)
            cases=semantic_case_command(root,sys.executable,out)
            if any(r['name']=='root-build' and r['status']=='PASS' for r in rows):
                run('native-semantic-cases','native_semantics',cases)
            else:blocked('native-semantic-cases','native_semantics','requires successful root all-target build',cases)
            binary=native_artifact(root, 'product/Cargo.toml', 'pcap-product.exe' if os.name=='nt' else 'pcap-product')
            if any(r['name']=='product-build' and r['status']=='PASS' for r in rows):
                run('semantic-projection-parity','native_projection',
                    [sys.executable,'scripts/validate_semantic_product.py','--binary',str(binary),
                     '--output-dir',str(out/'semantic-parity')])
            else:blocked('semantic-projection-parity','native_projection','requires successful product build',[])
            cc=shutil.which('cl' if os.name=='nt' else 'cc')
            suffix='pcap_evidence_ffi.dll.lib' if os.name=='nt' else 'libpcap_evidence_ffi.dylib' if sys.platform=='darwin' else 'libpcap_evidence_ffi.so'
            library=native_artifact(root, 'product/ffi/Cargo.toml', suffix)
            abi=out/'linked-abi'
            if any(r['name']=='ffi-build' and r['status']=='PASS' for r in rows):
                row=run('linked-abi','native_abi',[sys.executable,'scripts/check_linked_abi.py',
                        '--output',str(abi),'--library',str(library)])
                if (abi/'receipt.json').is_file():
                    nested=json.loads((abi/'receipt.json').read_text())
                    if nested['status']=='BLOCKED' and not row.get('reason') and row.get('returncode')==2:row['status']='BLOCKED';row['reason']=nested.get('reason')
                    elif nested['status']!=row['status']:row['status']='FAIL';row['reason']=row.get('reason') or 'ABI receipt/exit status disagreement'
            else:blocked('linked-abi','native_abi','requires successful FFI build',[])
            if sys.platform.startswith('linux'):
                with tempfile.TemporaryDirectory(prefix='pcap-c-denial-') as temp:
                    binary=str(Path(temp)/'capture-denied')
                    command=[cc or 'cc','-std=c11','-Wall','-Wextra','-Werror','-DPCAP_TEST_DENY_SOCKET',
                             'product/live/capture_linux.c','-o',binary]
                    if not cc:blocked('live-denial','injected_live_failure','Linux C compiler unavailable',command)
                    elif run('live-denial-compile','injected_live_failure',command)['status']=='PASS':
                        target=str(Path(temp)/'must-not-exist.pcap')
                        row=run('live-denial-run','injected_live_failure',
                                [binary,'--allow-live-capture','--interface','test0','--output',target],expected=3)
                        if Path(target).exists():row['status']='FAIL';row['reason']='denial created capture output'
            else:
                rows.append(dict(name='live-denial',category='injected_live_failure',status='NOT_APPLICABLE',
                                 reason='injected socket denial is Linux-only; actual NIC capture excluded'))
        elif not args.portable_only:
            for name, command in native_commands():blocked(name,'native_rust','portable preflight did not pass',['cargo',*command])
            for name, category in [('native-semantic-cases','native_semantics'),('semantic-projection-parity','native_projection'),('linked-abi','native_abi'),('live-denial','injected_live_failure')]:
                blocked(name,category,'portable preflight did not pass',[])
    except KeyboardInterrupt:
        if not rows or rows[-1].get('reason') not in {'interrupted','gate_interrupted'}:
            rows.append(dict(name='validation-interrupted',category='lifecycle',status='FAIL',reason='interrupted'))
    after=source_snapshot(root)
    if before!=after:rows.append(dict(name='source-generation',category='provenance',status='FAIL',reason='source changed during validation'))
    summary={'schema':'pcap-evidence.product-qualification.v1','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
             'scope':'portable_only'if args.portable_only else 'portable_and_native_requested',
             'platform':platform.platform(),'python':platform.python_version(),
             'results':rows,'source_files_sha256':before,'source_unchanged':before==after,
             'excluded_proof':list(EXCLUDED_PROOF),'excluded_workspaces':EXCLUDED_WORKSPACES,
             'independent_qualification':{'schema':'BLOCKED','catalog':'BLOCKED',
                 'reason':'structural audits and offline models do not establish schema/catalog normative qualification'},'sustained_fuzz_campaign':'NOT_RUN','representative_large_capture_benchmark':'NOT_RUN',
             'full_browser_to_native':'NOT_RUN','normative_protocol_qualification':'NOT_ESTABLISHED',
             'full_history_automatic_tcp':'NOT_IMPLEMENTED'}
    summary['status']='FAIL'if any(r['status']=='FAIL'for r in rows)else 'BLOCKED'if any(r['status']=='BLOCKED'for r in rows)else 'PASS'
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':summary['status'],'scope':summary['scope'],'receipt':str(out/'summary.json'),
                      'failed_gates':failure_diagnostics(rows,out)},indent=2))
    return {'PASS':0,'FAIL':1,'BLOCKED':2}[summary['status']]


if __name__=='__main__':raise SystemExit(main())
