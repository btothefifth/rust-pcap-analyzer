"""Execute an explicitly provided native semantic probe against source-backed cases.

A missing probe is BLOCKED, not a fallback to Python semantic interpretation.
This script verifies normalized field assertions and raw witnesses independently.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys
import threading

ROOT=Path(__file__).resolve().parents[1]
MAX_OUTPUT=4*1024*1024

def sha(b):return hashlib.sha256(b).hexdigest()

def load(path,maximum=MAX_OUTPUT):
    with Path(path).open('rb')as f:b=f.read(maximum+1)
    if len(b)>maximum:raise ValueError('JSON byte budget')
    def unique(pairs):
        d={}
        for k,v in pairs:
            if k in d:raise ValueError('duplicate JSON key')
            d[k]=v
        return d
    return json.loads(b,object_pairs_hook=unique)

def audit(root):
    root=Path(root);manifest=load(root/'manifest.json')
    names=set()
    for c in manifest['cases']+manifest['captures']:
        name=c['path']
        if Path(name).name!=name or name in names:raise ValueError('invalid/duplicate fixture path')
        names.add(name);p=root/name
        if p.is_symlink():raise ValueError('fixture symlink')
        with p.open('rb')as f:b=f.read(65_537)
        if len(b)>65_536:raise ValueError('fixture byte budget')
        if len(b)!=c['bytes']or sha(b)!=c['sha256']:raise ValueError('fixture identity mismatch: '+name)
    return manifest

def validate_report(report,case,payload):
    failures=[]
    if report.get('input_sha256')!=sha(payload):failures.append('input hash')
    if report.get('status')!=case['expected']['status']:failures.append('status')
    if not 0<=int(report.get('consumed',-1))<=len(payload):failures.append('consumed')
    fields={}
    for rec in report.get('records',[]):
        for f in rec['fields']:
            fields.setdefault(f['name'],[]).append(f['value'])
            a,b=int(f['range']['start']),int(f['range']['end'])
            if not 0<=a<b<=len(payload):raise ValueError('field outside source')
            rebuilt=bytearray();cursor=0
            for s in f['evidence']['spans']:
                if s['frame']!='1' or s['record_offset']!='0':raise ValueError('foreign primitive source')
                x,y,p=int(s['start']),int(s['end']),int(s['packet_start'])
                if x!=cursor or y<=x or p<0 or p+y-x>len(payload):raise ValueError('invalid witness range')
                rebuilt.extend(payload[p:p+y-x]);cursor=y
            if bytes(rebuilt)!=payload[a:b] or sha(rebuilt)!=f['evidence']['sha256']:
                raise ValueError('field bytes/hash mismatch')
    for rule in case['expected']['fields']:
        vals=fields.get(rule['name'],[])
        if len(vals)<=rule['ordinal']or vals[rule['ordinal']]!=rule['value']:
            failures.append('field '+rule['name']+'['+str(rule['ordinal'])+']')
    for name in case['expected']['absent_fields']:
        if name in fields:failures.append('invented field '+name)
    return failures

def execute(command, timeout=30):
    """Bound both pipes while the trusted local process is still running."""
    proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False)
    buffers=[bytearray(),bytearray()];limited=threading.Event()
    def read(pipe,index,maximum):
        try:
            while chunk:=pipe.read(4096):
                if len(buffers[index])+len(chunk)>maximum:
                    limited.set()
                    try:proc.kill()
                    except OSError:pass
                    break
                buffers[index].extend(chunk)
        finally:pipe.close()
    threads=[threading.Thread(target=read,args=(proc.stdout,0,MAX_OUTPUT),daemon=True),
             threading.Thread(target=read,args=(proc.stderr,1,65536),daemon=True)]
    for thread in threads:thread.start()
    try:
        code=proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill();proc.wait();raise
    finally:
        for thread in threads:thread.join(timeout=2)
    if any(t.is_alive()for t in threads):raise ValueError('producer pipe did not close')
    if limited.is_set():raise ValueError('producer output limit')
    if code:raise ValueError('producer operational failure '+str(code))
    return bytes(buffers[0]),bytes(buffers[1])

def run(root,probe=None):
    root=Path(root);m=audit(root)
    receipt=dict(schema='pcap-evidence.semantic-case-receipt.v1',cases=[],fixture_audit='PASS',
        native_execution='BLOCKED',normative_review='NOT_RUN',external_differential='NOT_RUN')
    if probe is None or not Path(probe).is_file():
        receipt['reason']='explicit compiled semantic_probe executable required';return receipt,2
    probe=Path(probe).resolve();h=hashlib.sha256()
    with probe.open('rb')as f:
        while block:=f.read(65536):h.update(block)
    receipt['producer_sha256']=h.hexdigest()
    failed=False
    for c in m['cases']:
        cmd=[str(probe),c['protocol'],c['context'],str((root/c['path']).resolve())]
        try:
            data,err=execute(cmd)
            value=json.loads(data);failures=validate_report(value['report'],c,(root/c['path']).read_bytes())
            result=dict(id=c['id'],status='FAIL'if failures else'PASS',failures=failures,
                source_sha256=c['sha256'],stdout_sha256=sha(data),stderr_sha256=sha(err),command=cmd)
        except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired)as e:
            result=dict(id=c['id'],status='FAIL',classification='operational_or_contract_failure',reason=str(e)[:300])
        failed|=result['status']!='PASS';receipt['cases'].append(result)
    receipt['native_execution']='FAIL'if failed else'PASS'
    return receipt,1 if failed else 0

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--fixtures',type=Path,default=ROOT/'fixtures/semantics')
    p.add_argument('--probe',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    receipt,code=run(a.fixtures,a.probe)
    with a.output.open('x',encoding='utf-8')as f:json.dump(receipt,f,indent=2);f.write('\n')
    print(json.dumps(dict(status=receipt['native_execution'],cases=len(receipt['cases']))));sys.exit(code)
