"""Local-only evidence explorer with isolated workers and bounded query endpoints.

Security boundary: trusted local account and stable capture/workspace parents.
No generic shell or arbitrary filesystem access is exposed to the browser.
"""
from __future__ import annotations
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import re
import secrets
import signal
import sqlite3
import subprocess
import sys
import threading
import urllib.parse
import uuid
from . import store
from .worker import state
from tools.research.contract import safe_file,read_json,decode_json,canonical,compare_fields,file_identity
from tools.research import adapters,cases,bundle
from tools.product.comparison import validate as validate_interpretation
ROOT=Path(__file__).resolve().parents[2]
WEB=ROOT/"desktop/web"

class Manager:
    def __init__(self,capture_root,workspace,engine=None,tshark=None,disk_budget=10*1024**3):
        self.capture_root=Path(capture_root).resolve(strict=True);self.workspace=Path(workspace).resolve()
        if self.workspace==self.capture_root:raise ValueError("choose a separate workspace, not the capture directory")
        self.workspace.mkdir(parents=True,exist_ok=True);(self.workspace/"runs").mkdir(exist_ok=True)
        self.engine=Path(engine).resolve(strict=True)if engine else None;self.tshark=Path(tshark).resolve(strict=True)if tshark else None
        self.disk_budget=disk_budget;self.children={};self.lock=threading.Lock();self.research_lock=threading.Lock()
        self.owner=self.workspace/".owner.lock"
        fd=os.open(self.owner,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w")as f:f.write(str(os.getpid()))
        # This manager owns this workspace exclusively. Interrupted jobs remain
        # inspectable but cannot inherit a successful source binding.
        for p in (self.workspace/"runs").glob("*/state.json"):
            try:
                value=read_json(p)
                if value.get("state")in {"running","queued","cancelling"}:value.update(state="interrupted",source_binding="provisional_prefix");state(p,value)
            except (ValueError,OSError):pass
    def path(self,job):
        if not isinstance(job,str)or not re.fullmatch(r"[0-9a-f]{32}",job):raise ValueError("invalid workspace job ID")
        p=self.workspace/"runs"/job
        if p.is_symlink()or not p.is_dir():raise ValueError("job not found")
        return p
    def source(self,job):return safe_file(self.capture_root,read_json(self.path(job)/"job.json")["source"])
    def status(self,job):
        p=self.path(job);v=read_json(p/"state.json")
        proc=self.children.get(job)
        if proc is not None and proc.poll()is not None and v.get("state")in {"queued","running"}:
            error=(p/"worker.stderr.txt")
            detail=error.read_text(errors="replace")[:320]if error.is_file()else ""
            v.update(state="failed",source_binding="provisional_prefix",worker_exit_code=proc.returncode,error=detail or "worker exited before completion")
            state(p/"state.json",v)
        return v
    def jobs(self):
        values=[]
        for p in sorted((self.workspace/"runs").iterdir(),reverse=True):
            if re.fullmatch(r"[0-9a-f]{32}",p.name):
                try:values.append(self.status(p.name))
                except (ValueError,OSError):continue
            if len(values)>=100:break
        return values
    def captures(self,after=""):
        # Bounded single-directory listing. Nested files can be selected by an
        # explicitly entered relative path; no uncontrolled recursive traversal.
        rows=[];examined=0
        with os.scandir(self.capture_root)as entries:
            for e in entries:
                examined+=1
                if examined>10000:break
                if e.is_file(follow_symlinks=False)and e.name.lower().endswith((".pcap",".pcapng",".cap")):
                    rows.append({"path":e.name,"bytes":str(e.stat(follow_symlinks=False).st_size)})
        rows.sort(key=lambda x:x["path"])
        selected=[r for r in rows if r["path"]>after]
        return {"files":selected[:200],"has_more":len(selected)>200,"listing_limited":examined>10000}
    def start(self,relative,mode,profile):
        source=safe_file(self.capture_root,relative)
        if mode not in {"rust","container"}or profile not in {"it-light","it-full","ics-core","ics-full"}:raise ValueError("invalid mode/profile")
        if mode=="rust"and self.engine is None:raise ValueError("Rust engine not configured; build product and launch with --engine")
        with self.lock:
            if any(p.poll()is None for p in self.children.values()):raise ValueError("one active analysis job allowed; cancel or finish it first")
            job=uuid.uuid4().hex;p=self.workspace/"runs"/job;p.mkdir()
            (p/"job.json").write_bytes(canonical({"source":relative,"mode":mode,"profile":profile})+b"\n")
            state(p/"state.json",{"id":job,"state":"queued","source_name":source.name,"source_bytes":str(source.stat().st_size),"mode":mode,"source_binding":"provisional","packets":"0","events":"0"})
            cmd=[sys.executable,"-m","tools.desktop.worker",str(p),str(source),"--mode",mode,"--profile",profile,"--disk-budget",str(self.disk_budget)]
            if self.engine:cmd+=["--engine",str(self.engine)]
            env={**os.environ,"PYTHONPATH":str(ROOT),"PYTHONUNBUFFERED":"1"}
            flags={"start_new_session":True}if os.name=="posix"else {"creationflags":subprocess.CREATE_NEW_PROCESS_GROUP}
            stderr=(p/"worker.stderr.txt").open("wb")
            try:self.children[job]=subprocess.Popen(cmd,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=stderr,shell=False,**flags)
            finally:stderr.close()
        return self.status(job)
    def cancel(self,job):
        p=self.path(job);proc=self.children.get(job)
        if proc and proc.poll()is None:
            if os.name=="posix":os.killpg(proc.pid,signal.SIGTERM)
            else:
                # Windows console break reaches the worker's process group and
                # native child; force terminate the worker if it does not exit.
                try:proc.send_signal(signal.CTRL_BREAK_EVENT)
                except OSError:proc.terminate()
            try:proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                if os.name=="posix":os.killpg(proc.pid,signal.SIGKILL)
                else:proc.kill()
                proc.wait(timeout=2)
            value=read_json(p/"state.json");value.update(state="cancelled",source_binding="provisional_prefix");state(p/"state.json",value)
        return self.status(job)
    def close(self):
        for job in list(self.children):self.cancel(job)
        self.owner.unlink(missing_ok=True)
    def research_path(self,job,rid):
        if not isinstance(rid,str)or not re.fullmatch(r"[0-9a-f]{32}",rid):raise ValueError("invalid interpretation ID")
        p=self.path(job)/"research"/rid
        if p.is_symlink()or not p.is_dir():raise ValueError("interpretation not found")
        return p
    def save_research(self,job,result):
        parent=self.path(job)/"research";parent.mkdir(exist_ok=True);rid=uuid.uuid4().hex;p=parent/rid;p.mkdir()
        artifacts=result.get("artifacts",{})
        for name,raw in artifacts.items():
            if name not in {"stdout","stderr","version"}or not isinstance(raw,bytes)or len(raw)>8*1024*1024:raise ValueError("tool artifact budget")
            (p/(name+".bin")).write_bytes(raw)
        if result.get("snapshot"):(p/"interpretation.json").write_bytes(canonical(result["snapshot"])+b"\n")
        receipt={k:v for k,v in result.items()if k not in {"snapshot","artifacts"}};receipt["id"]=rid
        if result.get("snapshot"):receipt["producer"]=result["snapshot"]["producer"]
        (p/"receipt.json").write_bytes(canonical(receipt)+b"\n");return receipt
    def run_research(self,job,adapter):
        if adapter not in {"container","product","tshark"}:raise ValueError("adapter not allowed")
        if not self.research_lock.acquire(blocking=False):raise ValueError("research job already running")
        try:
            binary=self.engine if adapter=="product"else self.tshark if adapter=="tshark"else None
            result=adapters.run_adapter(adapter,self.source(job),binary,timeout=30)
            return self.save_research(job,result)
        finally:self.research_lock.release()
    def import_research(self,job,value):
        validate_interpretation(value)
        if value["source"]!=file_identity(self.source(job)):raise ValueError("import source identity does not match selected capture")
        return self.save_research(job,{"status":"IMPORTED_UNTRUSTED_INTERPRETATION","snapshot":value,"authorship_authenticated":False})
    def list_research(self,job):
        parent=self.path(job)/"research"
        if not parent.exists():return []
        return [read_json(p/"receipt.json")for p in sorted(parent.iterdir())if p.is_dir()and (p/"receipt.json").is_file()][:100]
    def interpretations(self,job,left,right):
        return [read_json(self.research_path(job,rid)/"interpretation.json")for rid in (left,right)]
    def export_bundle(self,job,left,right,include_raw):
        if include_raw is not True:raise ValueError("explicit acknowledgement required: bundle includes original captured bytes")
        a,b=self.interpretations(job,left,right);folder=self.path(job)/"exports";folder.mkdir(exist_ok=True);name=uuid.uuid4().hex+".zip"
        specs=[{"id":"independent-evidence-policy-v1","section":"docs/implementation/TRUST_ROOT.md","basis":"research_question","requirement":"Adjudicate this disagreement from exact captured bytes and applicable primary specifications. No implementation is presumed correct."}]
        proof=bundle.create(folder/name,self.source(job),a,b,specifications=specs)
        return {"name":name,"proof":proof,"contains_raw_capture":True}

class Server(ThreadingHTTPServer):
    daemon_threads=True
    allow_reuse_address=False
    def __init__(self,address,manager):
        self.manager=manager;self.token=secrets.token_urlsafe(32);self.requests_gate=threading.BoundedSemaphore(12)
        super().__init__(address,Handler)
    @property
    def origin(self):return "http://127.0.0.1:"+str(self.server_address[1])

class Handler(BaseHTTPRequestHandler):
    server_version="PCAPEvidenceLocal/1"
    def setup(self):
        super().setup();self.connection.settimeout(35)
    def log_message(self,*_):pass # No capture paths/tokens in HTTP access logs.
    def output(self,value,code=200,ctype="application/json"):
        raw=canonical(value)if ctype=="application/json"else value
        if len(raw)>8*1024*1024 and ctype!="application/zip":raise ValueError("response byte budget")
        self.send_response(code);self.send_header("Content-Type",ctype);self.send_header("Content-Length",str(len(raw)))
        self.send_header("Cache-Control","no-store");self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("Referrer-Policy","no-referrer")
        self.send_header("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers();self.wfile.write(raw)
    def do_GET(self):self.handle_request(False)
    def do_POST(self):self.handle_request(True)
    def handle_request(self,post):
        if not self.server.requests_gate.acquire(blocking=False):self.output({"error":"request concurrency budget"},429);return
        try:
            expected="127.0.0.1:"+str(self.server.server_address[1])
            if self.headers.get("Host")!=expected:raise PermissionError("invalid loopback Host")
            origin=self.headers.get("Origin")
            if origin and origin!=self.server.origin:raise PermissionError("cross-origin request rejected")
            path=urllib.parse.urlsplit(self.path).path
            if not path.startswith("/api/"):
                if post:raise ValueError("static endpoint is read-only")
                files={"/":"index.html","/app.js":"app.js","/model.mjs":"model.mjs","/style.css":"style.css"}
                if path not in files:raise ValueError("not found")
                name=files[path];raw=(WEB/name).read_bytes();self.output(raw,ctype={"html":"text/html; charset=utf-8","js":"text/javascript; charset=utf-8","mjs":"text/javascript; charset=utf-8","css":"text/css; charset=utf-8"}[name.rsplit(".",1)[1]]);return
            supplied=self.headers.get("Authorization","")
            if not secrets.compare_digest(supplied,"Bearer "+self.server.token):raise PermissionError("session authorization required")
            if post:
                if self.headers.get("Content-Type","").split(";")[0]!="application/json":raise ValueError("JSON request required")
                n=int(self.headers.get("Content-Length","0"))
                if not 0<n<=8*1024*1024:raise ValueError("request body budget")
                data=decode_json(self.rfile.read(n))
                if not isinstance(data,dict):raise ValueError("object request required")
            else:
                parsed=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query,strict_parsing=False,max_num_fields=20)
                if any(len(v)!=1 for v in parsed.values()):raise ValueError("duplicate query field")
                data={k:v[0]for k,v in parsed.items()}
            value=self.route(path,data,post)
            if value is not None:self.output(value)
        except PermissionError as e:self.output({"error":str(e)},403)
        except (ValueError,OSError,KeyError,sqlite3.Error)as e:self.output({"error":str(e)[:320]},400)
        finally:self.server.requests_gate.release()
    def route(self,path,d,post):
        m=self.server.manager
        if path=="/api/config":return {"engine_available":m.engine is not None,"tshark_available":m.tshark is not None,"modes":["container","rust"],"root_label":m.capture_root.name,"trust_model":"independent_engine_external_views_never_consensus"}
        if path=="/api/captures"and not post:return m.captures(d.get("after",""))
        if path=="/api/jobs"and not post:return {"jobs":m.jobs()}
        if path=="/api/start"and post:return m.start(d["capture"],d["mode"],d.get("profile","ics-full"))
        if path=="/api/catalog"and not post:return read_json(ROOT/"product/research/catalog.json")
        if path=="/api/audit"and not post:return cases.audit(ROOT)
        job=d.get("job");folder=m.path(job)
        if path=="/api/status"and not post:return m.status(job)
        if path=="/api/cancel"and post:return m.cancel(job)
        if path=="/api/overview"and not post:return store.overview(folder/"events.sqlite")
        if path=="/api/query"and not post:return store.query(folder/"events.sqlite",{k:v for k,v in d.items()if k!="job"})
        if path=="/api/event"and not post:return store.detail(folder/"events.sqlite",d["sequence"])
        if path=="/api/packet"and not post:return store.packet_bytes(folder/"events.sqlite",m.source(job),d["frame"],int(d.get("start","0")),int(d.get("count","256")))
        if path=="/api/reverse"and not post:return store.reverse(folder/"events.sqlite",d["frame"],int(d["start"]),int(d["end"]),d.get("after","0"))
        if path=="/api/timeline"and not post:return store.timeline(folder/"events.sqlite",d.get("after","0"))
        if path=="/api/research/list"and not post:return {"interpretations":m.list_research(job)}
        if path=="/api/research/run"and post:return m.run_research(job,d["adapter"])
        if path=="/api/research/import"and post:return m.import_research(job,d["interpretation"])
        if path=="/api/research/compare"and post:return compare_fields(*m.interpretations(job,d["left"],d["right"]))
        if path=="/api/research/export"and post:return m.export_bundle(job,d["left"],d["right"],d.get("include_raw_capture"))
        if path=="/api/research/download"and not post:
            name=d["name"]
            if not re.fullmatch(r"[0-9a-f]{32}\.zip",name):raise ValueError("invalid export ID")
            p=folder/"exports"/name
            if p.is_symlink()or p.stat().st_size>96*1024*1024:raise ValueError("export budget/path")
            # One bounded local artifact. JSON routes never serve arbitrary paths.
            self.output(p.read_bytes(),ctype="application/zip");return None
        raise ValueError("unknown API route or method")

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--capture-root",type=Path,required=True);p.add_argument("--workspace",type=Path,required=True);p.add_argument("--engine",type=Path);p.add_argument("--tshark",type=Path);p.add_argument("--port",type=int,default=0);p.add_argument("--disk-budget",type=int,default=10*1024**3);a=p.parse_args()
    if not 0<=a.port<=65535 or a.disk_budget<1024*1024:raise ValueError("invalid port/budget")
    m=Manager(a.capture_root,a.workspace,a.engine,a.tshark,a.disk_budget);server=Server(("127.0.0.1",a.port),m)
    print(server.origin+"/#token="+server.token,flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:m.close();server.server_close()
if __name__=="__main__":main()
