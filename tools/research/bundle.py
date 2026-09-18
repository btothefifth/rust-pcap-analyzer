"""Reproducible adjudication bundles: exact source + attributed views + witnesses.

Bundles are local, opt-in, potentially sensitive artifacts. No upload, report,
email, external tool execution, or automatic vulnerability claim is performed.
"""
from __future__ import annotations
import io
import json
import os
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from tools.product import comparison
from .contract import (InvalidResearch, canonical, decode_json, digest, file_identity,
                       compare_fields, MAX_DOCUMENT)

SCHEMA = "pcap-evidence.research-bundle.v1"
MAX_BUNDLE = 96 * 1024 * 1024
MAX_MEMBERS = 64


def _witnesses(source_bytes, report):
    first=report.get("first_semantic_divergence")
    if first is None:
        return {"status":"NO_OBSERVED_DIVERGENCE","packets":[],"notes":["Agreement does not establish correctness."]}
    frames=set()
    for side in ("left_evidence","right_evidence"):
        e=first.get(side,{})
        frames.update(e.get("frames",[]));frames.update(s["frame"] for s in e.get("spans",[]))
    if len(frames)>512:raise InvalidResearch("witness frame budget")
    packets=[];found=set()
    from tools.evidence.containers import Reader
    try:
        for record in Reader(io.BytesIO(source_bytes),evidence=True).records():
            p=record.packet
            if p is None or str(p.frame) not in frames:continue
            found.add(str(p.frame));ranges=[]
            for side in ("left_evidence","right_evidence"):
                for s in first.get(side,{}).get("spans",[]):
                    if s["frame"]!=str(p.frame):continue
                    a,b=int(s["start"]),int(s["end"])
                    if not 0<=a<b<=len(p.data):
                        raise InvalidResearch("comparison claims source span outside the captured packet")
                    ranges.append({"producer_side":side,"packet_start":str(a),"packet_end":str(b),
                                   "source_start":str(p.data_offset+a),"source_end":str(p.data_offset+b),
                                   "sha256":digest(p.data[a:b])})
            packets.append({"frame":str(p.frame),"record_offset":str(p.record_offset),
                            "data_offset":str(p.data_offset),"captured_length":str(len(p.data)),
                            "original_length":str(p.original_length),"sha256":digest(p.data),"ranges":ranges})
    except InvalidResearch:raise
    except (ValueError, EOFError, OSError) as e:
        # Malformed containers themselves are research targets. The full bytes
        # stay in the bundle; unparseable packet references never become verified.
        return {"status":"PARTIAL_CONTAINER_MAP","packets":packets,
                "unresolved_frames":sorted(frames-found,key=int),"reason":type(e).__name__,
                "raw_source_preserved":True}
    if frames-found:raise InvalidResearch("comparison references packets absent from the exact source")
    return {"status":"CHECKED_WITH_INDEPENDENT_CONTAINER_MAP","packets":packets,
            "interpretation_correctness_proven":False}


def _specs(specs):
    if not isinstance(specs,list) or len(specs)>64:raise InvalidResearch("specification reference budget")
    for item in specs:
        if not isinstance(item,dict) or not all(isinstance(item.get(k),str) and item[k] for k in ("id","section","requirement","basis")):
            raise InvalidResearch("specification id, section, requirement and basis required")
        if item["basis"] not in {"normative_specification","project_invariant","research_question"}:
            raise InvalidResearch("invalid specification authority category")
    return specs


def create(path, source, left, right, *, specifications, artifacts=None, case=None):
    destination=Path(path)
    if destination.exists():raise FileExistsError("bundle output already exists")
    identity=file_identity(source);data=Path(source).read_bytes()
    if {"sha256":digest(data),"bytes":str(len(data))}!=identity:raise InvalidResearch("source changed while bundling")
    report=compare_fields(left,right)
    if report["source"]!=identity:raise InvalidResearch("interpretations not bound to selected capture")
    witnesses=_witnesses(data,report)
    members={"source.capture":data,"left.interpretation.json":canonical(left)+b"\n",
             "right.interpretation.json":canonical(right)+b"\n","differential.json":canonical(report)+b"\n",
             "witnesses.json":canonical(witnesses)+b"\n","specifications.json":canonical(_specs(specifications))+b"\n",
             "README.md":b"# Parser differential research bundle\n\nPotentially sensitive original capture included. Do not publish without rights/privacy review.\nRun `python -m tools.research verify-bundle THIS.zip` from the integrated repository.\nDigest verification is not authenticity, semantic correctness, or proof of security impact.\nThe original capture, ordered observations, competing states and raw tool receipts remain separate.\nNo command from this archive is executed. Specification sources are references, never downloaded.\n"}
    if case is not None: members["case.json"]=canonical(case)+b"\n"
    for name,raw in (artifacts or {}).items():
        if not isinstance(name,str) or not name or len(name)>64 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for c in name):
            raise InvalidResearch("invalid tool artifact name")
        if not isinstance(raw,bytes) or len(raw)>MAX_DOCUMENT:raise InvalidResearch("tool artifact byte budget")
        members["artifacts/"+name]=raw
    if len(members)>MAX_MEMBERS-1 or sum(map(len,members.values()))>MAX_BUNDLE:raise InvalidResearch("bundle budget")
    manifest={"schema":SCHEMA,"source":identity,"contains_raw_capture":True,
              "first_divergence":report["first_semantic_divergence"],"adjudication":"UNRESOLVED",
              "canonical_engine_modified":False,"software_dependencies_are_not_independent_votes":True,
              "files":{name:{"bytes":len(raw),"sha256":digest(raw)} for name,raw in sorted(members.items())}}
    members["manifest.json"]=canonical(manifest)+b"\n"
    destination.parent.mkdir(parents=True,exist_ok=True)
    fd,temp=tempfile.mkstemp(prefix=".research-",dir=destination.parent)
    try:
        with os.fdopen(fd,"wb") as file:
            with zipfile.ZipFile(file,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
                for name,raw in sorted(members.items()):
                    entry=zipfile.ZipInfo(name,date_time=(2020,1,1,0,0,0));entry.compress_type=zipfile.ZIP_DEFLATED;entry.external_attr=0o100600<<16
                    z.writestr(entry,raw)
            file.flush();os.fsync(file.fileno())
        os.link(temp,destination)  # No-clobber publication on a trusted stable parent.
        return {"status":"CREATED","sha256":file_identity(destination,max_bytes=MAX_BUNDLE)["sha256"],
                "source":identity,"adjudication":"UNRESOLVED"}
    finally:
        try:os.unlink(temp)
        except FileNotFoundError:pass


def verify(path):
    if Path(path).stat().st_size>MAX_BUNDLE:raise InvalidResearch("bundle size limit")
    members={}
    with zipfile.ZipFile(path) as z:
        entries=z.infolist()
        if len(entries)>MAX_MEMBERS or sum(e.file_size for e in entries)>MAX_BUNDLE:
            raise InvalidResearch("expanded bundle limit")
        for e in entries:
            parts=PurePosixPath(e.filename).parts
            if e.filename in members or not parts or e.is_dir() or e.filename.startswith("/") or any(p in {".",".."} for p in parts) or "\\" in e.filename or ":" in e.filename or (e.external_attr>>16)&0o170000==0o120000:
                raise InvalidResearch("unsafe/duplicate bundle member")
            if e.file_size>32*1024*1024:raise InvalidResearch("bundle member size limit")
            members[e.filename]=z.read(e)
    manifest=decode_json(members.pop("manifest.json",b""))
    if manifest.get("schema")!=SCHEMA or set(manifest.get("files",{}))!=set(members):raise InvalidResearch("bundle inventory mismatch")
    for name,raw in members.items():
        if manifest["files"][name]!={"bytes":len(raw),"sha256":digest(raw)}:raise InvalidResearch("bundle content digest mismatch")
    source=members["source.capture"]
    identity={"sha256":digest(source),"bytes":str(len(source))}
    if manifest["source"]!=identity:raise InvalidResearch("bundle source mismatch")
    left=comparison.load(members["left.interpretation.json"]);right=comparison.load(members["right.interpretation.json"])
    report=compare_fields(left,right)
    if report["source"]!=identity or canonical(report)+b"\n"!=members["differential.json"]:raise InvalidResearch("recomputed divergence differs")
    if manifest.get("first_divergence")!=report["first_semantic_divergence"]:raise InvalidResearch("manifest divergence differs")
    if canonical(_witnesses(source,report))+b"\n"!=members["witnesses.json"]:raise InvalidResearch("recomputed source witnesses differ")
    _specs(decode_json(members["specifications.json"]))
    return {"schema":"pcap-evidence.research-bundle-verification.v1","status":"PASS",
            "source":identity,"recomputed_differential":True,"recomputed_source_witnesses":True,
            "semantic_correctness_proven":False,"authorship_authenticated":False,
            "security_impact":"not_established","adjudication":"UNRESOLVED"}
