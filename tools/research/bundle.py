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
from . import bgp_compare
from .contract import (InvalidResearch, canonical, decode_json, digest, file_identity,
                       compare_fields, recompute_differential, MAX_DOCUMENT)

SCHEMA = "pcap-evidence.research-bundle.v1"
BGP_SCHEMA = "pcap-evidence.bgp.research-bundle.v1"
MAX_BUNDLE = 96 * 1024 * 1024
MAX_MEMBERS = 64
MAX_MEMBER = 32 * 1024 * 1024


def _mode(left, right):
    """Exact BGP schemas select their owner; mixed families never fall through."""
    if type(left) is not dict or type(right) is not dict:
        raise InvalidResearch("bundle interpretations must be objects")
    schemas = (left.get("schema"), right.get("schema"))
    if any(type(schema) is not str for schema in schemas):
        raise InvalidResearch("bundle interpretation schema must be text")
    bgp_schemas = {bgp_compare.SCHEMA, bgp_compare.SCHEMA_V2}
    if any(schema in bgp_schemas for schema in schemas):
        if schemas[0] != schemas[1] or schemas[0] not in bgp_schemas:
            raise InvalidResearch("bundle interpretation schema mismatch")
        return "bgp"
    return "capture"


def _bgp_first(report):
    index = report["first_observed_disagreement"]
    return None if index is None else {"index": index, "row": report["rows"][index]}


def _bgp_witnesses(source, report):
    """Check producer-declared ranges against bytes, without parsing records."""
    first = _bgp_first(report)
    ranges = []
    if first is not None:
        for side in ("left", "right"):
            span = first["row"][side + "_source_range"]
            if span is None:
                continue
            start, end = int(span["start"]), int(span["end"])
            if not 0 <= start < end <= len(source):
                raise InvalidResearch("BGP witness outside exact source")
            ranges.append({"producer_side": side, "record_offset": first["row"]["record_offset"],
                           "source_start": str(start), "source_end": str(end),
                           "sha256": digest(source[start:end])})
    return {"status": "CHECKED_DECLARED_RAW_RANGES" if first is not None else "NO_OBSERVED_DIVERGENCE",
            "ranges": ranges, "independent_record_mapping": False,
            "interpretation_correctness_proven": False,
            "notes": ["Ranges are producer-declared byte anchors; no parsed-record mapping is established.",
                      "Agreement does not establish correctness."]}


def _member_identity(raw):
    return {"bytes": len(raw), "sha256": digest(raw)}


def _bgp_dataset(left, right, report, members):
    """A recomputable provenance projection inside the existing manifest."""
    sides = {}
    for side, document in (("left", left), ("right", right)):
        native = document.get("native_evidence")
        sides[side] = {"interpretation": _member_identity(members[side + ".interpretation.json"]),
                       "schema": document["schema"], "producer": document["producer"],
                       "native_partition": document.get("native_partition"),
                       "native_coverage_verification": document.get("native_coverage_verification"),
                       "native_evidence": None if native is None else {
                           "manifest_sha256": digest(canonical(native)),
                           "semantic_identity": native.get("semantic_identity"),
                           "semantic_profile": native.get("semantic_profile"),
                           "sequence": native.get("sequence"), "window": native.get("window")}}
    return {"source": report["source"], "normalization": report["normalization"],
            "differential": _member_identity(members["differential.json"]),
            "interpretations": sides, "source_authenticated": False,
            "semantic_correctness_proven": False, "independent_record_mapping": False}


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
    mode=_mode(left,right)
    identity=file_identity(source,max_bytes=MAX_MEMBER)
    with Path(source).open("rb") as stream:data=stream.read(MAX_MEMBER+1)
    if len(data)>MAX_MEMBER:raise InvalidResearch("bundle source size limit")
    if {"sha256":digest(data),"bytes":str(len(data))}!=identity:raise InvalidResearch("source changed while bundling")
    report=bgp_compare.compare(left,right) if mode=="bgp" else compare_fields(left,right)
    if report["source"]!=identity:raise InvalidResearch("interpretations not bound to selected capture")
    witnesses=_bgp_witnesses(data,report) if mode=="bgp" else _witnesses(data,report)
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
              "first_divergence":_bgp_first(report) if mode=="bgp" else report["first_semantic_divergence"],"adjudication":"UNRESOLVED",
              "canonical_engine_modified":False,"software_dependencies_are_not_independent_votes":True,
              "files":{name:{"bytes":len(raw),"sha256":digest(raw)} for name,raw in sorted(members.items())}}
    if mode=="bgp":
        manifest["schema"]=BGP_SCHEMA
        manifest["derived_dataset"]=_bgp_dataset(left,right,report,members)
    members["manifest.json"]=canonical(manifest)+b"\n"
    # Verification charges the manifest and every expanded member. Creation
    # must admit the same final representation before any publication.
    if sum(map(len,members.values()))>MAX_BUNDLE:raise InvalidResearch("expanded bundle limit")
    if any(len(raw)>MAX_MEMBER for raw in members.values()):raise InvalidResearch("bundle member size limit")
    # Every JSON consumer below uses the bounded document decoder. Admit the
    # exact newline-bearing representation, including the provenance manifest.
    if any(len(members[name])>MAX_DOCUMENT for name in ("manifest.json","left.interpretation.json",
            "right.interpretation.json","differential.json","witnesses.json","specifications.json")):
        raise InvalidResearch("bundle document byte budget")
    destination.parent.mkdir(parents=True,exist_ok=True)
    fd,temp=tempfile.mkstemp(prefix=".research-",dir=destination.parent)
    try:
        with os.fdopen(fd,"wb") as file:
            with zipfile.ZipFile(file,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
                for name,raw in sorted(members.items()):
                    entry=zipfile.ZipInfo(name,date_time=(2020,1,1,0,0,0));entry.compress_type=zipfile.ZIP_DEFLATED;entry.external_attr=0o100600<<16
                    z.writestr(entry,raw)
            file.flush();os.fsync(file.fileno())
            if os.fstat(file.fileno()).st_size>MAX_BUNDLE:raise InvalidResearch("bundle size limit")
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
            if e.file_size>MAX_MEMBER:raise InvalidResearch("bundle member size limit")
            members[e.filename]=z.read(e)
    manifest=decode_json(members.pop("manifest.json",b""))
    if (type(manifest) is not dict or type(manifest.get("schema")) is not str
            or type(manifest.get("files")) is not dict):
        raise InvalidResearch("invalid bundle manifest")
    if manifest.get("schema") not in {SCHEMA,BGP_SCHEMA} or set(manifest.get("files",{}))!=set(members):raise InvalidResearch("bundle inventory mismatch")
    for name,raw in members.items():
        if manifest["files"][name]!={"bytes":len(raw),"sha256":digest(raw)}:raise InvalidResearch("bundle content digest mismatch")
    source=members["source.capture"]
    identity={"sha256":digest(source),"bytes":str(len(source))}
    if manifest["source"]!=identity:raise InvalidResearch("bundle source mismatch")
    if manifest["schema"]==BGP_SCHEMA:
        return _verify_bgp(manifest,members,source,identity)
    if "derived_dataset" in manifest:raise InvalidResearch("mixed bundle mode")
    left=comparison.load(members["left.interpretation.json"]);right=comparison.load(members["right.interpretation.json"])
    recorded=decode_json(members["differential.json"])
    report=recompute_differential(left,right,recorded.get("schema"))
    if report["source"]!=identity or canonical(report)+b"\n"!=members["differential.json"]:raise InvalidResearch("recomputed divergence differs")
    if manifest.get("first_divergence")!=report["first_semantic_divergence"]:raise InvalidResearch("manifest divergence differs")
    if canonical(_witnesses(source,report))+b"\n"!=members["witnesses.json"]:raise InvalidResearch("recomputed source witnesses differ")
    _specs(decode_json(members["specifications.json"]))
    return {"schema":"pcap-evidence.research-bundle-verification.v1","status":"PASS",
            "source":identity,"recomputed_differential":True,"recomputed_source_witnesses":True,
            "semantic_correctness_proven":False,"authorship_authenticated":False,
            "security_impact":"not_established","adjudication":"UNRESOLVED"}


def _verify_bgp(manifest, members, source, identity):
    keys={"schema","source","contains_raw_capture","first_divergence","adjudication",
          "canonical_engine_modified","software_dependencies_are_not_independent_votes","files","derived_dataset"}
    if (set(manifest)!=keys or manifest["contains_raw_capture"] is not True
            or manifest["adjudication"]!="UNRESOLVED" or manifest["canonical_engine_modified"] is not False
            or manifest["software_dependencies_are_not_independent_votes"] is not True):
        raise InvalidResearch("invalid BGP bundle claims")
    left=decode_json(members["left.interpretation.json"])
    right=decode_json(members["right.interpretation.json"])
    if _mode(left,right)!="bgp":raise InvalidResearch("mixed bundle mode")
    report=bgp_compare.compare(left,right)
    if report["source"]!=identity or canonical(report)+b"\n"!=members["differential.json"]:
        raise InvalidResearch("recomputed divergence differs")
    if canonical(manifest["first_divergence"])!=canonical(_bgp_first(report)):
        raise InvalidResearch("manifest divergence differs")
    if canonical(manifest["derived_dataset"])!=canonical(_bgp_dataset(left,right,report,members)):
        raise InvalidResearch("recomputed derived dataset differs")
    if canonical(_bgp_witnesses(source,report))+b"\n"!=members["witnesses.json"]:
        raise InvalidResearch("recomputed source witnesses differ")
    _specs(decode_json(members["specifications.json"]))
    return {"schema":"pcap-evidence.bgp.research-bundle-verification.v1","status":"PASS",
            "source":identity,"recomputed_differential":True,"recomputed_source_witnesses":True,
            "recomputed_derived_dataset":True,"independent_record_mapping":False,
            "semantic_correctness_proven":False,"authorship_authenticated":False,
            "security_impact":"not_established","adjudication":"UNRESOLVED"}
