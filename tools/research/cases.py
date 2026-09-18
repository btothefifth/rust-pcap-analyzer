"""Case/specification ledger and native known-answer execution.

The ledger is evidence of maintenance, not evidence of successful qualification.
A broad protocol label never closes missing adapter or normative-review gates.
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from .contract import (InvalidResearch, read_json, safe_file, file_identity, assertions,
                       decode_json, canonical, digest)
from .adapters import execute

CATALOG = "product/research/catalog.json"
REQUIRED = ("conformance", "adversarial", "properties", "fuzz", "differential")

def audit(root, *, required_families=None):
    root=Path(root).resolve();catalog=read_json(root/CATALOG)
    if catalog.get("schema")!="pcap-evidence.research-catalog.v1":raise InvalidResearch("unsupported research catalog")
    cases=catalog.get("cases",[]);families=catalog.get("families",[])
    if not isinstance(cases,list) or len(cases)>2048 or not isinstance(families,list) or len(families)>256:
        raise InvalidResearch("research catalog size budget")
    ids={};findings=[];coverage=[]
    for case in cases:
        if not re.fullmatch(r"[a-z0-9_.-]{1,100}",case.get("id","")) or case["id"] in ids:
            raise InvalidResearch("invalid/duplicate research case ID")
        ids[case["id"]]=case
        for key in ("payload","capture"):
            if case.get(key):
                p=safe_file(root,case[key]["path"])
                if file_identity(p)!=case[key]["identity"]: findings.append({"case":case["id"],"gap":"fixture_identity"})
        if not case.get("specifications") or not case.get("rationale"):
            findings.append({"case":case["id"],"gap":"specification_or_rationale"})
        for ref in case.get("specifications",[]):
            if ref not in catalog.get("specifications",{}):findings.append({"case":case["id"],"gap":"unknown_specification"})
        if case.get("kind") not in {"conformance","adversarial","ambiguity"}:
            findings.append({"case":case["id"],"gap":"case_kind"})
    names=set()
    for family in families:
        name=family.get("id")
        if not isinstance(name,str) or name in names:raise InvalidResearch("duplicate/invalid family")
        names.add(name);gaps=[]
        for component in REQUIRED:
            witnesses=family.get(component,[])
            if not witnesses:gaps.append(component)
            if component in {"conformance","adversarial"}:
                for case_id in witnesses:
                    if case_id not in ids or ids[case_id]["family"]!=name:
                        findings.append({"family":name,"gap":"invalid_case_reference","case":case_id})
            elif component in {"properties","fuzz"}:
                for witness in witnesses:
                    p=safe_file(root,witness["path"])
                    if witness.get("selector") and witness["selector"] not in p.read_text("utf-8"):
                        findings.append({"family":name,"gap":"test_selector_missing"})
        if family.get("normative_review")!="reviewed":gaps.append("normative_review")
        if not any(x.get("status")=="semantic_adapter_implemented" for x in family.get("differential",[])):
            gaps.append("protocol_specific_differential_adapter")
        # Receipts require exact source/command/binary identities; registry entries
        # alone cannot claim any native test, fuzz campaign or external run passed.
        if not family.get("qualification_receipts"):gaps.append("executed_qualification")
        coverage.append({"family":name,"layer":family.get("layer"),"maintenance_components":{k:bool(family.get(k)) for k in REQUIRED},
                         "gaps":gaps,"qualification":"BLOCKED" if gaps else "REVIEW_REQUIRED"})
    if required_families:
        for name in sorted(set(required_families)-names):findings.append({"family":name,"gap":"advertised_family_not_registered"})
    return {"schema":"pcap-evidence.research-coverage.v1","maintenance_status":"FAIL" if findings else "PASS",
            "qualification_status":"BLOCKED","case_count":len(cases),"family_count":len(families),
            "findings":findings,"families":coverage,
            "note":"Source case/adapter registration is not executed conformance, completeness, or security proof."}

def select(root, case_id):
    catalog=read_json(Path(root)/CATALOG)
    for case in catalog["cases"]:
        if case["id"]==case_id:return case,catalog
    raise InvalidResearch("unknown case ID")

def run_probe_case(root, case, binary, *, timeout=10):
    payload=case.get("payload")
    if not payload or not case.get("native_protocol"):
        return {"case":case["id"],"status":"BLOCKED","reason":"case needs capture/state adapter, not the payload decoder adapter"}
    path=safe_file(root,payload["path"])
    if file_identity(path)!=payload["identity"]:raise InvalidResearch("case payload identity mismatch")
    if binary is None:return {"case":case["id"],"status":"BLOCKED","reason":"native probe executable not supplied"}
    binary=Path(binary).resolve(strict=False)
    result=execute([str(binary),case["native_protocol"],str(path)],timeout=timeout,output_limit=2*1024*1024)
    if result.status!="PASS":
        return {"case":case["id"],"status":result.status,"returncode":result.returncode,
                "stdout_sha256":digest(result.stdout),"stderr_sha256":digest(result.stderr)}
    output=decode_json(result.stdout)
    if output.get("schema")!="pcap-evidence.research-probe.v1" or output.get("protocol")!=case["native_protocol"] or output.get("payload_sha256")!=payload["identity"]["sha256"]:
        raise InvalidResearch("native probe output identity/schema mismatch")
    if output.get("compiled") is not True:return {"case":case["id"],"status":"BLOCKED","reason":"decoder not compiled"}
    rules=case.get("assertions",[])
    checks=assertions(output,rules)
    status="MISMATCH" if any(c["status"]=="MISMATCH" for c in checks) else "NOT_COVERED" if not checks or any(c["status"]=="NOT_COVERED" for c in checks) else "PASS"
    return {"case":case["id"],"status":status,"checks":checks,"source":payload["identity"],
            "binary_sha256":file_identity(binary,512*1024*1024)["sha256"],"command":["<configured-probe>",case["native_protocol"],"<hash-pinned-payload>"],
            "observation":output,"basis":"explicit_fixture_invariants_not_another_parser_output",
            "security_impact":"not_established"}
