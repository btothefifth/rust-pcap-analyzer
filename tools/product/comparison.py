"""Strict normalized interpretation envelope. No parser output is authoritative.

Fields may be absent because an adapter does not cover them. Every imported
interpretation is attributed and source-bound, and cannot mutate core evidence.
"""
from __future__ import annotations
import json
import math
import re

SCHEMA = "pcap-evidence.interpretation.v1"
NORMALIZATION = "source-anchored-fields-v1"
LAYERS = ("capture_record", "packet_bytes", "timestamp", "link_layer", "network_layer",
          "fragment_set", "transport_identity", "tcp_reconstruction", "stream_bytes",
          "protocol_detection", "protocol_message", "transaction", "higher_order")
STATES = {"observed", "candidate", "ambiguous", "incomplete", "unsupported", "rejected", "opaque"}
MAX_BYTES = 8 * 1024 * 1024

def _tree(value):
    nodes = 0
    def walk(v, depth):
        nonlocal nodes
        nodes += 1
        if nodes > 200000 or depth > 24: raise ValueError("JSON tree budget")
        if v is None or type(v) is bool: return
        if type(v) is int:
            if not -(1 << 127) <= v < (1 << 128): raise ValueError("integer range")
        elif type(v) is float:
            if not math.isfinite(v): raise ValueError("nonfinite JSON number")
        elif type(v) is str:
            if len(v) > 65536: raise ValueError("string budget")
        elif type(v) is list:
            if len(v) > 10000: raise ValueError("array budget")
            for x in v: walk(x, depth + 1)
        elif type(v) is dict:
            if len(v) > 4096: raise ValueError("object budget")
            for k, x in v.items():
                if type(k) is not str or not k or len(k)>1024: raise ValueError("invalid key")
                walk(x, depth + 1)
        else: raise ValueError("noncanonical JSON type")
    walk(value, 0)

def canonical(value):
    _tree(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")

def _decimal(v, positive=False):
    if type(v) is not str or not re.fullmatch(r"0|[1-9][0-9]{0,19}",v): raise ValueError("decimal identity required")
    n = int(v)
    if n >= 1 << 64 or positive and not n: raise ValueError("identity outside u64")
    return n

def validate(v):
    _tree(v)
    if not isinstance(v,dict) or v.get("schema")!=SCHEMA or v.get("normalization")!=NORMALIZATION:
        raise ValueError("unsupported interpretation schema/normalizer")
    source=v.get("source",{})
    if set(source)!={"sha256","bytes"} or not re.fullmatch(r"[0-9a-f]{64}",source.get("sha256","")):
        raise ValueError("source identity required")
    _decimal(source["bytes"])
    p=v.get("producer",{})
    if not isinstance(p,dict) or any(not isinstance(p.get(k),str) or not 1<=len(p[k])<=128 for k in ("id","version","origin")):
        raise ValueError("explicit producer identity required")
    if p["origin"] not in {"independent_engine","independent_fixture","external_tool","manual_research"}:
        raise ValueError("unsupported producer origin")
    if not re.fullmatch(r"[0-9a-f]{64}",p.get("config_sha256","")): raise ValueError("producer config hash required")
    if not isinstance(p.get("command"),list) or not isinstance(p.get("dependencies"),list): raise ValueError("producer provenance required")
    coverage=v.get("coverage")
    if not isinstance(coverage,dict) or set(coverage)!=set(LAYERS) or any(x not in {"complete","partial","not_collected","unsupported"} for x in coverage.values()):
        raise ValueError("explicit all-layer adapter coverage required")
    rows=v.get("observations")
    if not isinstance(rows,list) or len(rows)>10000: raise ValueError("observation budget")
    seen=set()
    for row in rows:
        if not isinstance(row,dict) or row.get("layer") not in LAYERS or row.get("status") not in STATES:
            raise ValueError("invalid observation layer/state")
        key=row.get("key")
        if not isinstance(key,str) or not 1<=len(key)<=1024: raise ValueError("source anchor required")
        identity=row["layer"],key
        if identity in seen: raise ValueError("duplicate observation anchor; represent alternatives in an ordered value")
        seen.add(identity)
        if not isinstance(row.get("value"),dict): raise ValueError("observation value must be an object")
        e=row.get("evidence",{})
        if not isinstance(e,dict): raise ValueError("invalid witness object")
        for field in ("frames","events"):
            a=e.get(field,[])
            if not isinstance(a,list) or len(a)>512: raise ValueError("witness identity budget")
            for n in a:_decimal(n,True)
        spans=e.get("spans",[])
        if not isinstance(spans,list) or len(spans)>1024: raise ValueError("span budget")
        for s in spans:
            if not isinstance(s,dict) or set(s)!={"frame","start","end"}: raise ValueError("packet-relative span shape")
            _decimal(s["frame"],True)
            if _decimal(s["start"])>=_decimal(s["end"]): raise ValueError("nonempty half-open span required")
    if len(canonical(v))>MAX_BYTES: raise ValueError("interpretation byte budget")
    return v

def load(raw):
    from tools.research.contract import decode_json
    return validate(decode_json(raw))
