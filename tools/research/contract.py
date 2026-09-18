"""Bounded research contracts and deterministic, source-anchored field comparison.

Equal outputs are agreement, not correctness. Missing adapter coverage is not a
negative observation. State changes remain different even when values match.
"""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from tools.product import comparison

LAYERS = comparison.LAYERS
MAX_DOCUMENT = 8 * 1024 * 1024
MAX_ROWS = 10000
SCHEMA = "pcap-evidence.research-observation.v1"

class InvalidResearch(ValueError):
    pass

def canonical(value):
    return comparison.canonical(value)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def read_json(path, limit=MAX_DOCUMENT):
    with Path(path).open("rb") as f:
        raw = f.read(limit + 1)
    return decode_json(raw, limit)

def decode_json(raw, limit=MAX_DOCUMENT):
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise InvalidResearch("research document byte budget")
    # Reject deep input before json.loads (not after exhausting its stack).
    depth = 0
    quoted = escaped = False
    for b in raw:
        if quoted:
            if escaped: escaped = False
            elif b == 92: escaped = True
            elif b == 34: quoted = False
        elif b == 34: quoted = True
        elif b in (91, 123):
            depth += 1
            if depth > 24: raise InvalidResearch("research document depth budget")
        elif b in (93, 125): depth -= 1
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out: raise InvalidResearch("duplicate JSON key")
            out[k] = v
        return out
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(InvalidResearch("nonfinite number")))
        comparison._tree(value)
    except (ValueError, RecursionError, UnicodeError) as e:
        raise InvalidResearch("invalid bounded research JSON") from e
    return value

def safe_file(root, relative, *, must_exist=True):
    root = Path(root).resolve(strict=True)
    if not isinstance(relative, str) or not relative or "\\" in relative or "\x00" in relative:
        raise InvalidResearch("invalid relative artifact path")
    p = Path(relative)
    if p.is_absolute() or any(x in ("", ".", "..") for x in relative.split("/")) or ":" in relative:
        raise InvalidResearch("artifact path must stay within selected root")
    current = root
    for part in p.parts:
        current = current / part
        if current.is_symlink(): raise InvalidResearch("symlink artifact rejected")
    if must_exist and not current.is_file(): raise InvalidResearch("artifact missing: " + relative)
    if not current.resolve(strict=must_exist).is_relative_to(root): raise InvalidResearch("artifact escapes root")
    return current

def file_identity(path, max_bytes=32 * 1024 * 1024):
    total = 0
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        while chunk := f.read(65536):
            total += len(chunk)
            if total > max_bytes: raise InvalidResearch("research input byte budget")
            h.update(chunk)
    return {"sha256": h.hexdigest(), "bytes": str(total)}

def snapshot(producer, source, observations, coverage=None, *, notes=()):
    value = {"schema": comparison.SCHEMA, "normalization": comparison.NORMALIZATION,
             "producer": producer, "source": source,
             "coverage": coverage or {layer: "partial" if any(r["layer"] == layer for r in observations) else "not_collected" for layer in LAYERS},
             "observations": observations, "notes": list(notes)}
    return comparison.validate(value)

def observation(layer, key, value, *, status="observed", frames=(), spans=(), events=(), notes=()):
    return {"layer": layer, "key": key, "status": status, "value": value,
            "evidence": {"frames": [str(x) for x in frames], "spans": list(spans),
                         "events": [str(x) for x in events], "notes": list(notes)}}

def _flatten(value, prefix="", output=None):
    """Arrays stay ordered values. Never sort away duplicates or alternatives."""
    out = {} if output is None else output
    for k, v in value.items():
        path = prefix + "/" + k.replace("~", "~0").replace("/", "~1")
        if isinstance(v, dict) and v:
            _flatten(v, path, out)
        else:
            out[path] = v
    return out

def _anchor_order(key):
    # Source-frame anchors are numeric, never lexicographic (frame:10 vs frame:2).
    match = re.match(r"frame:([0-9]+)(?:;|$)", key)
    return (0, int(match[1]), key) if match else (1, 0, key)

def compare_fields(left, right, *, maximum=10000):
    comparison.validate(left); comparison.validate(right)
    if left["source"] != right["source"]: raise InvalidResearch("comparison source identity mismatch")
    if not 1 <= maximum <= MAX_ROWS: raise InvalidResearch("comparison row budget")
    a = {(r["layer"], r["key"]): r for r in left["observations"]}
    b = {(r["layer"], r["key"]): r for r in right["observations"]}
    rows, first, prior_unknown = [], None, []
    summaries = []
    for layer in LAYERS:
        counts = {"same": 0, "different": 0, "not_comparable": 0}
        keys = sorted({k for l, k in a.keys() | b.keys() if l == layer}, key=_anchor_order)
        if not keys or left["coverage"][layer] != "complete" or right["coverage"][layer] != "complete":
            prior_unknown.append(layer)
        for key in keys:
            l, r = a.get((layer, key)), b.get((layer, key))
            def add(field, outcome, reason, lv, rv):
                nonlocal first
                if len(rows) >= maximum: raise InvalidResearch("comparison field budget exceeded; narrow the research case")
                row = {"layer": layer, "key": key, "field": field, "result": outcome,
                       "reason": reason, "left": lv, "right": rv,
                       "left_evidence": {} if l is None else l.get("evidence", {}),
                       "right_evidence": {} if r is None else r.get("evidence", {})}
                counts[outcome] += 1
                if first is None and outcome == "different":
                    earlier = [p for p in prior_unknown if LAYERS.index(p) < LAYERS.index(layer)]
                    first = {**row, "row": len(rows), "earlier_unresolved_layers": earlier,
                             "earliest_within_declared_coverage": not earlier,
                             "scope": "observed_witnesses_not_complete_endpoint_execution",
                             "security_impact": "not_established", "correct_implementation": None}
                rows.append(row)
            if l is None or r is None:
                complete = left["coverage"][layer] == right["coverage"][layer] == "complete"
                add("/", "different" if complete else "not_comparable", "missing_observation" if complete else "coverage_gap", l, r)
                if not complete and layer not in prior_unknown: prior_unknown.append(layer)
                continue
            if l["status"] in {"opaque", "unsupported"} or r["status"] in {"opaque", "unsupported"}:
                add("/status", "not_comparable", "unsupported_semantics", l["status"], r["status"])
                if layer not in prior_unknown: prior_unknown.append(layer)
                continue
            if l["status"] != r["status"]:
                add("/status", "different", "uncertainty_or_acceptance_differs", l["status"], r["status"])
            lf, rf = _flatten(l["value"]), _flatten(r["value"])
            for field in sorted(lf.keys() | rf.keys()):
                if field not in lf or field not in rf:
                    add(field, "not_comparable", "field_not_normalized_by_both_adapters", lf.get(field), rf.get(field))
                    if layer not in prior_unknown: prior_unknown.append(layer)
                else:
                    same = canonical(lf[field]) == canonical(rf[field])
                    add(field, "same" if same else "different", "agreement_not_proof" if same else "normalized_value_differs", lf[field], rf[field])
        summaries.append({"layer": layer, **counts, "left_coverage": left["coverage"][layer], "right_coverage": right["coverage"][layer]})
    return {"schema": "pcap-evidence.research-differential.v1", "source": left["source"],
            "producers": [left["producer"], right["producer"]], "layers": summaries, "rows": rows,
            "first_semantic_divergence": first, "consensus_used": False,
            "comparison_changes_canonical_evidence": False,
            "policy": "primary_specification_and_raw_witness_adjudication_required"}

def json_pointer(value, pointer):
    if pointer == "": return value
    if not isinstance(pointer, str) or not pointer.startswith("/"): raise InvalidResearch("invalid assertion pointer")
    try:
        for part in pointer[1:].split("/"):
            k = part.replace("~1", "/").replace("~0", "~")
            value = value[int(k)] if isinstance(value, list) and k.isdecimal() else value[k]
        return value
    except (IndexError, KeyError, TypeError, ValueError):
        raise InvalidResearch("assertion field not covered: " + pointer) from None

def assertions(value, rules):
    if not isinstance(rules, list) or len(rules) > 128: raise InvalidResearch("assertion budget")
    results = []
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("op") not in {"equals", "one_of", "absent"}:
            raise InvalidResearch("unsupported assertion operator")
        try: actual = json_pointer(value, rule["path"]); exists = True
        except InvalidResearch: actual, exists = None, False
        if rule["op"] == "absent": ok = not exists
        elif not exists:
            results.append({"path": rule["path"], "status": "NOT_COVERED", "actual": None}); continue
        elif rule["op"] == "equals": ok = canonical(actual) == canonical(rule.get("value"))
        else: ok = any(canonical(actual) == canonical(v) for v in rule.get("values", []))
        results.append({"path": rule["path"], "status": "PASS" if ok else "MISMATCH",
                        "actual": actual, "basis": rule.get("basis", "explicit_project_invariant")})
    return results
