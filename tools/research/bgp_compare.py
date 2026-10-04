"""Bounded, attributed BGP interpretation comparison for offline research.

Imported command arrays are inert provenance. Agreement neither establishes
correctness nor admits a route into canonical state. The normalization config
hash identifies common semantic options, not the adapter executable.
"""
from __future__ import annotations

import argparse
import copy
import json
import re
from pathlib import Path

from .contract import MAX_DOCUMENT, MAX_ROWS, InvalidResearch, canonical, decode_json, digest, read_json

SCHEMA = "pcap-evidence.bgp.interpretation.v1"
DIFFERENTIAL_SCHEMA = "pcap-evidence.bgp.differential.v1"
NORMALIZATION = "bgp-source-fields-v1"
GROUPS = ("disposition", "framing", "message", "attributes", "nlri", "validation")
COVERAGE = {"complete", "partial", "unsupported", "not_collected"}
DISPOSITIONS = {"accepted", "rejected", "incomplete", "unknown", "unsupported"}
FIELD_STATES = {"observed", "unknown", "incomplete", "unsupported"}
NATIVE_PROFILE = "pcap-evidence.bgp.semantic-route-identity.v2"
ENTRY_KEYS = ("ordinal", "source_id", "checkpoint_id", "source_sha256", "source_bytes", "record_count",
              "final_chain", "store_seal", "predecessor_digest")
COVERAGE_KEYS = ("records", "rows", "observations", "route_free", "opaque", "rejected", "unsupported",
                 "unknown_time", "unknown_mrt_record_time", "unknown_asn", "selected", "timestamp_regressions", "witnesses",
                 "witnesses_truncated", "count_unit")
MANIFEST_KEYS = ("schema", "complete", "rows", "rows_bytes", "rows_sha256", "rows_digest_scope", "sequence",
                 "semantic_profile", "replay_relationship", "window", "coverage", "source_authenticated",
                 "endpoint_state_claimed", "resume_cursor_supported")


def _compact(value):
    """Rust Json wire identity uses prescribed insertion order, never sorted keys."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _domain_hash(domain, raw):
    return digest(domain.encode("ascii") + b"\x00" + raw)


def _ordered(value, keys, label):
    _keys(value, keys, label=label)
    return {key: value[key] for key in keys}


def _native_manifest_payload(manifest):
    """Reconstruct every ordered native DTO, including canonical sidecars."""
    payload = {key: manifest[key] for key in MANIFEST_KEYS}
    sequence = manifest["sequence"]
    payload["sequence"] = {key: sequence[key] for key in ("schema", "ordering", "independent_checkpoints", "entries", "sequence_digest")}
    payload["sequence"]["entries"] = [{**{key: entry[key] for key in ENTRY_KEYS}, "entry_digest": entry["entry_digest"]}
                                       for entry in sequence["entries"]]
    coverage = _ordered(manifest["coverage"], COVERAGE_KEYS, "native coverage")
    if type(coverage["witnesses"]) is not list or len(coverage["witnesses"]) > 4096:
        raise InvalidResearch("native coverage witness budget")
    witness_keys = ("sequence_ordinal", "source_sha256", "record_ordinal", "record_offset", "record_sha256", "entry_index", "reason")
    coverage["witnesses"] = [_ordered(witness, witness_keys, "coverage witness") for witness in coverage["witnesses"]]
    payload["coverage"] = coverage
    window = manifest["window"]
    if window is not None:
        window_keys = ("time_basis", "clock_scope", "clock_scope_semantics", "start_ns", "end_ns", "interval", "certain_occurrence_time_claimed", "asn")
        window = _ordered(window, window_keys, "native window")
        if window["asn"] is not None:
            window["asn"] = _ordered(window["asn"], ("number", "role"), "window ASN")
        payload["window"] = window
    return payload


def _keys(value, required, optional=(), label="object"):
    if type(value) is not dict or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise InvalidResearch("invalid " + label + " keys")


def _uint(value, label="anchor"):
    if type(value) is int:
        number = value
    elif type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
        number = int(value)
    else:
        raise InvalidResearch(label + " must be an exact unsigned integer")
    if not 0 <= number < 1 << 64:
        raise InvalidResearch(label + " outside u64")
    return number


def _hash(value, label):
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise InvalidResearch(label + " must be lowercase sha256")
    return value


def _signed(value, label):
    if type(value) is int:
        number = value
    elif type(value) is str and re.fullmatch(r"0|-?[1-9][0-9]{0,38}", value):
        number = int(value)
    else:
        raise InvalidResearch(label + " must be an exact signed integer")
    if not -(1 << 127) <= number < 1 << 127:
        raise InvalidResearch(label + " outside i128")
    return number


def _text(value, label, maximum=128):
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise InvalidResearch("explicit " + label + " required")
    return value


def validate(value):
    """Return a detached normalized document; integer anchors become decimals.

    Unknown group names are preserved as research data, never compared. Each
    field has its own uncertainty tag, independent of the group's coverage.
    Semantic field values are exact JSON: numeric strings are not coerced.
    """
    if len(canonical(value)) > MAX_DOCUMENT:
        raise InvalidResearch("BGP interpretation byte budget")
    _keys(value, ("schema", "source", "normalization", "producer", "observations"), ("native_evidence",), "interpretation")
    if value["schema"] != SCHEMA:
        raise InvalidResearch("unsupported BGP interpretation schema")
    out = copy.deepcopy(value)
    source = out["source"]
    _keys(source, ("sha256", "bytes"), label="source")
    _hash(source["sha256"], "source digest")
    length = _uint(source["bytes"], "source length")
    source["bytes"] = str(length)
    normalization = out["normalization"]
    _keys(normalization, ("profile", "config_sha256"), label="normalization")
    if normalization["profile"] != NORMALIZATION:
        raise InvalidResearch("unsupported BGP normalization profile")
    _hash(normalization["config_sha256"], "normalization config")
    producer = out["producer"]
    _keys(producer, ("id", "version", "adapter_version", "origin", "command"), label="producer")
    for key in ("id", "version", "adapter_version"):
        _text(producer[key], "producer " + key)
    if type(producer["origin"]) is not str or producer["origin"] not in {"native_evidence", "external_tool", "independent_fixture", "manual_research"}:
        raise InvalidResearch("unsupported producer origin")
    command = producer["command"]
    if type(command) is not list or len(command) > 128 or any(type(x) is not str or len(x) > 4096 for x in command):
        raise InvalidResearch("inert command metadata budget")
    rows = out["observations"]
    if type(rows) is not list or len(rows) > MAX_ROWS:
        raise InvalidResearch("BGP observation budget")
    seen = set()
    for row in rows:
        _keys(row, ("record_offset", "source_range", "disposition", "coverage", "fields"), ("entry_index", "evidence"), "observation")
        offset = _uint(row["record_offset"], "record offset")
        row["record_offset"] = str(offset)
        entry = row.get("entry_index")
        if entry is not None:
            entry = _uint(entry, "entry index")
            row["entry_index"] = str(entry)
        else:
            row.pop("entry_index", None)
        identity = offset, entry
        if identity in seen:
            raise InvalidResearch("duplicate BGP source anchor")
        seen.add(identity)
        span = row["source_range"]
        _keys(span, ("kind", "start", "end"), label="source range")
        start, end = _uint(span["start"]), _uint(span["end"])
        if span["kind"] != "source_range" or start != offset or not start < end <= length:
            raise InvalidResearch("record source range outside exact source or wrong anchor")
        span.update(start=str(start), end=str(end))
        if type(row["disposition"]) is not str or row["disposition"] not in DISPOSITIONS:
            raise InvalidResearch("invalid BGP disposition")
        coverage, fields = row["coverage"], row["fields"]
        if type(coverage) is not dict or any(type(x) is not str or x not in COVERAGE for x in coverage.values()):
            raise InvalidResearch("invalid field-group coverage")
        if type(fields) is not dict or len(fields) > 64 or len(coverage) > 64:
            raise InvalidResearch("field-group budget")
        for group in coverage:
            _text(group, "coverage group")
        if fields.get("disposition"):
            raise InvalidResearch("disposition belongs in its canonical row field")
        for group, members in fields.items():
            _text(group, "field group")
            if type(members) is not dict or len(members) > 256:
                raise InvalidResearch("field budget")
            for name, field in members.items():
                _text(name, "field name")
                _keys(field, ("status", "value"), label="field")
                if type(field["status"]) is not str or field["status"] not in FIELD_STATES:
                    raise InvalidResearch("invalid field uncertainty")
        if "evidence" in row:
            _keys(row["evidence"], ("record_sha256", "record_ordinal", "sequence_ordinal", "source_id", "checkpoint_id", "store_seal", "event", "observation"), label="native row evidence")
            evidence = row["evidence"]
            for key in ("record_sha256", "store_seal"):
                _hash(evidence[key], key)
            for key in ("record_ordinal", "sequence_ordinal"):
                evidence[key] = str(_uint(evidence[key], key))
            for key in ("source_id", "checkpoint_id"):
                _text(evidence[key], key, 1024)
    if len(canonical(out)) > MAX_DOCUMENT:
        raise InvalidResearch("normalized BGP interpretation byte budget")
    return out


def read_interpretation(path):
    return validate(read_json(path))


def _anchor(row):
    return int(row["record_offset"]), -1 if "entry_index" not in row else int(row["entry_index"])


def compare(left, right, *, maximum=MAX_ROWS, output_limit=MAX_DOCUMENT):
    """Compare only exact source/config peers with explicit common coverage."""
    if type(maximum) is not int or not 1 <= maximum <= MAX_ROWS:
        raise InvalidResearch("comparison row budget")
    if type(output_limit) is not int or not 1 <= output_limit <= MAX_DOCUMENT:
        raise InvalidResearch("comparison output byte budget")
    left, right = validate(left), validate(right)
    if left["source"] != right["source"]:
        raise InvalidResearch("comparison source identity mismatch")
    if left["normalization"] != right["normalization"]:
        raise InvalidResearch("comparison normalization profile/config mismatch")
    a = {_anchor(r): r for r in left["observations"]}
    b = {_anchor(r): r for r in right["observations"]}
    rows, first, used = [], None, 0
    counts = {"agreement": 0, "disagreement": 0, "not_comparable": 0}

    def add(anchor, group, field, outcome, reason, lv, rv, l, r):
        nonlocal first, used
        row = {"record_offset": str(anchor[0]), "group": group, "field": field,
               "result": outcome, "reason": reason, "left": lv, "right": rv,
               "left_source_range": None if l is None else l["source_range"],
               "right_source_range": None if r is None else r["source_range"]}
        if anchor[1] >= 0:
            row["entry_index"] = str(anchor[1])
        used += len(canonical(row)) + 1
        if len(rows) >= maximum or used > output_limit:
            raise InvalidResearch("comparison output budget exceeded; narrow the case")
        if first is None and outcome == "disagreement":
            first = len(rows)
        rows.append(row)
        counts[outcome] += 1

    for anchor in sorted(a.keys() | b.keys()):
        l, r = a.get(anchor), b.get(anchor)
        if l is None or r is None:
            add(anchor, "disposition", "/", "not_comparable", "missing_observation", l, r, l, r)
            continue
        complete = l["coverage"].get("disposition") == r["coverage"].get("disposition") == "complete"
        ld, rd = l["disposition"], r["disposition"]
        comparable = complete and ld in {"accepted", "rejected"} and rd in {"accepted", "rejected"}
        add(anchor, "disposition", "/", ("agreement" if ld == rd else "disagreement") if comparable else "not_comparable",
            "agreement_is_not_correctness" if comparable and ld == rd else "acceptance_differs" if comparable else "disposition_coverage_or_uncertainty", ld, rd, l, r)
        groups = set(l["fields"]) | set(r["fields"]) | set(l["coverage"]) | set(r["coverage"])
        groups.discard("disposition")
        for group in sorted(groups, key=lambda x: (GROUPS.index(x) if x in GROUPS else len(GROUPS), x)):
            lf, rf = l["fields"].get(group, {}), r["fields"].get(group, {})
            complete = l["coverage"].get(group) == r["coverage"].get(group) == "complete"
            names = sorted(lf.keys() | rf.keys()) or ["/"]
            for name in names:
                lv, rv = lf.get(name), rf.get(name)
                reason = None
                if group not in GROUPS:
                    reason = "unknown_field_group"
                elif not complete:
                    reason = "field_group_coverage_gap"
                elif lv is None or rv is None:
                    reason = "field_not_normalized_by_both_adapters"
                elif lv["status"] != "observed" or rv["status"] != "observed":
                    reason = "unknown_or_incomplete_field"
                if reason:
                    add(anchor, group, name, "not_comparable", reason, lv, rv, l, r)
                else:
                    same = canonical(lv["value"]) == canonical(rv["value"])
                    add(anchor, group, name, "agreement" if same else "disagreement",
                        "agreement_is_not_correctness" if same else "normalized_value_differs", lv, rv, l, r)
    result = {"schema": DIFFERENTIAL_SCHEMA, "source": left["source"],
              "normalization": left["normalization"], "producers": [left["producer"], right["producer"]],
              "counts": counts, "rows": rows, "first_observed_disagreement": first,
              "consensus_used": False, "state_admission": False,
              "comparison_changes_canonical_evidence": False,
              "producer_authentication": "not_established", "semantic_correctness_proven": False,
              "policy": "raw_source_witness_and_primary_specification_adjudication_required"}
    if len(canonical(result)) > output_limit:
        raise InvalidResearch("comparison output byte budget")
    return result


def _field(value, status=None):
    return {"status": status or ("unknown" if value is None else "observed"), "value": value}


def _native_observation(row):
    """Conservative projection; keep the original event/observation alongside it.

    The accepted tag means a decoded candidate interpretation, not reducer
    admission. Unknown parser statuses are deliberately not classified by
    substring or by outer-container success.
    """
    event, observation = row["event"], row["observation"]
    event = event if type(event) is dict else {}
    status = event.get("parse_status")
    accepted = {"decoded_open", "decoded_update_candidate", "decoded_notification_reset",
                "decoded_keepalive", "decoded_route_refresh"}
    disposition = "accepted" if type(status) is str and status in accepted else "rejected" if status == "rejected" else "unknown"
    # RIB entries have normalized route evidence but no session-event status.
    if status is None and type(observation) is dict and observation.get("message_type") == 2:
        disposition = "accepted"
    coverage = {group: "not_collected" for group in GROUPS}
    coverage["disposition"] = "complete" if disposition in {"accepted", "rejected"} else "partial"
    fields = {"framing": {"record_bytes": _field(str(_uint(row["record_bytes"]))),
                          "record_type": _field(row["record_type"]), "subtype": _field(row["subtype"]),
                          "mrt_record_time": _field(row["mrt_record_time"], "unknown" if row["mrt_record_time"]["time_ns"] is None else "observed")},
              "validation": {"parse_status": _field(status),
                             "issues": _field(event.get("issues"))}}
    coverage["framing"] = "complete"
    coverage["validation"] = "partial"
    if type(observation) is dict:
        fields["message"] = {key: _field(observation.get(key)) for key in ("message_type", "message_detail")}
        coverage["message"] = "complete"
        routes = observation.get("routes")
        if type(routes) is list and all(type(route) is dict for route in routes):
            fields["nlri"] = {"routes": _field([{key: route.get(key) for key in ("action", "prefix")} for route in routes])}
            attribute_keys = ("attributes", "attribute_ranges", "imported_attribute_occurrences")
            fields["attributes"] = {"route_attributes": _field(
                [{key: route[key] for key in attribute_keys if key in route} for route in routes])}
            coverage["nlri"] = "complete"
            coverage["attributes"] = "complete" if all("attributes" in r for r in routes) else "partial"
        fields["validation"]["normalized_issues"] = _field(observation.get("issues"))
    return {"record_offset": row["record_offset"], "entry_index": row.get("entry_index"),
            "source_range": {"kind": "source_range", "start": row["record_offset"],
                             "end": str(_uint(row["record_offset"]) + _uint(row["record_bytes"]))},
            "disposition": disposition, "coverage": coverage, "fields": fields,
            "evidence": {key: row[key] for key in ("record_sha256", "record_ordinal", "sequence_ordinal",
                                                    "source_id", "checkpoint_id", "store_seal", "event", "observation")}}


def from_native(raw, manifest=None, *, source_ordinal=None):
    """Convert exact native NDJSON bytes, verifying the export byte commitment.

    The terminal manifest may be the last NDJSON line or supplied separately.
    Multiple source entries require an explicit ordinal; no source partitions
    are merged. Store seals remain attributed claims, not authenticated inputs.
    """
    if type(raw) is not bytes or len(raw) > MAX_DOCUMENT:
        raise InvalidResearch("native evidence byte budget")
    rows, row_parts = [], []
    terminal = None
    for part in raw.splitlines(keepends=True):
        if not part.endswith(b"\n") or not part.strip():
            raise InvalidResearch("native NDJSON needs nonempty newline-terminated rows")
        value = decode_json(part)
        if type(value) is dict and value.get("schema") == "pcap-evidence.bgp.evidence-manifest.v1":
            if terminal is not None:
                raise InvalidResearch("multiple native manifests")
            terminal = value
        else:
            if terminal is not None:
                raise InvalidResearch("native rows after terminal manifest")
            if len(rows) >= MAX_ROWS:
                raise InvalidResearch("native evidence record budget")
            rows.append(value)
            row_parts.append(part)
    if manifest is None:
        manifest = terminal
    elif terminal is not None and canonical(manifest) != canonical(terminal):
        raise InvalidResearch("sidecar/terminal manifest mismatch")
    _keys(manifest, MANIFEST_KEYS + ("semantic_identity",), label="native manifest")
    if manifest["schema"] != "pcap-evidence.bgp.evidence-manifest.v1" or manifest["complete"] is not True:
        raise InvalidResearch("incomplete native evidence manifest")
    for flag in ("endpoint_state_claimed", "source_authenticated", "resume_cursor_supported"):
        if manifest[flag] is not False:
            raise InvalidResearch("native manifest authority flag")
    if type(manifest["replay_relationship"]) is not str or manifest["replay_relationship"] not in {"unknown", "internal", "external"}:
        raise InvalidResearch("native replay relationship")
    if manifest["semantic_profile"] != NATIVE_PROFILE:
        raise InvalidResearch("unsupported native semantic profile")
    if manifest["rows_digest_scope"] != "exact_ndjson_rows_including_newlines_excluding_manifest":
        raise InvalidResearch("native row digest scope")
    _hash(manifest["semantic_identity"], "native semantic identity")
    row_raw = b"".join(row_parts)
    if (_uint(manifest["rows"]) != len(rows) or _uint(manifest["rows_bytes"]) != len(row_raw)
            or _hash(manifest["rows_sha256"], "native rows hash") != digest(row_raw)):
        raise InvalidResearch("native row count/bytes/digest mismatch")
    sequence = manifest["sequence"]
    _keys(sequence, ("schema", "entries", "sequence_digest", "ordering", "independent_checkpoints"), label="native sequence")
    if sequence["ordering"] != "caller_file_order" or sequence["independent_checkpoints"] is not True:
        raise InvalidResearch("native sequence ordering contract")
    if sequence["schema"] != "pcap-evidence.bgp.source-sequence.v1":
        raise InvalidResearch("unsupported native sequence schema")
    _hash(sequence["sequence_digest"], "native sequence digest")
    entries = sequence["entries"]
    if type(entries) is not list or not 1 <= len(entries) <= 256:
        raise InvalidResearch("native source count budget")
    by_ordinal = {}
    predecessor = _domain_hash("pcap-evidence/bgp-source-sequence/v1", b"genesis")
    for entry in entries:
        _keys(entry, ENTRY_KEYS + ("entry_digest",), label="native sequence entry")
        ordinal = _uint(entry["ordinal"], "source ordinal")
        if ordinal != len(by_ordinal):
            raise InvalidResearch("native source ordinals must be contiguous")
        for key in ("source_sha256", "final_chain", "store_seal", "predecessor_digest", "entry_digest"):
            _hash(entry[key], key)
        for key in ("source_id", "checkpoint_id"):
            _text(entry[key], key, 1024)
        source_bytes = _uint(entry["source_bytes"], "native source length")
        record_count = _uint(entry["record_count"], "native source record count")
        if not 0 < record_count <= source_bytes // 12:
            raise InvalidResearch("native record count/source size contract")
        if entry["predecessor_digest"] != predecessor:
            raise InvalidResearch("native sequence predecessor mismatch")
        expected = _domain_hash("pcap-evidence/bgp-source-sequence/v1", _compact({key: entry[key] for key in ENTRY_KEYS}))
        if entry["entry_digest"] != expected:
            raise InvalidResearch("native sequence entry digest mismatch")
        predecessor = expected
        by_ordinal[ordinal] = entry
    if sequence["sequence_digest"] != predecessor:
        raise InvalidResearch("native sequence terminal digest mismatch")
    payload = _native_manifest_payload(manifest)
    expected = _domain_hash("pcap-evidence/bgp-evidence-manifest/v1", _compact(payload))
    if manifest["semantic_identity"] != expected:
        raise InvalidResearch("native manifest semantic identity mismatch")
    for key in COVERAGE_KEYS:
        if key not in {"witnesses", "count_unit"}:
            _uint(manifest["coverage"][key], "native coverage count")
    if (manifest["coverage"]["count_unit"] != "rows_except_records_unknown_mrt_record_time_and_timestamp_regressions"
            or _uint(manifest["coverage"]["rows"]) != len(rows)):
        raise InvalidResearch("native coverage row count/unit mismatch")
    if source_ordinal is None:
        if len(entries) != 1:
            raise InvalidResearch("multiple sources require explicit source ordinal")
        source_ordinal = 0
    source_ordinal = _uint(source_ordinal, "selected source ordinal")
    if source_ordinal not in by_ordinal:
        raise InvalidResearch("selected native source ordinal absent")
    selected, observations = by_ordinal[source_ordinal], []
    row_required = ("schema", "provisional", "sequence_ordinal", "source_id", "checkpoint_id", "source_sha256",
                    "full_source_bytes", "store_seal", "record_ordinal", "record_offset", "record_bytes", "record_type", "subtype", "record_sha256",
                    "mrt_record_time", "rib_originated_time_ns", "observation_time_ns", "event", "observation",
                    "window_disposition", "asn_disposition", "selected", "certain_occurrence_time_claimed")
    seen_anchors, records = set(), {ordinal: {} for ordinal in by_ordinal}
    previous_anchor = None
    unknown_mrt_records = set()
    for row in rows:
        _keys(row, row_required, ("entry_index",), "native evidence row")
        if row["schema"] != "pcap-evidence.bgp.evidence-row.v1" or row["provisional"] is not True:
            raise InvalidResearch("invalid native evidence row schema")
        ordinal = _uint(row["sequence_ordinal"], "native source ordinal")
        entry = by_ordinal.get(ordinal)
        if entry is None:
            raise InvalidResearch("native row source ordinal absent")
        if type(row["selected"]) is not bool or row["certain_occurrence_time_claimed"] is not False:
            raise InvalidResearch("native row selection/authority flags")
        for key in ("record_type", "subtype"):
            if type(row[key]) is not int or not 0 <= row[key] < 1 << 16:
                raise InvalidResearch("native MRT record type/subtype must be u16 JSON integers")
        time = row["mrt_record_time"]
        _keys(time, ("seconds", "microseconds", "validity", "precision", "time_ns"), label="native record time")
        seconds = _uint(time["seconds"], "native seconds")
        micros = None if time["microseconds"] is None else _uint(time["microseconds"], "native microseconds")
        if seconds >= 1 << 32 or micros is not None and micros >= 1 << 32:
            raise InvalidResearch("native MRT raw timestamp outside u32")
        if row["record_type"] != 17:
            validity, precision, time_ns = "seconds", "seconds", seconds * 1_000_000_000
        elif micros is None:
            validity, precision, time_ns = "missing_microseconds", "unknown", None
        elif micros >= 1_000_000:
            validity, precision, time_ns = "invalid_microseconds", "unknown", None
        else:
            validity, precision, time_ns = "microseconds", "microseconds", seconds * 1_000_000_000 + micros * 1000
        reported_ns = None if time["time_ns"] is None else _signed(time["time_ns"], "native time")
        if time["validity"] != validity or time["precision"] != precision or reported_ns != time_ns:
            raise InvalidResearch("native MRT time representation mismatch")
        for key in ("rib_originated_time_ns", "observation_time_ns"):
            if row[key] is not None:
                _signed(row[key], key)
        if time_ns is None and row["observation_time_ns"] is not None:
            raise InvalidResearch("unknown MRT time cannot establish an observation time label")
        for row_key, entry_key in (("source_sha256", "source_sha256"), ("store_seal", "store_seal"),
                                   ("source_id", "source_id"), ("checkpoint_id", "checkpoint_id")):
            if row[row_key] != entry[entry_key]:
                raise InvalidResearch("native row source/seal mismatch")
        if _uint(row["full_source_bytes"]) != _uint(entry["source_bytes"]):
            raise InvalidResearch("native row source length mismatch")
        offset, size = _uint(row["record_offset"]), _uint(row["record_bytes"])
        if size < 12 or offset + size > _uint(entry["source_bytes"]):
            raise InvalidResearch("native record range outside source")
        record_ordinal = _uint(row["record_ordinal"])
        if record_ordinal >= _uint(entry["record_count"]):
            raise InvalidResearch("native record ordinal outside source")
        if time_ns is None:
            unknown_mrt_records.add((ordinal, record_ordinal))
        _hash(row["record_sha256"], "native record digest")
        if row.get("entry_index") is not None:
            _uint(row["entry_index"], "native entry index")
        anchor = ordinal, offset, None if row.get("entry_index") is None else _uint(row["entry_index"])
        if anchor in seen_anchors:
            raise InvalidResearch("duplicate native source anchor")
        ordered_anchor = ordinal, record_ordinal, -1 if anchor[2] is None else anchor[2]
        if previous_anchor is not None and ordered_anchor <= previous_anchor:
            raise InvalidResearch("native chronology order mismatch")
        previous_anchor = ordered_anchor
        seen_anchors.add(anchor)
        record_identity = offset, size, row["record_sha256"], row["record_type"], row["subtype"], _compact(time)
        prior = records[ordinal].get(record_ordinal)
        if prior is not None and prior != record_identity:
            raise InvalidResearch("native entry record identity mismatch")
        records[ordinal][record_ordinal] = record_identity
        if ordinal == source_ordinal:
            observations.append(_native_observation(row))
    if any(len(records[ordinal]) != _uint(entry["record_count"]) for ordinal, entry in by_ordinal.items()):
        raise InvalidResearch("native chronology coverage incomplete")
    for ordinal, inventory in records.items():
        expected_offset = 0
        for offset, size, *_ in inventory.values():
            if offset != expected_offset:
                raise InvalidResearch("native record ranges leave source gap or overlap")
            expected_offset += size
        if expected_offset != _uint(by_ordinal[ordinal]["source_bytes"]):
            raise InvalidResearch("native record ranges do not cover full source")
    if (_uint(manifest["coverage"]["records"]) != sum(map(len, records.values()))
            or _uint(manifest["coverage"]["observations"]) != sum(row["observation"] is not None for row in rows)
            or _uint(manifest["coverage"]["unknown_mrt_record_time"]) != len(unknown_mrt_records)
            or _uint(manifest["coverage"]["selected"]) != sum(row["selected"] for row in rows)):
        raise InvalidResearch("native coverage contradicts row evidence")
    config = {"semantic_profile": manifest["semantic_profile"], "replay_relationship": manifest["replay_relationship"]}
    return validate({"schema": SCHEMA, "source": {"sha256": selected["source_sha256"], "bytes": selected["source_bytes"]},
                     "normalization": {"profile": NORMALIZATION, "config_sha256": digest(canonical(config))},
                     "producer": {"id": "pcap-evidence-native", "version": "evidence-row.v1", "adapter_version": "1",
                                  "origin": "native_evidence", "command": []},
                     "observations": observations, "native_evidence": manifest})


def convert_native_file(rows_path, manifest_path=None, *, source_ordinal=None):
    with Path(rows_path).open("rb") as stream:
        raw = stream.read(MAX_DOCUMENT + 1)
    manifest = None if manifest_path is None else read_json(manifest_path)
    return from_native(raw, manifest, source_ordinal=source_ordinal)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    native = commands.add_parser("native", help="convert native source-bound NDJSON")
    native.add_argument("rows", type=Path)
    native.add_argument("manifest", type=Path, nargs="?")
    native.add_argument("--source-ordinal", type=int)
    compare_parser = commands.add_parser("compare", help="compare attributed interpretations")
    compare_parser.add_argument("left", type=Path)
    compare_parser.add_argument("right", type=Path)
    compare_parser.add_argument("--max-rows", type=int, default=MAX_ROWS)
    compare_parser.add_argument("--output-bytes", type=int, default=MAX_DOCUMENT)
    args = parser.parse_args(argv)
    if args.command == "native":
        result = convert_native_file(args.rows, args.manifest, source_ordinal=args.source_ordinal)
    else:
        result = compare(read_interpretation(args.left), read_interpretation(args.right),
                         maximum=args.max_rows, output_limit=args.output_bytes)
    print(canonical(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as error:
        print(canonical({"status": "ERROR", "reason": str(error)}).decode("utf-8"))
        raise SystemExit(1)
