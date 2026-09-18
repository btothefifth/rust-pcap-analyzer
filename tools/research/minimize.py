"""Packet-subset reduction preserving the FIRST semantic-difference fingerprint.

For structurally readable, explicitly bounded research captures only. This is
not malformed-container repair and not a minimality or correctness oracle.
The fingerprint ignores renumbered frame keys, but requires the same layer,
field, reason and attributed values; crashes never count as a reproduced diff.
"""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
from tools.evidence.containers import Reader
from tools.evidence.minimize import ddmin, write_subset
from tools.evidence.common import publish_new
from .contract import InvalidResearch, file_identity, compare_fields, canonical, digest
from .adapters import run_adapter


def fingerprint(report):
    first=report.get('first_semantic_divergence')
    if first is None:return None
    return {k:first[k] for k in ('layer','field','reason','left','right')}


def reduce_capture(source,destination,evaluate,*,max_calls=40,max_packets=2000):
    """evaluate(path) must return an attributed compare_fields report or raise.

    The evaluator is trusted local code, not deserialized from a case document.
    Errors/timeouts/crashes abort instead of satisfying a different predicate.
    """
    source=Path(source).resolve(strict=True);destination=Path(destination)
    if destination.exists():raise FileExistsError(destination)
    if not 2<=max_calls<=200 or not 1<=max_packets<=10000:raise ValueError('reduction budget')
    original=file_identity(source);baseline=evaluate(source);target=fingerprint(baseline)
    if target is None:raise InvalidResearch('no semantic divergence in the selected comparison')
    with source.open('rb')as f:records=list(Reader(f).records())
    frames=[r.packet.frame for r in records if r.packet is not None]
    if len(frames)>max_packets:raise InvalidResearch('packet reduction budget; select a smaller case')
    attempts=[]
    with tempfile.TemporaryDirectory(prefix='pcap-research-reduce-',dir=destination.parent)as td:
        trial=Path(td)/'candidate.pcap'
        def predicate(selected):
            write_subset(records,set(selected),trial)
            report=evaluate(trial)
            match=fingerprint(report)==target
            attempts.append({'selected_packet_count':len(selected),'capture':file_identity(trial),
                             'same_first_divergence':match,'comparison_sha256':digest(canonical(report))})
            return match
        selected,calls,_=ddmin(frames,predicate,max_calls=max_calls)
        # A successful deletion can change earlier deletion results for a
        # non-monotone semantic predicate. Only a complete fresh no-deletion
        # pass justifies the single-deletion-minimal claim.
        minimal=False
        while calls<max_calls:
            changed=False;finished=True
            for item in list(selected):
                if calls>=max_calls:finished=False;break
                candidate=[x for x in selected if x!=item];calls+=1
                if predicate(candidate):selected=candidate;changed=True;break
            if finished and not changed:minimal=True;break
            if not finished:break
        write_subset(records,set(selected),trial)
        final=evaluate(trial)
        if fingerprint(final)!=target:raise InvalidResearch('final recheck failed; unstable predicate')
        if file_identity(source)!=original:raise InvalidResearch('original capture changed during reduction')
        receipt={'schema':'pcap-evidence.research-reduction.v1','status':'PASS',
                 'source':original,'derived':file_identity(trial),'target_fingerprint':target,
                 'predicate_calls':calls,'additional_original_and_final_evaluations':2,
                 'single_deletion_minimal_for_this_predicate':minimal,'budget_exhausted':calls>=max_calls,
                 'frame_map':[{'derived_frame':str(i+1),'original_frame':str(n)}for i,n in enumerate(selected)],
                 'metadata_policy':'capture/section/interface headers only; finite section lengths changed to unknown',
                 'original_capture_modified':False,'security_impact':'not_established','attempts':attempts}
        destination.mkdir()
        publish_new(trial,destination/'reduced.pcap')
        (destination/'comparison.json').write_bytes(canonical(final)+b'\n')
        # Completion receipt last: an interrupted directory is not a complete result.
        (destination/'reduction.json').write_bytes(canonical(receipt)+b'\n')
        return receipt


def reduce_adapters(source,destination,left,right,*,left_binary=None,right_binary=None,max_calls=40,timeout=30):
    if left not in {'container','product','tshark'} or right not in {'container','product','tshark'}:
        raise InvalidResearch('unknown local adapter')
    def evaluate(path):
        a=run_adapter(left,path,left_binary,timeout=timeout);b=run_adapter(right,path,right_binary,timeout=timeout)
        for result in (a,b):
            if result['status']!='PASS':raise InvalidResearch('adapter did not complete: '+result['status'])
        return compare_fields(a['snapshot'],b['snapshot'])
    return reduce_capture(source,destination,evaluate,max_calls=max_calls)
