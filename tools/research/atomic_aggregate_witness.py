"""Adjudicate the fixed synthetic ATOMIC_AGGREGATE case against RFC 7606 §7.6.

Inputs are verified native interpretations from qualify_bgp_sample. The fixture
and independent expected value are authored bytes, not votes from two parsers.
Only this single field is covered by the deliberately narrow projection.
"""
import argparse
import copy
import json
from pathlib import Path

from . import bgp_compare as bgp, bundle
from .contract import InvalidResearch, canonical, digest, file_identity

FIXTURE = Path(__file__).with_name('fixtures') / 'bgp-corpus-known.json'
SPECIFICATION = 'https://www.rfc-editor.org/rfc/rfc7606.html#section-7.6'


def project(native, source, expected, version):
    offset = str(expected['record_offset'])
    matches = [r for r in native['observations'] if r['record_offset'] == offset]
    if len(matches) != 1 or native['source'] != source:
        raise InvalidResearch('atomic witness source/anchor mismatch')
    row = matches[0]
    observation = row['evidence']['observation']
    routes = observation['routes']
    occurrences = observation['message_detail']['attribute_ranges']
    atomic = [a for a in occurrences if a['type'] == 6]
    if len(routes) != 1 or len(atomic) != 1 or atomic[0]['disposition'] != 'attribute_discard':
        raise InvalidResearch('witness did not reach the malformed-attribute projection')
    config = {'field': 'effective_atomic_aggregate', 'duplicate_policy': 'first_occurrence',
              'invalid_length': 'attribute_discard', 'specification': SPECIFICATION}
    return bgp.validate({'schema': bgp.SCHEMA, 'source': source,
        'normalization': {'profile': bgp.NORMALIZATION, 'config_sha256': digest(canonical(config))},
        'producer': {'id': 'pcap-depth-atomic-projection', 'version': version, 'adapter_version': '1',
                     'origin': 'external_tool', 'command': []},
        'observations': [{'record_offset': offset, 'source_range': row['source_range'],
            'disposition': 'unknown', 'coverage': {'disposition': 'not_collected', 'attributes': 'complete'},
            'fields': {'attributes': {'atomic_aggregate': {'status': 'observed',
                'value': routes[0]['attributes']['atomic_aggregate']}}}}]})


def adjudicate(source, baseline, candidate, output):
    fixture = next(f for f in json.loads(FIXTURE.read_text()) if f['name'] == 'atomic-discard')
    raw = bytes.fromhex(fixture['hex'])
    identity = file_identity(source)
    if identity != {'bytes': str(len(raw)), 'sha256': digest(raw)}:
        raise InvalidResearch('expected exact synthetic atomic witness')
    expected = fixture['expected'][0]
    # This fixed witness has a 12-byte MRT header, 20-byte AS4 transport header,
    # and the malformed attribute at BGP offset 43. Its length is one, not zero.
    attribute_start = expected['record_offset'] + 12 + 20 + 43
    if raw[attribute_start:attribute_start + 4].hex() != expected['attribute_hex']:
        raise InvalidResearch('independent raw attribute anchor mismatch')
    left = project(bgp.read_interpretation(baseline), identity, expected, 'baseline')
    repaired = project(bgp.read_interpretation(candidate), identity, expected, 'candidate')
    oracle = copy.deepcopy(left)
    oracle['producer'] = {'id': 'RFC7606-byte-witness', 'version': '7.6', 'adapter_version': '1',
                          'origin': 'independent_fixture', 'command': []}
    oracle['observations'][0]['fields']['attributes']['atomic_aggregate']['value'] = False
    before, after = bgp.compare(left, oracle), bgp.compare(repaired, oracle)
    if before['counts']['disagreement'] != 1 or after['counts']['agreement'] != 1 or after['counts']['disagreement']:
        raise InvalidResearch('before/after witness did not demonstrate the repaired defect')
    output.mkdir(exist_ok=False)
    bundle.create(output / 'first-divergence.zip', source, left, oracle,
                  specifications=[{'id': SPECIFICATION, 'section': '7.6',
                      'requirement': 'Invalid length requires attribute discard.', 'basis': 'normative_specification'}],
                  artifacts={'baseline-native.json': canonical(bgp.read_interpretation(baseline)),
                             'candidate-native.json': canonical(bgp.read_interpretation(candidate))})
    receipt = {'adjudication': 'confirmed_native_projection_defect_repaired', 'source': identity,
               'attribute_range': {'start': attribute_start, 'end': attribute_start + 4},
               'expected_atomic_aggregate': False, 'before': before, 'after': after,
               'bundle_verification': bundle.verify(output / 'first-divergence.zip'),
               'bundle': file_identity(output / 'first-divergence.zip')}
    (output / 'adjudication.json').write_bytes(canonical(receipt) + b'\n')
    return receipt


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'baseline', 'candidate', 'output'):
        p.add_argument(name, type=Path)
    a = p.parse_args()
    adjudicate(a.source, a.baseline, a.candidate, a.output)


if __name__ == '__main__':
    main()
