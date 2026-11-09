"""Replay one bounded MRT source and compare route fields with pinned mrtparse.

Run under the resource containment described in FOLLOWUP_QUALIFICATION.md.
The input source and wheel are local. This command does not acquire packages or
captures, execute artifact-provided commands, or infer collector authenticity.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from scripts.owned_process import run
from . import bgp_compare as bgp, bundle, mrtparse_adapter as external
from .contract import InvalidResearch, canonical, file_identity, read_json

LIMITS = ["--max-source-bytes", "2097152", "--max-store-bytes", "4194304",
          "--max-record-bytes", "1048576", "--max-records", "10000", "--max-work", "67108864"]


def qualify(source: Path, output: Path, binary: Path, wheel: Path):
    source, binary, wheel = source.resolve(strict=True), binary.resolve(strict=True), wheel.resolve(strict=True)
    source_identity = file_identity(source, max_bytes=2097152)
    binary_identity = file_identity(binary, max_bytes=256*1024*1024)
    decoder = external.load_decoder(wheel)
    output.mkdir(exist_ok=False)
    commands = [
        [str(binary), "bgp", "import-mrt-stream", str(source), "--workspace", str(output / 'store'),
         "--source-id", output.name, "--checkpoint", output.name, *LIMITS],
        [str(binary), "bgp", "chronology", str(output / 'store/bgp.mrt-stream'),
         "--workspace", str(output / 'export'), "--comparison-fields", "per-field-v2",
         *LIMITS, "--max-output-bytes", "8388608"]]
    executions = []
    for index, command in enumerate(commands):
        started = time.monotonic()
        with (output / f'command-{index}.log').open('xb') as log:
            result = run(command, stdout=log, stderr=log, timeout=60, max_output_bytes=1048576)
        executions.append({'command': command, 'exit': result.returncode, 'reason': result.reason,
                           'wall_seconds': round(time.monotonic() - started, 6)})
        (output / 'commands.json').write_bytes(canonical(executions) + b'\n')
        if result.returncode or result.reason:
            raise InvalidResearch('native command failed; retained commands.json and log')
    manifest = read_json(output / 'export/manifest.json')
    count = min(64, int(manifest['rows']))
    native = bgp.convert_native_file(output / 'export/evidence.ndjson', output / 'export/manifest.json',
                                    row_start=0, row_count=count, comparison_fields='per-field-v2')
    with source.open('rb') as stream:
        raw = stream.read(2097153)
    other = external.interpret(raw, decoder, row_count=count)
    known_answers = None
    fixtures = json.loads((Path(__file__).with_name('fixtures') / 'bgp-corpus-known.json').read_text())
    for fixture in fixtures:
        if bytes.fromhex(fixture['hex']) != raw or fixture['name'] == 'atomic-discard':
            continue
        known_answers = {'name': fixture['name'], 'external_prefixes_checked': 0, 'native_comparable_prefixes_checked': 0}
        for expected in fixture['expected']:
            def selected(rows):
                return next(r for r in rows if r['record_offset'] == str(expected['record_offset'])
                            and r.get('entry_index') == (None if expected['entry_index'] is None else str(expected['entry_index'])))
            ext, local = selected(other['observations']), selected(native['observations'])
            def check(row):
                fields = row['fields']['nlri']
                if fields['route_actions']['value'] != [{'route_index': '0', 'action': expected['action']}]:
                    raise InvalidResearch('known route action differs')
                prefixes = fields['route_prefixes']['value']
                if len(prefixes) != 1 or f"{prefixes[0]['prefix']['address']}/{prefixes[0]['prefix']['length']}" != expected['prefix']:
                    raise InvalidResearch('known prefix differs')
            if expected.get('external_available', True):
                check(ext)
                known_answers['external_prefixes_checked'] += 1
            elif any(ext['field_coverage']['nlri'][name] != 'not_collected' for name in bgp.PER_FIELD_NAMES):
                raise InvalidResearch('unknown external family became available')
            comparable = local['field_coverage']['nlri']['route_prefixes'] == 'complete'
            if comparable != expected['native_comparable']:
                raise InvalidResearch('known native availability differs')
            if comparable:
                check(local)
                known_answers['native_comparable_prefixes_checked'] += 1
    report = bgp.compare(native, other)
    if report["source"] != source_identity or file_identity(binary, max_bytes=256*1024*1024) != binary_identity:
        raise InvalidResearch("source or binary changed during qualification")
    for name, value in [('native.json', native), ('external.json', other), ('comparison.json', report)]:
        (output / name).write_bytes(canonical(value) + b'\n')
    bundle.create(output / 'comparison.zip', source, native, other, specifications=[])
    verification = bundle.verify(output / 'comparison.zip')
    families = {"native_comparable": set(), "external_observed": set()}
    for row in report['rows']:
        if row['field'] == 'route_prefixes' and row['result'] in ('agreement', 'disagreement'):
            families['native_comparable'].update(v['prefix']['afi'] for v in row['left']['value'])
    for row in other['observations']:
        values = row['fields']['nlri']['route_prefixes']['value']
        if values:
            families['external_observed'].update(v['prefix']['afi'] for v in values)
    receipt = {'source': source_identity, 'binary': binary_identity,
               'wheel': file_identity(wheel), 'adapter': file_identity(Path(external.__file__)),
               'partition': {'start': 0, 'count': count, 'complete_export_rows': manifest['rows']},
               'native_coverage': manifest['coverage'], 'counts': report['counts'], 'known_answers': known_answers,
               'first_observed_disagreement': report['first_observed_disagreement'],
               'families': {k: sorted(v) for k, v in families.items()}, 'bundle_verification': verification,
               'outputs': {name: file_identity(output / name) for name in (
                   'native.json', 'external.json', 'comparison.json', 'comparison.zip', 'export/evidence.ndjson', 'export/manifest.json')},
               'executions': executions}
    (output / 'qualification.json').write_bytes(canonical(receipt) + b'\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--wheel', type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.source, args.output, args.binary, args.wheel)
    print(canonical({'counts': result['counts'], 'families': result['families']}).decode())


if __name__ == '__main__':
    main()
