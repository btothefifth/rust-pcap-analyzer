#!/usr/bin/env python3
"""Exercise the real CLI against independently constructed synthetic cases.

Requires a built binary. Exit 2 means BLOCKED, never a successful test run.
No captures are downloaded, and inputs are written only in a temporary directory.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
sys.dont_write_bytecode = True
from build_hardening_corpus import seeds


def check(binary: Path) -> dict:
    from check_cli import provenance
    from reference_verify import parse
    checked = 0
    rebuilt = 0
    with tempfile.TemporaryDirectory(prefix='pcap-hardening-') as directory:
        root = Path(directory)
        for seed in seeds():
            if seed.container_valid is None:
                continue
            path = root / (seed.name + '.pcap')
            path.write_bytes(seed.data)
            run = subprocess.run([str(binary), 'inspect', str(path), '--include-payload'],
                                 capture_output=True, text=True, timeout=30, check=False)
            if not seed.container_valid:
                if run.returncode != 4 or run.stdout:
                    raise AssertionError(f'{seed.name}: expected structural rejection, got {run.returncode}: {run.stdout[:300]}')
            else:
                if run.returncode:
                    raise AssertionError(f'{seed.name}: inspect failed: {run.stderr}')
                report = json.loads(run.stdout)
                packets = [r['body'] for r in report['records'] if r['body']['kind'] == 'packet']
                if len(packets) != seed.packet_count:
                    raise AssertionError(f'{seed.name}: packet count mismatch')
                if report['capture_sha256'] != hashlib.sha256(seed.data).hexdigest():
                    raise AssertionError('source identity mismatch')
                oracle = parse(seed.data)['packets']
                for actual, expected in zip(packets, oracle):
                    if actual['packet_hex'] != expected['data'].hex():
                        raise AssertionError(f'{seed.name}: packet bytes differ')
                if seed.name in {'dnp_valid_udp', 'dnp_transport_application_gap_udp', 'ipv6_next_header_variation', 'ipv6_overlap_changed_next_header'}:
                    result = subprocess.run([str(binary), 'analyze', str(path), '--include-payload'],
                                            capture_output=True, text=True, timeout=30, check=False)
                    if result.returncode:
                        raise AssertionError(f'{seed.name}: analysis failed: {result.stderr}')
                    analysis = json.loads(result.stdout)
                    rebuilt += provenance(analysis, oracle)
                    if any(p['disposition'] in ('pending', 'fragment_pending') for p in analysis['packets']):
                        raise AssertionError('nonterminal packet disposition')
                    if seed.name.startswith('dnp_'):
                        apps = analysis.get('udp_applications', [])
                        if len(apps) != 1:
                            raise AssertionError(f'{seed.name}: UDP application was not analyzed')
                        messages = apps[0]['data'].get('messages', [])
                        complete = [m for m in messages if m['complete']]
                        if seed.name == 'dnp_valid_udp' and len(complete) != 1:
                            raise AssertionError('valid DNP3 UDP message missing')
                        if seed.name == 'dnp_transport_application_gap_udp' and complete:
                            raise AssertionError('DNP3 state bridged an interrupted transport')
                    elif seed.name == 'ipv6_next_header_variation':
                        if any(p['disposition'] != 'udp_observed' for p in analysis['packets']):
                            raise AssertionError('IPv6 fragments were split by Next Header')
                    elif not analysis['fragment_notices']:
                        raise AssertionError('overlap was not diagnosed')
            if path.read_bytes() != seed.data:
                raise AssertionError('CLI modified the source capture')
            checked += 1
    return {'status': 'PASS', 'native_cli_executed': True, 'synthetic_container_cases': checked,
            'provenance_objects_rebuilt': rebuilt, 'real_world_captures': False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        print(json.dumps({'status': 'BLOCKED', 'reason': 'compiled CLI binary is absent'}))
        return 2
    try:
        print(json.dumps(check(binary), indent=2))
    except ImportError as error:
        print(json.dumps({"status": "BLOCKED", "reason": "apply overlay to upstream checkout first", "error": str(error)}))
        return 2
    except (OSError, AssertionError, ValueError, subprocess.TimeoutExpired) as error:
        print(json.dumps({'status': 'FAIL', 'error': str(error)}))
        return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
