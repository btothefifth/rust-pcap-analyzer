#!/usr/bin/env python3
"""Bounded local cargo-fuzz campaign; records actual execution, never installs tools.

Use a disposable Linux worker with an external memory/CPU quota. libFuzzer's RSS
flag is not an OS sandbox. Corpus/output are created only at a new destination.
Dependencies must be cached in advance: CARGO_NET_OFFLINE=true is enforced.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
sys.dont_write_bytecode = True
from build_hardening_corpus import generate

TARGETS = ('capture', 'engine', 'capture_parity', 'wire', 'tcp', 'protocols', 'provenance', 'index')


def execute(command: list[str], cwd: Path, log: Path, timeout: int) -> dict:
    started = time.monotonic()
    env = dict(os.environ, CARGO_NET_OFFLINE='true', RUST_BACKTRACE='1')
    with log.open('x', encoding='utf-8') as output:
        process = subprocess.Popen(command, cwd=cwd, stdout=output, stderr=subprocess.STDOUT,
                                   env=env, start_new_session=True)
        timed_out = False
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait()
    return {'command': command, 'returncode': code, 'timed_out': timed_out,
            'duration_seconds': round(time.monotonic() - started, 3),
            'log': log.name, 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()}


def source_identity(root: Path) -> dict:
    # Includes working-tree edits, not just HEAD. No payload/capture files in hash inventory.
    paths = [root/'Cargo.toml', root/'Cargo.lock', root/'rust-toolchain.toml', root/'fuzz/Cargo.toml']
    paths += sorted((root/'src').glob('*.rs')) + sorted((root/'fuzz/fuzz_targets').rglob('*.rs'))
    hashes = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
    return {'files_sha256': hashes, 'inventory_sha256': hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--toolchain', required=True, help='explicit installed nightly or nightly-YYYY-MM-DD')
    parser.add_argument('--seconds-per-target', type=int, default=60)
    parser.add_argument('--rss-mib', type=int, default=2048)
    parser.add_argument('--seed', type=int, default=20260918)
    parser.add_argument('--targets', nargs='+', choices=TARGETS, default=list(TARGETS))
    args = parser.parse_args()
    if not re.fullmatch(r'nightly(?:-\d{4}-\d{2}-\d{2})?', args.toolchain):
        parser.error('toolchain must be nightly or nightly-YYYY-MM-DD')
    if not 1 <= args.seconds_per_target <= 86400 or not 256 <= args.rss_mib <= 65536 or not 1 <= args.seed <= 2147483647:
        parser.error('invalid duration/RSS/seed budget')
    if len(set(args.targets)) != len(args.targets):
        parser.error('duplicate fuzz target')
    root = Path(__file__).resolve().parents[1]
    # Killing the entire process group is implemented on POSIX only.
    if os.name != 'posix' or any(not shutil.which(name) for name in ('cargo', 'rustc', 'rustup')):
        print(json.dumps({'status': 'BLOCKED', 'reason': 'requires POSIX worker and installed cargo/rustc/rustup; no tools installed'}))
        return 2
    out = args.output.absolute()
    if any(p.is_symlink() for p in (out, *out.parents)):
        parser.error('output contains a symlink component')
    try:
        out.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        print(json.dumps({'status': 'BLOCKED', 'reason': str(error)}))
        return 2
    receipt = {'schema': 'pcap-evidence.fuzz-campaign.v1', 'status': 'IN_PROGRESS',
               'started_utc': datetime.now(timezone.utc).isoformat(), 'source': source_identity(root),
               'real_world_captures': False, 'steps': [], 'campaigns': [], 'coverage_percentage': None,
               'seconds_per_target': args.seconds_per_target, 'rss_mib': args.rss_mib, 'seed': args.seed}
    def save() -> None:
        temporary = out/'receipt.tmp'
        temporary.write_text(json.dumps(receipt, indent=2)+'\n')
        os.replace(temporary, out/'receipt.json')
    save()
    try:
        # Listing installed toolchains does not implicitly download a missing one.
        installed = execute(['rustup', 'toolchain', 'list'], root, out/'installed-toolchains.log', 30)
        receipt['steps'].append(installed); save()
        names = []
        for line in (out/'installed-toolchains.log').read_text().splitlines():
            match = re.match(r'^(nightly(?:-\d{4}-\d{2}-\d{2})?)(?:-|$)', line)
            if match: names.append(match.group(1))
        if installed['returncode'] or args.toolchain not in names:
            receipt['status'] = 'BLOCKED'
            receipt['error'] = 'requested nightly is not already installed; install it explicitly before retrying'
            return 2
        for label, command in [
            ('rust-version', ['rustc', '+'+args.toolchain, '-Vv']),
            ('cargo-version', ['cargo', '+'+args.toolchain, '-V']),
            ('fuzz-version', ['cargo', '+'+args.toolchain, 'fuzz', '--version']),
        ]:
            item = execute(command, root, out/(label+'.log'), 30); receipt['steps'].append(item); save()
            if item['returncode']:
                receipt['status'] = 'BLOCKED'; return 2
        generate(out/'corpus')
        receipt['corpus_manifest_sha256'] = hashlib.sha256((out/'corpus/MANIFEST.json').read_bytes()).hexdigest()
        for target in args.targets:
            build = execute(['cargo', '+'+args.toolchain, 'fuzz', 'build', target], root, out/(target+'-build.log'), 900)
            receipt['steps'].append(build); save()
            if build['returncode'] or build['timed_out']:
                receipt['status'] = 'BUILD_FAILED_OR_DEPENDENCY_BLOCKED'; return 1
            artifacts = out/'artifacts'/target; artifacts.mkdir(parents=True)
            command = ['cargo', '+'+args.toolchain, 'fuzz', 'run', target, str(out/'corpus'/target), '--',
                       '-max_total_time='+str(args.seconds_per_target), '-timeout=10',
                       '-rss_limit_mb='+str(args.rss_mib), '-max_len=65536', '-seed='+str(args.seed),
                       '-artifact_prefix='+str(artifacts)+os.sep]
            campaign = execute(command, root, out/(target+'-run.log'), args.seconds_per_target+120)
            # Keep raw logs; do not infer coverage percentages from "cov" counters.
            campaign['artifacts'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts.iterdir() if p.is_file()}
            receipt['campaigns'].append(campaign); save()
            if campaign['returncode'] or campaign['timed_out'] or campaign['artifacts']:
                receipt['status'] = 'FAIL_OR_TIMEOUT'; return 1
        receipt['status'] = 'PASS_BOUNDED_SYNTHETIC_CAMPAIGN'
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        receipt['status'] = 'BLOCKED_OR_FAILED'; receipt['error'] = str(error); return 2
    finally:
        receipt['finished_utc'] = datetime.now(timezone.utc).isoformat()
        lock = root/'fuzz/Cargo.lock'
        if lock.exists():
            receipt['fuzz_lock_sha256'] = hashlib.sha256(lock.read_bytes()).hexdigest()
            shutil.copyfile(lock, out/'fuzz-Cargo.lock')
        save()
        print(json.dumps({'status': receipt['status'], 'receipt': str(out/'receipt.json')}, indent=2))

if __name__ == '__main__':
    raise SystemExit(main())
