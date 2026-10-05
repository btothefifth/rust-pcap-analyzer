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
import subprocess
import sys
import time
sys.dont_write_bytecode = True
from build_hardening_corpus import generate
from owned_process import run as run_owned
from validation_frontier import source_snapshot
import tomllib

TARGETS = ('capture', 'engine', 'capture_parity', 'wire', 'tcp', 'protocols', 'provenance', 'index', 'semantics')


def execute(command: list[str], cwd: Path, log: Path, timeout: int) -> dict:
    started = time.monotonic()
    env = dict(os.environ, CARGO_NET_OFFLINE='true', RUST_BACKTRACE='1')
    try:
        with log.open('xb') as output:
            result = run_owned(command, cwd=cwd, stdout=output, stderr=output,
                               env=env, timeout=timeout, max_output_bytes=64*1024*1024)
    except BaseException as error:
        result = getattr(error, 'process_result', None)
        error.campaign_step = {'command': command, 'status': 'INTERRUPTED' if isinstance(error, KeyboardInterrupt) else 'FAIL',
                               'reason': result.reason if result else 'launch_failure',
                               'returncode': result.returncode if result else None,
                               'timed_out': False, 'log': log.name,
                               'duration_seconds': round(time.monotonic()-started, 3),
                               'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest() if log.is_file() else None}
        raise
    return {'command': command, 'status': 'PASS' if result.returncode == 0 and not result.reason else 'FAIL',
            'reason': result.reason, 'returncode': result.returncode, 'timed_out': result.reason == 'timeout',
            'duration_seconds': round(time.monotonic() - started, 3),
            'log': log.name, 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()}


def source_identity(root: Path) -> dict:
    # Bind recursive membership as well as bytes. This covers nested semantic,
    # correlate and support modules, both locks, build scripts, fixtures and the
    # executing Python harness. Generated evidence/build trees are excluded.
    root = Path(root).resolve()
    hashes = source_snapshot(root)
    seen = set()
    def local_dependencies(manifest):
        manifest = manifest.resolve()
        if manifest in seen:return
        seen.add(manifest)
        document = tomllib.loads(manifest.read_text())
        directory = manifest.parent
        if not directory.is_relative_to(root):
            for name, value in source_snapshot(directory).items():
                hashes['external:'+str(directory/name)] = value
        sections = [document.get(name,{}) for name in ('dependencies','dev-dependencies','build-dependencies','patch','replace')]
        sections.append(document.get('workspace',{}).get('dependencies',{}))
        sections.extend(document.get('target',{}).values())
        def visit(value):
            if not isinstance(value,dict):return
            if isinstance(value.get('path'),str):
                dependency = (directory/value['path']/'Cargo.toml').resolve()
                if not dependency.is_file():raise ValueError('local dependency manifest missing: '+str(dependency))
                local_dependencies(dependency)
            else:
                for child in value.values():visit(child)
        for section in sections:visit(section)
    local_dependencies(root/'fuzz/Cargo.toml')
    # Cargo reads config from each cwd ancestor and CARGO_HOME, even when the
    # code/manifest tree itself is unchanged. Preserve absence by membership.
    directories = set((root,*root.parents))
    for manifest in seen:directories.update((manifest.parent,*manifest.parent.parents))
    paths = {directory/'.cargo'/name for directory in directories for name in ('config','config.toml')}
    cargo_home = Path(os.environ.get('CARGO_HOME',Path.home()/'.cargo'))
    paths.update(cargo_home/name for name in ('config','config.toml'))
    for path in sorted(paths):
        if path.is_file():hashes['cargo-config:'+str(path.resolve())] = hashlib.sha256(path.read_bytes()).hexdigest()
    # Do not publish potentially private environment values; bind their bytes.
    inputs = {key:value for key,value in os.environ.items()
              if key.startswith(('CARGO_','RUST','CC','CXX','AR_')) and key not in {'CARGO_NET_OFFLINE','RUST_BACKTRACE'}}
    hashes['cargo-environment'] = hashlib.sha256(json.dumps(inputs,sort_keys=True).encode()).hexdigest()
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
    eligible = {entry['name'] for entry in tomllib.loads((root/'fuzz/Cargo.toml').read_text()).get('bin',[])
                if (root/'fuzz'/entry.get('path','')).is_file()}
    if set(TARGETS) != eligible:
        parser.error('campaign selector differs from actual eligible fuzz targets')
    # Killing the entire process group is implemented on POSIX only.
    if os.name != 'posix' or any(not shutil.which(name) for name in ('cargo', 'rustc', 'rustup')):
        print(json.dumps({'status': 'BLOCKED', 'reason': 'requires POSIX worker and installed cargo/rustc/rustup; no tools installed'}))
        return 2
    out = args.output.absolute()
    if out.is_relative_to(root) and not {'target','.local-build'} & set(out.relative_to(root).parts):
        parser.error('in-tree output must be under target or .local-build, outside the bound source closure')
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
        if installed['status'] != 'PASS' or args.toolchain not in names:
            receipt['status'] = 'BLOCKED'
            receipt['error'] = 'requested nightly is not already installed; install it explicitly before retrying'
            return 2
        for label, command in [
            ('rust-version', ['rustc', '+'+args.toolchain, '-Vv']),
            ('cargo-version', ['cargo', '+'+args.toolchain, '-V']),
            ('fuzz-version', ['cargo', '+'+args.toolchain, 'fuzz', '--version']),
        ]:
            item = execute(command, root, out/(label+'.log'), 30); receipt['steps'].append(item); save()
            if item['status'] != 'PASS':
                receipt['status'] = 'BLOCKED'; return 2
        generate(out/'corpus')
        receipt['corpus_manifest_sha256'] = hashlib.sha256((out/'corpus/MANIFEST.json').read_bytes()).hexdigest()
        for target in args.targets:
            build = execute(['cargo', '+'+args.toolchain, 'fuzz', 'build', target], root, out/(target+'-build.log'), 900)
            receipt['steps'].append(build); save()
            if build['status'] != 'PASS':
                receipt['status'] = 'BUILD_FAILED_OR_DEPENDENCY_BLOCKED'; return 1
            artifacts = out/'artifacts'/target; artifacts.mkdir(parents=True)
            # The semantic target is a checked-in eligible binary even when the
            # older seed generator has no semantic-specific seed population.
            (out/'corpus'/target).mkdir(exist_ok=True)
            command = ['cargo', '+'+args.toolchain, 'fuzz', 'run', target, str(out/'corpus'/target), '--',
                       '-max_total_time='+str(args.seconds_per_target), '-timeout=10',
                       '-rss_limit_mb='+str(args.rss_mib), '-max_len=65536', '-seed='+str(args.seed),
                       '-artifact_prefix='+str(artifacts)+os.sep]
            campaign = execute(command, root, out/(target+'-run.log'), args.seconds_per_target+120)
            # Keep raw logs; do not infer coverage percentages from "cov" counters.
            campaign['artifacts'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts.iterdir() if p.is_file()}
            receipt['campaigns'].append(campaign); save()
            if campaign['status'] != 'PASS' or campaign['artifacts']:
                receipt['status'] = 'FAIL_OR_TIMEOUT'; return 1
        final_source = source_identity(root)
        receipt['final_source'] = final_source
        receipt['source_unchanged'] = final_source == receipt['source']
        if not receipt['source_unchanged']:
            receipt['status'] = 'SOURCE_CHANGED'; return 1
        receipt['status'] = 'PASS_BOUNDED_SYNTHETIC_CAMPAIGN'
        return 0
    except KeyboardInterrupt as error:
        if hasattr(error,'campaign_step'):receipt['steps'].append(error.campaign_step)
        receipt['status'] = 'INTERRUPTED'; receipt['error'] = 'campaign interrupted after owned process cleanup'
        return 130
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        if hasattr(error,'campaign_step'):receipt['steps'].append(error.campaign_step)
        receipt['status'] = 'BLOCKED_OR_FAILED'; receipt['error'] = str(error); return 2
    finally:
        receipt['finished_utc'] = datetime.now(timezone.utc).isoformat()
        if 'final_source' not in receipt:
            try:
                receipt['final_source'] = source_identity(root)
                receipt['source_unchanged'] = receipt['final_source'] == receipt['source']
            except (OSError,ValueError) as error:
                receipt['source_unchanged'] = False
                receipt['source_check_error'] = str(error)
        lock = root/'fuzz/Cargo.lock'
        if lock.exists():
            receipt['fuzz_lock_sha256'] = hashlib.sha256(lock.read_bytes()).hexdigest()
            shutil.copyfile(lock, out/'fuzz-Cargo.lock')
        save()
        print(json.dumps({'status': receipt['status'], 'receipt': str(out/'receipt.json')}, indent=2))

if __name__ == '__main__':
    raise SystemExit(main())
