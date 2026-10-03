#!/usr/bin/env python3
"""Deterministic, bounded source ZIP with explicit core/expanded-product closure.

Only the indexed source inventory and explicitly declared new source files are
eligible. Generated receipts, caches and private captures are excluded. The
archive's fresh manifest attests bytes and membership, never executed gates.
Packaging does not rewrite historical receipts in the source checkout. Failed
publication retains public artifacts for explicit recovery; it never deletes a
public pathname whose owner may have changed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import ast
import re
import os
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ('core', 'expanded-product')
EXCLUDED = {'.git', 'target', '__pycache__', '.pytest_cache', 'artifacts'}
SOURCE_DIRS = {'src', 'tests', 'scripts', 'docs', 'examples', 'fuzz', 'streaming',
               'corpus', '.github', 'product', 'tools', 'history', 'history-app',
               'desktop', 'fixtures'}
ROOT_FILES = {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.gitignore', '.gitattributes',
              'README.md', 'LICENSE', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', 'AGENTS.md'}
CAPTURE_SUFFIXES = {'.pcap', '.pcapng', '.cap', '.bin', '.mrt'}
FIXTURE_ROOTS = ('tests/fixtures/', 'fixtures/semantics/', 'product/tests/fixtures/',
                 'product/research/fixtures/', 'history/fixtures/')
CORE_SCRIPTS = {'__init__.py', 'package.py', 'validate.py', 'static_check.py',
                'make_fixtures.py', 'reference_verify.py', 'test_oracle.py',
                'check_cli.py', 'check_hardening_cli.py', 'build_hardening_corpus.py',
                'mutation_check.py', 'validation_frontier.py', 'update_test_manifest.py', 'benchmark_cli.py',
                'differential_tshark.py'}
# Newly authored files must be explicit until the integrator indexes them.
NEW_SOURCES = ('scripts/validation_frontier.py', 'scripts/test_validation_frontier.py',
               'scripts/test_package_contract.py', 'scripts/requirements-qualification.txt')
MAX_SOURCE_BYTES = 20_000_000


def inventory(root):
    root = Path(root)
    if (root / '.git').exists():
        result = subprocess.run(['git', 'ls-files', '--cached', '-z'], cwd=root,
                                capture_output=True, check=True)
        names = set(result.stdout.decode('utf-8').split('\0')) - {''}
        names.update(name for name in NEW_SOURCES if (root / name).is_file())
        return sorted(names)
    # A source extraction has no Git index. Its manifest is the sealed inventory.
    manifest = json.loads((root / 'evidence/source-manifest.json').read_text())
    return sorted(manifest['files'])


def selected(name, profile):
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('unsafe source path: ' + name)
    if not relative.parts or set(relative.parts) & EXCLUDED or relative.suffix.lower() in {'.pyc', '.zip'}:
        return False
    if len(relative.parts) == 1:
        return name in ROOT_FILES
    if relative.parts[0] not in SOURCE_DIRS:
        return False
    if 'fuzz' in relative.parts and 'corpus' in relative.parts:
        return False
    if relative.suffix.lower() in CAPTURE_SUFFIXES and not name.startswith(FIXTURE_ROOTS):
        return False
    if profile == 'core':
        if relative.parts[0] in {'product', 'tools', 'history', 'history-app', 'desktop'}:
            return False
        if relative.parts[0] == 'scripts':
            return len(relative.parts) == 2 and relative.name in CORE_SCRIPTS
        if relative.parts[:2] == ('.github', 'workflows'):
            return relative.name in {'ci.yml', 'hardening.yml'}
        if relative.parts[0] == 'docs' and len(relative.parts) > 2:
            return relative.parts[1] in {'streaming', 'semantics'}
    return True


def files(profile='expanded-product', root=None):
    if profile not in PROFILES:
        raise ValueError('unknown package profile: ' + profile)
    root = Path(root or ROOT)
    if not (root / '.git').exists():
        manifest = json.loads((root / 'evidence/source-manifest.json').read_text())
        if profile != manifest['profile']:
            raise ValueError('extraction inventory belongs to a different package profile')
    expected = None
    if not (root / '.git').exists():expected = manifest['files']
    for name in inventory(root):
        if selected(name, profile):
            path = root / name
            if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root.parent):
                raise ValueError('source symlink is forbidden: ' + name)
            if not path.is_file():
                raise ValueError('indexed source missing: ' + name)
            if expected is not None and hashlib.sha256(path.read_bytes()).hexdigest() != expected[name]:
                raise ValueError('sealed extraction source changed: ' + name)
            yield path, name


def check_closure(root, members):
    """Catch local Rust module/Python import omissions before archive construction.

    This checks source membership, not Rust syntax/types or Python execution.
    External packages remain their owning native/portable gate's responsibility.
    """
    root = Path(root).resolve()
    names = {name for _, name in members}
    def require_existing(paths, owner):
        for path in paths:
            if path.is_file() and path.resolve().is_relative_to(root):
                name = path.resolve().relative_to(root).as_posix()
                if name not in names:raise ValueError('package dependency missing: ' + owner + ' -> ' + name)
                return
    for path, name in members:
        if path.suffix == '.rs':
            for match in re.finditer(r'(?:#\[path\s*=\s*"([^"]+)"\]\s*)?(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;', path.read_text()):
                explicit, module = match.groups()
                if explicit:require_existing([path.parent/explicit], name)
                else:
                    base = path.parent if path.stem in {'lib', 'main', 'mod'} else path.with_suffix('')
                    require_existing([base/(module+'.rs'), base/module/'mod.rs'], name)
        elif path.suffix == '.py':
            for node in ast.walk(ast.parse(path.read_text())):
                modules = []
                if isinstance(node, ast.Import):modules = [(alias.name, 0) for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:modules = [(node.module, node.level)]
                for module, level in modules:
                    if module.split('.')[0] == 'jsonschema':
                        requirement = 'scripts/requirements-qualification.txt'
                        if requirement not in names:
                            raise ValueError('package dependency missing: ' + name + ' -> ' + requirement)
                    base = path.parent
                    if level:
                        for _ in range(level-1):base = base.parent
                        targets = [base]
                    else:targets = [root, path.parent]
                    for directory in targets:
                        candidate = directory.joinpath(*module.split('.'))
                        require_existing([candidate.with_suffix('.py'), candidate/'__init__.py'], name)


def build(output, profile='expanded-product', root=None, max_source_bytes=MAX_SOURCE_BYTES):
    root = Path(root or ROOT).resolve()
    output = Path(output).resolve()
    if output == root or root in output.parents:
        raise ValueError('archive output must be outside the source root')
    if output.exists() or output.with_suffix(output.suffix + '.sha256').exists():
        raise ValueError('archive or checksum output already exists')
    members = list(files(profile, root))
    total = sum(path.stat().st_size for path, _ in members)
    if total > max_source_bytes:
        raise ValueError('source inventory exceeds bounded package budget')
    check_closure(root, members)
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for path, name in members}
    manifest = {'schema': 'pcap-evidence.source-files.v2', 'profile': profile,
                'files': hashes, 'source_bytes': total, 'native_build_claim': False,
                'validation_receipts': 'EXCLUDED_GENERATED_OR_HISTORICAL',
                'entrypoints': ['scripts/validate.py', 'Cargo.toml', 'streaming/Cargo.toml']}
    if profile == 'expanded-product':
        requirement = 'scripts/requirements-qualification.txt'
        if requirement in hashes:
            manifest['qualification_dependencies'] = {
                'requirements': requirement, 'provisioning': 'EXPLICIT_BEFORE_OFFLINE_GATES',
                'application_runtime_dependency': False}
        manifest['entrypoints'] += ['scripts/validate_product.py', 'scripts/validate_followup.py',
                                   'product/Cargo.toml', 'product/ffi/Cargo.toml',
                                   'history/Cargo.toml', 'history-app/Cargo.toml']
    output.parent.mkdir(parents=True, exist_ok=True)
    checksum = output.with_suffix(output.suffix + '.sha256')
    owned_archive = owned_checksum = None
    archive_created = checksum_created = False
    try:
        # Acquisition is exclusive. Failure before acquisition owns no cleanup.
        with output.open('xb') as handle:
            archive_created = True
            owned_archive = file_identity(os.fstat(handle.fileno()))
            with zipfile.ZipFile(handle, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                for path, name in members:
                    data = path.read_bytes()
                    if hashlib.sha256(data).hexdigest() != hashes[name]:
                        raise ValueError('source changed during packaging: ' + name)
                    write_member(archive, name, data)
                write_member(archive, 'evidence/source-manifest.json',
                             (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode())
        # Membership drift is also a generation change; never attest a mixed tree.
        if [name for _, name in files(profile, root)] != list(hashes):
            raise ValueError('source inventory changed during packaging')
        if any(hashlib.sha256(path.read_bytes()).hexdigest() != hashes[name] for path, name in members):
            raise ValueError('source changed during packaging')
        assert_owned(output, owned_archive)
        with zipfile.ZipFile(output) as archive:
            if archive.testzip() is not None:
                raise ValueError('archive integrity check failed')
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        assert_owned(output, owned_archive)
        with checksum.open('x', newline='\n') as handle:
            checksum_created = True
            owned_checksum = file_identity(os.fstat(handle.fileno()))
            handle.write(f'{digest}  {output.name}\n')
        assert_owned(output, owned_archive)
        assert_owned(checksum, owned_checksum)
    except BaseException as error:
        if not archive_created:
            raise
        recovery = {'status': 'FAIL', 'recovery': 'MANUAL_RECOVERY_REQUIRED',
                    'inspection_paths': [str(output), str(checksum)],
                    'archive_creation_crossed': archive_created, 'checksum_creation_crossed': checksum_created,
                    'automatic_cleanup': False, 'cause_type': type(error).__name__, 'cause': str(error)}
        if isinstance(error, Exception):
            raise PublicationFailure(recovery) from error
        error.add_note(json.dumps(recovery, sort_keys=True))
        raise

    return {'archive': str(output), 'profile': profile, 'files': len(members) + 1,
            'source_bytes': total, 'bytes': output.stat().st_size, 'sha256': digest,
            'native_build_claim': False}


def file_identity(stat):
    return stat.st_dev, stat.st_ino


def assert_owned(path, identity):
    if path.is_symlink() or file_identity(path.stat()) != identity:
        raise ValueError('output ownership changed: ' + str(path))


class PublicationFailure(ValueError):
    """Publication crossed exclusive creation but did not complete; retain state."""
    def __init__(self, recovery):
        self.recovery = recovery
        super().__init__(json.dumps(recovery, sort_keys=True))


def write_member(archive, name, data):
    info = zipfile.ZipInfo('pcap-evidence/' + name, date_time=(2026, 9, 16, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=PROFILES, default='expanded-product')
    parser.add_argument('--output', type=Path, default=ROOT.parent / 'pcap-evidence.zip')
    parser.add_argument('--max-source-bytes', type=int, default=MAX_SOURCE_BYTES)
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.output, args.profile, max_source_bytes=args.max_source_bytes), indent=2))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
