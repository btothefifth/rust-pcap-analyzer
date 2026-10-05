#!/usr/bin/env python3
"""Declared repeatable selectors for the offline repository qualification frontier.

Native commands never install tools. Portable vectors are independent fixture
oracles; their success does not establish native or normative qualification.
"""
from pathlib import Path
import hashlib
import os

WORKSPACES = (
    ('root', 'Cargo.toml'), ('streaming', 'streaming/Cargo.toml'),
    ('product', 'product/Cargo.toml'), ('ffi', 'product/ffi/Cargo.toml'),
    ('history', 'history/Cargo.toml'), ('history-app', 'history-app/Cargo.toml'),
)
EXCLUDED_WORKSPACES = {
    'tools/pcap-parser-oracle/Cargo.toml': 'optional external comparator lacks reviewed lock/license qualification',
    'fuzz/Cargo.toml': 'development-only libFuzzer graph; separate campaign/toolchain qualification',
    'streaming/fuzz/Cargo.toml': 'development-only libFuzzer graph; separate campaign/toolchain qualification',
    'product/fuzz/Cargo.toml': 'development-only libFuzzer graph; separate campaign/toolchain qualification',
    'history/fuzz/Cargo.toml': 'development-only libFuzzer graph; separate campaign/toolchain qualification',
}
FEATURE_PROFILES = ('', 'standard', 'extensions', 'industrial', 'industrial-full', 'binary')
# Fuzz workspaces are development-only graphs, selected by their separate campaigns.
EXCLUDED_PROOF = ('actual-authorized-NIC-capture', 'browser-to-native',
                  'sustained-fuzz', 'representative-large-capture-benchmark',
                  'normative-protocol-qualification', 'desktop-install-upgrade-uninstall')



def portable_commands(python):
    return (
        ('python-tests', [python, '-m', 'unittest', 'discover', '-s', 'tools/tests', '-v']),
        ('bgp-vectors', [python, '-m', 'unittest', 'discover', '-s', 'product/tests', '-p', '*vectors.py', '-v']),
        ('semantic-tools', [python, 'scripts/test_semantic_tools.py', '-v']),
        ('opcua-transforms', [python, '-m', 'unittest', 'tools.depth.test_opcua_crypto', '-v']),
        ('validation-frontier', [python, 'scripts/test_validation_frontier.py', '-v']),
        ('package-contract', [python, 'scripts/test_package_contract.py', '-v']),
        ('owned-process', [python, 'scripts/test_owned_process.py', '-v']),
    )


def native_commands():
    for label, manifest in WORKSPACES:
        for name, options in (
            ('format', ['fmt', '--all', '--', '--check']),
            ('tests', ['test', '--locked', '--offline', '--all-targets']),
            ('release-tests', ['test', '--locked', '--offline', '--release', '--all-targets']),
            ('clippy', ['clippy', '--locked', '--offline', '--all-targets', '--', '-D', 'warnings']),
            ('build', ['build', '--locked', '--offline', '--release', '--all-targets']),
        ):
            yield label + '-' + name, [options[0], '--manifest-path', manifest, *options[1:]]
    for features in FEATURE_PROFILES:
        command = ['test', '--manifest-path', 'product/Cargo.toml', '--locked', '--offline',
                   '--all-targets', '--no-default-features']
        if features:
            command += ['--features', features]
        yield 'features-' + (features or 'none'), command


def native_artifact(root, manifest, filename, profile='release'):
    """Resolve Cargo's actual output directory, including an explicit shared target."""
    target = os.environ.get('CARGO_TARGET_DIR')
    directory = Path(target) if target else Path(manifest).parent / 'target'
    if not directory.is_absolute():
        directory = Path(root) / directory
    return directory / profile / filename


def semantic_case_command(root, python, output, profile='release'):
    probe = 'semantic_probe.exe' if os.name == 'nt' else 'semantic_probe'
    artifact = native_artifact(root, 'Cargo.toml', 'examples/' + probe, profile=profile)
    return [python, 'scripts/semantic_case_runner.py', '--probe', str(artifact),
            '--output', str(Path(output) / 'native-semantic-cases.json')]


def source_snapshot(root):
    """Bind executed receipts to all current source, including unindexed inputs.

    Git and fresh extractions use the same identity surface. Generated evidence
    and isolated tooling/build trees are excluded before walking descendants.
    """
    root = Path(root)
    excluded = {'target', '.git', '__pycache__', '.pytest_cache', '.local-tooling', '.local-build'}
    names = []
    for directory, subdirs, files in os.walk(root, followlinks=False):
        subdirs[:] = [name for name in subdirs if name not in excluded
                      and not (name == 'evidence' and Path(directory) == root)]
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(root)
            if not path.is_symlink() and path.is_file() and not set(relative.parts) & excluded and path.suffix not in {'.zip', '.pyc'}:
                names.append(relative.as_posix())
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sorted(names)}
