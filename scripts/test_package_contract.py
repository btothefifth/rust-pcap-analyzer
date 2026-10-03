"""Bounded package membership and extraction witnesses, with disposable outputs."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import package

ROOT = Path(__file__).resolve().parents[1]


def active_profiles():
    if (ROOT/'.git').exists():return package.PROFILES
    return (json.loads((ROOT/'evidence/source-manifest.json').read_text())['profile'],)


class PackageContract(unittest.TestCase):
    def test_reviewed_inventory_excludes_unindexed_and_generated_evidence(self):
        for profile in active_profiles():
            names = {name for _, name in package.files(profile)}
            self.assertFalse(any(name.startswith('evidence/') for name in names))
            self.assertNotIn('tools/user-private.pcap', names)
            self.assertLess(sum(path.stat().st_size for path, _ in package.files(profile)), package.MAX_SOURCE_BYTES)
        self.assertFalse(package.selected('product/private.pcap', 'expanded-product'))
        self.assertFalse(package.selected('product/target/debug/x', 'expanded-product'))
        self.assertFalse(package.selected('streaming/fuzz/corpus/x.bin', 'expanded-product'))
        self.assertFalse(package.selected('evidence/local-validation.json', 'expanded-product'))
        with self.assertRaises(ValueError):package.selected('../escape', 'core')

    def test_profiles_close_over_runtime_dependencies_and_all_synthetic_fixtures(self):
        for profile in active_profiles():
            names = {name for _, name in package.files(profile)}
            for name in names:
                if name.endswith('Cargo.toml') and 'fuzz' not in Path(name).parts:
                    for dependency in tomllib.loads((ROOT / name).read_text()).get('dependencies', {}).values():
                        if isinstance(dependency, dict) and 'path' in dependency:
                            required = ((ROOT / name).parent / dependency['path'] / 'Cargo.toml').resolve().relative_to(ROOT).as_posix()
                            self.assertIn(required, names)
            for prefix in package.FIXTURE_ROOTS:
                if profile == 'core' and prefix.startswith(('product/', 'history/')):continue
                for path in (ROOT / prefix).rglob('*'):
                    if path.is_file():self.assertIn(path.relative_to(ROOT).as_posix(), names)
            if profile == 'core':
                self.assertNotIn('scripts/validate_product.py', names)
                self.assertNotIn('.github/workflows/streaming-evidence.yml', names)
            else:
                for path in ('scripts/validate_product.py', 'scripts/validate_followup.py',
                             'product/Cargo.toml', 'history-app/Cargo.toml', 'desktop/web/model.test.mjs'):
                    self.assertIn(path, names)

    def test_small_extractions_match_fresh_inventory_and_execute_portable_entrypoints(self):
        if not (ROOT/'.git').exists():
            self.skipTest('sealed extraction: archive reproduction is selected only in the reviewed source checkout; membership, closure and denial tests still execute')
        env = dict(__import__('os').environ, PYTHONDONTWRITEBYTECODE='1')
        for profile in active_profiles():
            with self.subTest(profile=profile), tempfile.TemporaryDirectory(prefix='pcap-package-contract-') as temporary:
                directory = Path(temporary)
                archive = directory / 'source.zip'
                result = package.build(archive, profile)
                self.assertLess(result['bytes'], 5_000_000)
                with zipfile.ZipFile(archive) as source:source.extractall(directory / 'extracted')
                root = directory / 'extracted/pcap-evidence'
                manifest = json.loads((root / 'evidence/source-manifest.json').read_text())
                actual = {path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file()}
                self.assertEqual(actual, set(manifest['files']) | {'evidence/source-manifest.json'})
                self.assertEqual(manifest['profile'], profile)
                self.assertFalse(manifest['native_build_claim'])
                for name, digest in manifest['files'].items():
                    self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), digest)
                for script in ('scripts/static_check.py', 'scripts/make_fixtures.py', 'scripts/reference_verify.py', 'scripts/test_oracle.py'):
                    argv = [sys.executable, script] + (['--check'] if script.endswith('make_fixtures.py') else [])
                    completed = subprocess.run(argv, cwd=root, env=env, capture_output=True, timeout=60)
                    self.assertEqual(completed.returncode, 0, completed.stderr.decode()[-3000:])
                if profile == 'expanded-product':
                    for argv in ([sys.executable, '-m', 'unittest', 'discover', '-s', 'product/tests', '-p', '*vectors.py'],
                                 [sys.executable, 'scripts/test_semantic_tools.py'],
                                 [sys.executable, '-m', 'unittest', 'tools.depth.test_opcua_crypto']):
                        completed = subprocess.run(argv, cwd=root, env=env, capture_output=True, timeout=60)
                        self.assertEqual(completed.returncode, 0, completed.stderr.decode()[-3000:])
                if profile == 'expanded-product':
                    # Exercise both promised drivers through their public portable scope.
                    # The extracted owning test explicitly reports its sole recursion exclusion.
                    for driver, receipt in (('validate_product.py', 'summary.json'), ('validate_followup.py', 'receipt.json')):
                        output = directory/('driver-'+driver)
                        completed = subprocess.run([sys.executable, 'scripts/'+driver, '--portable-only', '--output', str(output)],
                                                   cwd=root, env=env, capture_output=True, timeout=180)
                        self.assertEqual(completed.returncode, 0, completed.stderr.decode()[-3000:]+completed.stdout.decode()[-3000:])
                        proof = json.loads((output/receipt).read_text())
                        self.assertEqual(proof['status'], 'PASS')
                        self.assertEqual(proof['scope'], 'portable_only')
                        self.assertTrue(proof['source_unchanged'])
                        self.assertEqual(proof['independent_qualification']['catalog'], 'BLOCKED')
                        log = output/('package-contract.log' if driver=='validate_product.py' else 'package-contract.stderr')
                        self.assertIn('skipped=1', log.read_text())
                        self.assertIn('sealed extraction:', log.read_text())
                # Repack the immutable extraction with its sealed membership; no Git dependency.
                package.build(directory / 'repacked.zip', profile, root=root)
                self.assertEqual(archive.read_bytes(), (directory / 'repacked.zip').read_bytes())
                (root/'src/lib.rs').write_text('changed')
                with self.assertRaisesRegex(ValueError, 'sealed extraction'):
                    package.build(directory/'tampered.zip',profile,root=root)
                self.assertFalse((directory/'tampered.zip').exists())

    def test_local_dependency_omission_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='pcap-package-closure-') as temporary:
            root = Path(temporary)
            (root/'src').mkdir()
            source = root/'src/lib.rs'
            source.write_text('pub mod required;')
            (root/'src/required.rs').write_text('pub fn works() {}')
            with self.assertRaisesRegex(ValueError, 'dependency missing'):
                package.check_closure(root, [(source, 'src/lib.rs')])
            package.check_closure(root, [(source, 'src/lib.rs'), (root/'src/required.rs', 'src/required.rs')])
            source = root/'caller.py'
            source.write_text('import helper')
            (root/'helper.py').write_text('value = 1')
            with self.assertRaisesRegex(ValueError, 'dependency missing'):
                package.check_closure(root, [(source, 'caller.py')])

    def test_competing_creators_are_preserved_at_exclusive_acquisition(self):
        from unittest import mock
        with tempfile.TemporaryDirectory(prefix='pcap-package-owner-') as temporary:
            directory = Path(temporary)
            source = directory/'source'
            source.mkdir()
            data = source/'README.md'
            data.write_text('source')
            output = directory/'archive.zip'
            open_original = Path.open
            def competitor(path, mode='r', *args, **kwargs):
                if path == output and mode == 'xb':
                    with open_original(path,'xb') as handle:handle.write(b'other-owner')
                return open_original(path,mode,*args,**kwargs)
            with mock.patch.object(package,'files',return_value=[(data,'README.md')]), mock.patch.object(Path,'open',competitor):
                with self.assertRaises(FileExistsError):package.build(output,root=source)
            self.assertEqual(output.read_bytes(),b'other-owner')
            output.unlink()
            checksum = output.with_suffix('.zip.sha256')
            def checksum_competitor(path, mode='r', *args, **kwargs):
                if path == checksum and mode == 'x':
                    with open_original(path,'xb') as handle:handle.write(b'other-checksum')
                return open_original(path,mode,*args,**kwargs)
            with mock.patch.object(package,'files',return_value=[(data,'README.md')]), mock.patch.object(Path,'open',checksum_competitor):
                with self.assertRaises(package.PublicationFailure) as failure:package.build(output,root=source)
            self.assertTrue(output.is_file())
            with zipfile.ZipFile(output) as retained:self.assertIsNone(retained.testzip())
            self.assertEqual(failure.exception.recovery['recovery'],'MANUAL_RECOVERY_REQUIRED')
            self.assertFalse(failure.exception.recovery['automatic_cleanup'])
            self.assertEqual(checksum.read_bytes(),b'other-checksum')
            # These exact temporary witnesses are owned by this test, after all writers finished.
            output.unlink()
            checksum.unlink()
            with mock.patch.object(package,'files',return_value=[(data,'README.md')]):
                package.build(output,root=source)
            self.assertTrue(output.is_file())
            self.assertTrue(checksum.read_text().startswith(hashlib.sha256(output.read_bytes()).hexdigest()))

    def test_failure_never_deletes_public_path_after_owner_replacement(self):
        from unittest import mock
        import os
        for replaced in ('archive', 'checksum'):
            with self.subTest(replaced=replaced), tempfile.TemporaryDirectory(prefix='pcap-package-aba-') as temporary:
                directory = Path(temporary)
                source = directory/'source'
                source.mkdir()
                data = source/'README.md'
                data.write_text('source')
                output = directory/'archive.zip'
                checksum = output.with_suffix('.zip.sha256')
                target = output if replaced=='archive' else checksum
                successor = directory/'successor'
                successor.write_bytes(b'competing-successor')
                original_assert = package.assert_owned
                cut_reached = False
                def replace_at_failure(path, identity):
                    nonlocal cut_reached
                    # Both publications have completed creation, immediately before
                    # final observations and failure handling. Replace at this cut.
                    if path==output and checksum.exists() and not cut_reached:
                        cut_reached = True
                        original_assert(target,identity if replaced=='archive' else package.file_identity(checksum.stat()))
                        os.replace(successor,target)
                        raise ValueError('injected post-publication failure')
                    return original_assert(path,identity)
                with mock.patch.object(package,'files',return_value=[(data,'README.md')]), mock.patch.object(package,'assert_owned',replace_at_failure), mock.patch.object(Path,'unlink',side_effect=AssertionError('public pathname deletion is forbidden')) as deletion:
                    with self.assertRaises(package.PublicationFailure) as failure:
                        package.build(output,root=source)
                self.assertTrue(cut_reached)
                deletion.assert_not_called()
                self.assertEqual(target.read_bytes(),b'competing-successor')
                self.assertEqual(failure.exception.recovery['status'],'FAIL')
                self.assertEqual(failure.exception.recovery['recovery'],'MANUAL_RECOVERY_REQUIRED')
                self.assertEqual(set(failure.exception.recovery['inspection_paths']),{str(output),str(checksum)})

    def test_creation_crossings_survive_identity_observation_failure(self):
        from unittest import mock
        for cut in ('archive', 'checksum'):
            for exception_type in (OSError, KeyboardInterrupt):
                with self.subTest(cut=cut,exception=exception_type.__name__), tempfile.TemporaryDirectory(prefix='pcap-package-creation-') as temporary:
                    directory = Path(temporary)
                    source = directory/'source'
                    source.mkdir()
                    data = source/'README.md'
                    data.write_text('source')
                    output = directory/'archive.zip'
                    checksum = output.with_suffix('.zip.sha256')
                    original = package.os.fstat
                    observations = 0
                    def fail_at_cut(descriptor):
                        nonlocal observations
                        observations += 1
                        if observations==(1 if cut=='archive' else 2):
                            raise exception_type('identity observation failed after exclusive creation')
                        return original(descriptor)
                    with mock.patch.object(package,'files',return_value=[(data,'README.md')]), mock.patch.object(package.os,'fstat',fail_at_cut), mock.patch.object(Path,'unlink',side_effect=AssertionError('public deletion is forbidden')) as deletion:
                        expected = package.PublicationFailure if exception_type is OSError else KeyboardInterrupt
                        with self.assertRaises(expected) as failure:package.build(output,root=source)
                    deletion.assert_not_called()
                    self.assertTrue(output.is_file())
                    self.assertEqual(checksum.is_file(),cut=='checksum')
                    if exception_type is OSError:recovery = failure.exception.recovery
                    else:
                        self.assertIs(type(failure.exception),KeyboardInterrupt)
                        recovery = json.loads(failure.exception.__notes__[-1])
                    self.assertEqual(recovery['status'],'FAIL')
                    self.assertEqual(recovery['recovery'],'MANUAL_RECOVERY_REQUIRED')
                    self.assertTrue(recovery['archive_creation_crossed'])
                    self.assertEqual(recovery['checksum_creation_crossed'],cut=='checksum')
                    self.assertEqual(recovery['cause_type'],exception_type.__name__)
                    self.assertFalse(recovery['automatic_cleanup'])

    def test_budget_and_existing_output_refuse_before_archive_creation(self):
        with tempfile.TemporaryDirectory(prefix='pcap-package-budget-') as temporary:
            output = Path(temporary) / 'source.zip'
            with self.assertRaisesRegex(ValueError, 'budget'):package.build(output, active_profiles()[0], max_source_bytes=1)
            self.assertFalse(output.exists())
            output.write_bytes(b'preserve')
            with self.assertRaisesRegex(ValueError, 'exists'):package.build(output,active_profiles()[0])
            self.assertEqual(output.read_bytes(), b'preserve')


if __name__ == '__main__':
    unittest.main()
