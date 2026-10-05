"""Cheap census of the declared CI/driver frontier; no native builds."""
import ast
import importlib.util
from pathlib import Path
import sys
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import validation_frontier as frontier


class ValidationFrontier(unittest.TestCase):
    def test_every_runtime_workspace_selected(self):
        # Independent census: every non-fuzz package with an isolated workspace.
        import os
        manifests = set()
        for directory, subdirs, files in os.walk(ROOT):
            subdirs[:] = [name for name in subdirs if name not in {'target', '.git', '.local-tooling', '.local-build'}]
            if 'Cargo.toml' in files:manifests.add((Path(directory)/'Cargo.toml').relative_to(ROOT).as_posix())
        manifests -= set(frontier.EXCLUDED_WORKSPACES)
        self.assertEqual(manifests, {manifest for _, manifest in frontier.WORKSPACES})
        for _, manifest in frontier.WORKSPACES:
            self.assertIn('workspace', tomllib.loads((ROOT / manifest).read_text()))

    def test_all_declared_feature_profiles_selected_in_isolation(self):
        features = tomllib.loads((ROOT / 'product/Cargo.toml').read_text())['features']
        self.assertEqual(set(frontier.FEATURE_PROFILES), {''} | (set(features) - {'default'}))
        rows = {name: command for name, command in frontier.native_commands() if name.startswith('features-')}
        self.assertEqual(len(rows), len(features))
        for command in rows.values():
            self.assertIn('--no-default-features', command)

    def test_independent_python_populations_are_nonempty_and_reachable(self):
        vectors = sorted((ROOT / 'product/tests').glob('*vectors.py'))
        self.assertEqual(len(vectors), 10)
        self.assertEqual(sum(count_tests(path) for path in vectors), 68)
        self.assertEqual(count_tests(ROOT / 'scripts/test_semantic_tools.py'), 15)
        self.assertEqual(count_tests(ROOT / 'tools/depth/test_opcua_crypto.py'), 3)
        rows = dict(frontier.portable_commands(sys.executable))
        self.assertEqual(rows['bgp-vectors'][-3:], ['-p', '*vectors.py', '-v'])
        self.assertIn('tools.depth.test_opcua_crypto', rows['opcua-transforms'])
        for path in ('scripts/test_semantic_tools.py', 'scripts/test_package_contract.py'):
            self.assertTrue((ROOT / path).is_file())

    def test_product_workflow_selects_dependency_frontier_and_linux_ci(self):
        text = (ROOT / '.github/workflows/product-qualification.yml').read_text()
        for event in ('push:', 'pull_request:'):
            block = text.split('  ' + event, 1)[1].split('permissions:', 1)[0]
            if event == 'push:':block = block.split('  pull_request:', 1)[0]
            for path in ('src/**', 'streaming/**', 'history/**', 'history-app/**',
                         'fixtures/**', 'scripts/**', 'Cargo.toml', 'rust-toolchain.toml'):
                self.assertIn("'" + path + "'", block)
        for workflow, runner in (('ci.yml', 'ubuntu-latest'),
                                 ('streaming-evidence.yml', 'ubuntu-latest'),
                                 ('hardening.yml', 'ubuntu-latest'),
                                 ('product-qualification.yml', 'ubuntu-22.04')):
            carrier = (ROOT / '.github/workflows' / workflow).read_text()
            self.assertIn('        os: [' + runner + ']\n', carrier)
            self.assertIn('    runs-on: ${{ matrix.os }}\n', carrier)
            self.assertNotIn('windows', carrier.lower())
            self.assertNotIn('macos', carrier.lower())
        self.assertIn('python scripts/validate_product.py', text)
        self.assertIn('CARGO_TARGET_DIR:', text)
        # The colon+space in --only-binary=:all: cannot be a plain YAML scalar.
        # Keep this exact shell command in a block scalar without adding a YAML
        # dependency to the portable test runtime. Parse the whole workflow with
        # the integration environment's YAML parser whenever this carrier changes.
        command = 'python -m pip install --only-binary=:all: -r scripts/requirements-qualification.txt'
        self.assertIn('        run: |\n          '+command+'\n',text)
        self.assertEqual(__import__('shlex').split(command),['python','-m','pip','install',
                         '--only-binary=:all:','-r','scripts/requirements-qualification.txt'])

    def test_source_identity_preserves_untracked_sources_and_prunes_tooling(self):
        import tempfile
        spec = importlib.util.spec_from_file_location('baseline_validator', ROOT/'scripts/validate.py')
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        with tempfile.TemporaryDirectory(prefix='pcap-source-identity-') as temporary:
            root = Path(temporary)
            (root/'src').mkdir()
            (root/'src/lib.rs').write_text('original')
            validator.ROOT = root
            before = validator.source_identity()
            snapshot = frontier.source_snapshot(root)
            for name in ('.local-tooling', '.local-build', 'evidence', 'target'):
                (root/name).mkdir()
                (root/name/'growth.bin').write_bytes(b'x'*1024)
            self.assertEqual(before, validator.source_identity())
            self.assertEqual(snapshot, frontier.source_snapshot(root))
            (root/'untracked.py').write_text('source')
            self.assertNotEqual(before, validator.source_identity())
            self.assertNotEqual(snapshot, frontier.source_snapshot(root))
            after = validator.source_identity()
            (root/'src/lib.rs').write_text('changed')
            self.assertNotEqual(after, validator.source_identity())

    def test_nested_evidence_code_is_bound_while_root_receipts_are_excluded(self):
        import tempfile
        spec = importlib.util.spec_from_file_location('nested_evidence_validator', ROOT/'scripts/validate.py')
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        with tempfile.TemporaryDirectory(prefix='pcap-source-boundary-') as temporary:
            root = Path(temporary)
            nested = root/'tools/evidence'
            nested.mkdir(parents=True)
            source = nested/'reader.py'
            source.write_bytes(b'original source')
            validator.ROOT = root
            before = validator.source_identity()
            snapshot = frontier.source_snapshot(root)
            self.assertEqual(set(snapshot), {'tools/evidence/reader.py'})
            source.write_bytes(b'changed source')
            self.assertNotEqual(before, validator.source_identity())
            self.assertNotEqual(snapshot, frontier.source_snapshot(root))
            after = validator.source_identity()
            after_snapshot = frontier.source_snapshot(root)
            (root/'evidence').mkdir()
            (root/'evidence/receipt.json').write_bytes(b'generated receipt')
            self.assertEqual(after, validator.source_identity())
            self.assertEqual(after_snapshot, frontier.source_snapshot(root))

    def test_red_portable_preflight_suppresses_native_in_both_drivers(self):
        from owned_process import Result
        import tempfile
        import contextlib
        import io
        from unittest import mock
        import validate_product
        import validate_followup
        for driver in (validate_product, validate_followup):
            observed = []
            def execute(command, **kwargs):
                observed.append(command)
                return Result(1 if 'scripts/test_package_contract.py' in command else 0,None,b'',b'',0,0)
            with tempfile.TemporaryDirectory(prefix='pcap-red-preflight-') as temporary:
                output = Path(temporary)/'receipt'
                terminal = io.StringIO()
                with contextlib.redirect_stdout(terminal), mock.patch.object(driver.platform,'platform',return_value='test-platform'), mock.patch.object(driver,'run_owned',execute), mock.patch.object(driver.shutil,'which',side_effect=lambda name:'/unexecuted/'+name):
                    result = driver.main(['--output',str(output)]) if driver is validate_product else driver.run(output)
                self.assertEqual(result,1)
                self.assertTrue(any('scripts/test_package_contract.py' in command for command in observed))
                self.assertFalse(any(Path(command[0]).name in {'cargo','cc','cl'} for command in observed))
                self.assertFalse(any('scripts/validate_semantic_product.py' in command or 'scripts/check_linked_abi.py' in command for command in observed))
                if driver is validate_product:
                    failures = __import__('json').loads(terminal.getvalue())['failed_gates']
                    gate = next(row for row in failures if row['name']=='package-contract')
                    self.assertEqual((gate['status'],gate['returncode'],gate['log']),('FAIL',1,'package-contract.log'))

    def test_native_semantic_gate_uses_actual_root_all_target_artifact(self):
        import os
        import tempfile
        from unittest import mock
        from owned_process import Result
        import contextlib
        import io
        import validate_product
        import validate_followup
        with tempfile.TemporaryDirectory(prefix='pcap-native-semantic-gate-') as temporary:
            shared=Path(temporary)/'target'
            for index,driver in enumerate((validate_product,validate_followup)):
                commands=[]
                def execute(argv,**kwargs):
                    commands.append(argv)
                    return Result(0,None,b'',b'',0,0)
                output=Path(temporary)/str(index)
                with mock.patch.dict(os.environ,{'CARGO_TARGET_DIR':str(shared)}), mock.patch.object(driver,'run_owned',execute), mock.patch.object(driver.shutil,'which',side_effect=lambda name:'/unused/'+name), contextlib.redirect_stdout(io.StringIO()):
                    result=driver.main(['--output',str(output)]) if driver is validate_product else driver.run(output)
                # Fake live-denial exit 0 must remain adverse (expected 3).
                self.assertEqual(result,1 if sys.platform.startswith('linux') else 0)
                cases=next(argv for argv in commands if 'scripts/semantic_case_runner.py' in argv)
                suffix='.exe' if os.name=='nt' else ''
                self.assertEqual(cases[cases.index('--probe')+1],str(shared/'release/examples'/('semantic_probe'+suffix)))
                root_build=next(argv for argv in commands if argv[1:4]==['build','--manifest-path','Cargo.toml'])
                self.assertIn('--all-targets',root_build)
                self.assertLess(commands.index(root_build),commands.index(cases))

    def test_interrupted_driver_persists_adverse_attempt_and_logs(self):
        import tempfile
        import contextlib
        import io
        import json
        from unittest import mock
        import validate_product
        import validate_followup
        for driver,receipt_name,key in ((validate_product,'summary.json','results'),(validate_followup,'receipt.json','gates')):
            with tempfile.TemporaryDirectory(prefix='pcap-interrupted-validator-') as temporary:
                output=Path(temporary)/'receipt'
                def interrupted(argv,**kwargs):
                    kwargs['stdout'].write(b'attempt began\n')
                    raise KeyboardInterrupt()
                with mock.patch.object(driver,'run_owned',interrupted),contextlib.redirect_stdout(io.StringIO()):
                    result=driver.main(['--output',str(output)]) if driver is validate_product else driver.run(output)
                self.assertEqual(result,1)
                report=json.loads((output/receipt_name).read_text())
                self.assertEqual(report['status'],'FAIL')
                attempts=[row for row in report[key] if row['status']=='FAIL']
                self.assertEqual(len(attempts),1)
                attempt=attempts[0]
                log=attempt.get('log',attempt.get('stdout'))
                self.assertEqual((output/log).read_bytes(),b'attempt began\n')

    def test_terminal_failure_tails_are_bounded_and_exclude_passing_logs(self):
        import tempfile
        import validate_product
        with tempfile.TemporaryDirectory(prefix='pcap-failure-tails-') as temporary:
            root = Path(temporary)
            (root/'failed.log').write_bytes(b'x'*30_000+b'final failure')
            (root/'pass.log').write_bytes(b'passing output')
            rows = [{'name':str(number),'status':'FAIL','log':'failed.log'} for number in range(7)]
            rows += [{'name':'passing','status':'PASS','log':'pass.log'},
                     {'name':'missing','status':'BLOCKED','reason':'runtime unavailable'}]
            issues = validate_product.failure_diagnostics(rows,root)
            self.assertEqual(len(issues),8)
            self.assertLessEqual(sum(len(row.get('log_tail','').encode()) for row in issues),8000)
            self.assertTrue(issues[0]['log_tail'].endswith('final failure'))
            self.assertEqual(issues[-1]['reason'],'runtime unavailable')

    def test_target_resolution_and_mutation_copy_preserve_runtime_origin(self):
        import os
        import tempfile
        from unittest import mock
        import mutation_check
        import contextlib
        import io
        with tempfile.TemporaryDirectory(prefix='pcap-native-target-') as temporary:
            root = Path(temporary)/'repo'
            root.mkdir()
            with mock.patch.dict(os.environ,{'CARGO_TARGET_DIR':'shared-target'}):
                self.assertEqual(frontier.native_artifact(root,'Cargo.toml','pcap-evidence',profile='debug'),root/'shared-target/debug/pcap-evidence')
            configured = Path(temporary)/'configured-target'
            with mock.patch.dict(os.environ,{'CARGO_TARGET_DIR':str(configured)}):
                self.assertEqual(frontier.native_artifact(root,'Cargo.toml','pcap-evidence',profile='debug'),configured/'debug/pcap-evidence')
                with mock.patch.object(mutation_check.subprocess,'run',return_value=None) as child:
                    mutation_check.run(root,'capture_contract','exact_test')
                self.assertEqual(child.call_args.kwargs['env']['CARGO_TARGET_DIR'],str(root.parent/'mutation-target'))
            # Inspect the actual copy ignore callback at the owning copytree boundary.
            with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(mutation_check.shutil,'which',return_value='/unused/tool'), mock.patch.object(mutation_check.shutil,'copytree') as copied, mock.patch.object(mutation_check,'MUTANTS',[]):
                self.assertEqual(mutation_check.main(),0)
            ignored = copied.call_args.kwargs['ignore'](str(root),['src','.local-tooling','.local-build','target','.git'])
            self.assertEqual(set(ignored),{'.local-tooling','.local-build','target','.git'})

    def test_missing_configured_cli_is_blocked_without_stale_fallback(self):
        import contextlib
        import io
        import os
        import tempfile
        from unittest import mock
        import check_cli
        with tempfile.TemporaryDirectory(prefix='pcap-cli-origin-') as temporary:
            root = Path(temporary)/'repo'
            filename = 'pcap-evidence.exe' if os.name=='nt' else 'pcap-evidence'
            stale = root/'target/debug'/filename
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b'stale must never execute')
            configured = Path(temporary)/'configured'
            output = io.StringIO()
            with mock.patch.dict(os.environ,{'CARGO_TARGET_DIR':str(configured)}), mock.patch.object(check_cli,'__file__',str(root/'scripts/check_cli.py')), mock.patch.object(sys,'argv',['check_cli.py']), mock.patch.object(check_cli,'check') as native, contextlib.redirect_stdout(output):
                self.assertEqual(check_cli.main(),2)
            native.assert_not_called()
            report = __import__('json').loads(output.getvalue())
            self.assertEqual(report['binary'],str((configured/'debug'/filename).resolve()))
            self.assertEqual(report['status'],'BLOCKED')

    def test_manifest_paths_close_over_local_dependencies(self):
        manifests = {manifest for _, manifest in frontier.WORKSPACES}
        for _, manifest in frontier.WORKSPACES:
            document = tomllib.loads((ROOT / manifest).read_text())
            for dependency in document.get('dependencies', {}).values():
                if isinstance(dependency, dict) and 'path' in dependency:
                    target = ((ROOT / manifest).parent / dependency['path'] / 'Cargo.toml').resolve().relative_to(ROOT)
                    self.assertIn(target.as_posix(), manifests)


def count_tests(path):
    tree = ast.parse(path.read_text())
    return sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_')
               for node in ast.walk(tree))


if __name__ == '__main__':
    unittest.main()
