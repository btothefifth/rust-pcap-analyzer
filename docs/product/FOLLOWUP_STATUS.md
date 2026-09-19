# Follow-up implementation status

Baseline: `5225e9aa794b91d5d0fdf6d8d313a957d6a337f1`.
Controlling request: `IMPLEMENTATION_HANDOFF.md`; original snapshot/streaming
contracts remain in force. This is a source candidate, not release promotion.

| Feedback area | Delivered change | Exact remaining boundary |
|---|---|---|
| Rust-owned TCP history | New `history/` workspace: source-bound journal, automatic scoped generation/epoch hypotheses, bounded tuple eviction/reload, source spans, external interval sort, late conflicts, quotas, cancellation, replay verification and prefix recovery | Integrated Windows format, debug/release test, example-build and Clippy gates pass; unlimited IP/application history, arbitrary endpoint truth and O(1) resume are not implemented |
| Deeper protocol semantics | BACnet services and CIP path/status fields wired into `Protocol::decode` | Partial subsets only; no normative edition approval, DNP3 object completion or complete MMS stack |
| First divergence | Comparison v2 considers earlier uncovered fields in the same layer and partial current-layer coverage | Not complete adapters for every protocol; no consensus or correctness winner |
| Old research artifacts | Exact v1 comparison algorithm retained; bundle verification dispatches by recorded report schema | Producer authentication remains outside a hash-only bundle |
| Investigation GUI | New coverage distinctions visible in Research; existing interface uses hardened real backend | Native-browser qualification harness included; no new packaged desktop installer or history view |
| Worker lifecycle | Persistent cancellation, direct-child termination, operation timeout, sampled logical disk budget, durable atomic state retries, bounded diagnostic read, closed SQLite/pipe resources, correct committed-prefix accounting | No claim of a kernel quota, adversarial local-owner sandbox or complete Windows descendant-job containment |
| C ABI | Real linked consumer harness: null/limits, one-shot state, no-clobber small buffers, exact output, 100 sequential/concurrent lifecycle cycles | Rust FFI format/test/release/Clippy and library-build gates pass; linked C execution remains blocked on this Windows host because no C compiler/native ABI setup is available |
| Qualification | Independent history-format verifier; Rust tests/fuzz target; portable regressions; real native-browser and linked-ABI gate scripts; guarded ZIP installer | Fresh integrated follow-up receipt: 25 gates PASS, linked ABI BLOCKED, and six independent classes NOT_RUN; sustained fuzz, operational corpus, 50–500 GiB measurement, actual NIC capture and Windows/Linux installers remain unqualified |

Fresh integrated Windows evidence now covers the new Rust modules: the follow-up
driver records 25 PASS gates across Python, GUI models, catalog maintenance, root,
streaming, product, FFI and history workspaces. The separate product qualification
run also passes its portable suite, native feature matrix and baseline regression
gate. These are local engineering receipts, not release promotion or proof of
normative protocol correctness.

## Preserved architecture

No dependency from the core parser to external analyzers, SQLite, GUI frameworks,
network services or third-party protocol libraries is added. Existing Python SQLite
and browser tooling stay above the Rust evidence boundary. Fuzz dependencies stay
in an explicitly separate development workspace. No private reference document,
internal product name or private corpus is incorporated into this public code.

The older reference designs' useful objectives (offline safe Rust, layered parsing,
feature profiles, machine-readable output, FFI/live adapters and conformance work)
remain design inputs. Their former GUI, storage and breadth exclusions do not limit
this product. Their broad performance and completeness claims are not inherited.

## Required next native action

The integrated checkout has completed the new native matrices and repaired the
validator/fixture portability defects found during that run. The next required
engineering action is a real linked C-ABI run on a host with a compatible C
toolchain, followed by the independent browser, sustained-fuzz, large-capture,
normative-protocol and installation gates. Fix compiler, borrow, lint or semantic
failures without relaxing assertions; preserve fresh receipts during each gate.

Commands and promotion conditions: `FOLLOWUP_QUALIFICATION.md`.
History contract: `../history/CONTRACT.md`. Protocol depth: `SERVICE_FIELDS.md`.
