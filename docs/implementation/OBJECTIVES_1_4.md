# Objectives 1–4 implementation and evidence ledger

## Decision and scope

Generation O14-1, authorized 2026-10-03 by the repository owner. Starting
revision: `b66e624f17e02975d5b74e0cd4e8c305a65bd4b4` on
`review/repository-baseline-2026-10-02`, pull request #1 to `main`.
The [repository review](REPOSITORY_REVIEW_2026-10-02.md) owns the baseline
findings; [BGP completion](../product/BGP_COMPLETION.md) owns protocol intent.
This ledger records implementation, independent review, integration, tests,
and delivery for the owner's selected objectives, without replacing those
contracts or historical receipts.

WISDOM routing: substantial coupled protocol/storage work, with delegated
implementation, independent source and integration review, and one root
integration/publication owner. Current verified WISDOM source SHA-256:
`df786b013b91cfa88b8b1d8ca5e88499a5682af93a4525ba14f8bbee468085b1`.
Agents load the applicable verified modules before their protected actions.
Workflow5 resolves implementation to Sol 6.1 High, bounded work to Luna Max,
and independent review to Sol 6.1 XHigh; the selected root is preserved.

Hard constraints: total local project storage stays strictly below
50,000,000,000 bytes; source evidence is preserved; existing offline and
no-overwrite boundaries remain; source/checkpoint/session/generation/peer/
path/clock/trust identities cannot collapse; missing evidence cannot become
negotiation, installation, reachability, authenticity, or policy authority.
No merge, release, router mutation, active peering, or real NIC capture is
authorized by this implementation task.

## System, criteria, and owning seams

| Criterion | Production seam / owner | Acceptance and cheapest falsifier |
| --- | --- | --- |
| O14-A1 retained storage | Desktop request -> workspace admission -> worker/research/export -> retained files; storage lane | Existing nested/old/staging data and concurrent reservations charged; valid writer progresses, over-budget sibling rejected; failed writes and actual worker exit preserve accounting. Logical accounting is not a filesystem quota. |
| O14-A2 bounded listing | Research publication -> bounded index -> paginated receipt reader; storage lane | Deterministic bounded page; malformed off-page receipt unexamined; bounded census/cardinality and restart behavior explicit. |
| O14-A3 frontier and package | Source/dependency inventory -> exact selectors/package membership -> native/portable consumers; validation lane | Six runtime workspaces, declared feature profiles, independent selectors and platform exclusions; fresh extraction runs promised entrypoints; stale receipts never become fresh PASS. |
| O14-A4 malformed CLI input | Generation argument -> byte parser -> history-app CLI; identifier lane | Valid ASCII hex accepted; wrong length, nonhex, and 64-byte UTF-8 counterexample return normal errors without unwind. |
| O14-A5 operator truth | Current code/contracts -> support matrix/navigation; documentation lane | Delivered behavior and residuals reconciled; historical receipts remain historical; unexecuted qualification stays open. |
| O14-B1 imported state | Complete MRT records -> shared decoder -> canonical Adj-RIB-In -> sealed fresh replay/query/export; imported-BGP lane | Announce/replace/withdraw and scoped reset/gap/teardown; sibling unchanged; file order preserved under regressing clocks; malformed complete records retain exact opaque/quarantine evidence; truncated outer container fails closed. |
| O14-B2 semantic identity | Verified occurrences -> AS4 reconstruction/identity -> independent state consumer; semantic lane | RFC-derived AS4 transformation and versioned identity compatibility; equivalent supported capture/import meaning with distinct provenance; unsupported or unresolved meaning remains incomplete. |
| O14-C persisted consumers | Verified source stores + explicit bounded profile/filters/clock mapping -> policy/query/association CLI; policy lane | Fresh-process results, deterministic traces, reached missing input unresolved, strict profile rejection, source non-collapse, corruption/no-overwrite/budget rejection. |
| O14-D BMP | Bounded BMP records -> shared BGP decoder/state -> sealed store -> ordinary CLI; BMP lane | Primary-spec framing/vectors; exact original ranges; supported reported events and opaque neighbors; scoped coverage/generation transitions; corrupt/restart/one-over and cross-source partition witnesses. |

The nearest harmful inverses are storage growth outside admission, reading past
a page, missing a dependency-triggered test, publishing an incomplete package,
panicking before CLI error handling, resurrecting a route across reset, giving
incomplete semantics a fingerprint, inventing a policy winner, and treating an
unsupported BMP partition as accepted route meaning. Each owning lane must
prove both valid continuation and suppression of its inverse through the real
consumer. A concrete counterexample reopens the owning seam only.

## Execution graph

| Lane | State | Owned changes / dependencies |
| --- | --- | --- |
| Storage | source, lifecycle fixtures and desktop integration accepted | Desktop admission, worker lifecycle and research pagination; independent of BGP. |
| Validation/package | source accepted; core/expanded extraction passed; final receipt governs aggregate gates | Workflows, selector drivers, package profiles; central isolated Rust provision; final matrix depends on integrated runtime changes. |
| Identifier | source accepted; both native CLI targets passed | Both generation parsers and six real CLI cases each. |
| Documentation | frozen current-candidate reconciliation | Baseline navigation/matrix reconciliation; final new-feature status waits for evidence. |
| Imported BGP | final closure/RIB/output source accepted; focused native targets passed | MRT decoder/store/Adj-RIB-In integration; shared identity consumer supplied by semantic lane. |
| Semantic identity | final v2 source closure/AS4 source accepted; ten parity cases passed | Versioned atomic/AS4 identity and consumer validation; coordinates imported projections and shared BMP parser exposure. |
| Policy/association | final occurrence/stage/disposition/budget source accepted; final ten-case receipt governs execution | Strict persisted profile, filters, verified typed stores and CLI; depends on final imported/BMP hooks. |
| BMP | replacement source accepted; twenty native cases passed; final receipt governs execution | New adapter/store/shim; depends on shared decoder and accepted normalized identities; CLI integration owned by policy lane. |
| Source review | all final frozen lane generations accepted independently | Separate Sol XHigh reviewers, frozen lane generations. |
| Integrated coherence | pending | Actual assembled diff/callers, cross-lane contracts, evidence and finding dispositions; distinct from integrator checks. |
| Publication | pending | Root commits/pushes to PR #1 after required checks; exact-head hosted evidence recorded separately. |

No concurrent writers share a file without an explicit accessor-only grant or
handover. Root classifies review findings and owns acceptance/publication.
One isolated pinned toolchain and shared build target avoid copied environments;
native jobs are scheduled centrally. Disposable captures/witnesses stay tiny.
Storage is measured before expensive operations and monitored with headroom.
Rollback is a bounded revert of the affected implementation increment; source
stores and original captures are never silently deleted or rewritten.

## Test evidence and remaining qualification

This ledger is a pre-publication checkpoint. The authoritative final same-generation
selector and resource receipt is
[`evidence/objectives-1-4-validation.json`](../../evidence/objectives-1-4-validation.json).
Its source inventory binds the code and documentation; generated evidence is
excluded from that source inventory to avoid a self-hash cycle. A `PENDING`
receipt is never a passing result. Final hosted CI is tied separately to the
published commit in PR #1; older hosted runs cannot validate this candidate.

Already executed composable observations are the desktop suite (228 tests),
JavaScript models (11 tests), and both generation CLI targets (six tests each).
The final focused MRT generation passed 12 parser, 19 BGP4MP replay and
23 scaling cases. The semantic parity target passed ten cases, BMP passed twenty,
and the repaired older ASN fixtures passed 23 phase1, 37 producer and 35 state
cases. Policy canonical parsing/exact limits passed thirty cases; all six
property controls passed after the renderer correction. Independent review caught and repaired
archive cleanup ownership/creation reporting, cancellation reservation release,
MRT/BMP output allocation before admission, BMP EOR duplication and malformed
Termination continuity, imported occurrence completeness and AS4 disposition
relabeling, persisted lifetime/stage grouping and symmetric current-candidate
association, canonical policy array serialization, and complete output structural
limits. Final aggregate execution is governed by the receipt rather than inferred
from these composable component results.

The finite generation-2 campaign in
[BGP_PROFILE_EVIDENCE.md](../product/BGP_PROFILE_EVIDENCE.md) is separately bound to
its immutable example executable: 982 completed cycles and 47,136 negative wire
cases in 60,050 ms, with 1,740 logical journal file bytes at peak and exact scratch
cleanup. The time limit is checked between iterations; the final iteration
overran by 50 ms. Physical peak allocation was not established. Later source
changes do not relabel that receipt as validation of a new executable.

The isolated Rust 1.85.1 toolchain and shared incremental-disabled target remain
inside this checkout. Project occupancy was 0.98 GB before the final release
frontier, far below the strict 50 GB ceiling; the final receipt records subsequent
observed occupancy. Packaging witnesses use tiny disposable source archives and
extractions, never copied toolchains or capture collections.

Full declared-profile qualification additionally needs sustained fuzz coverage,
lawful real-corpus disagreement adjudication, measured scale/RSS/performance,
and normative/security review. Those dimensions retain explicit unqualified
status until their representative gates are actually executed; fixture counts,
code registration, parser agreement, and a green unrelated CI suite cannot
close them. Optional development oracle/fuzz graphs with unreviewed dependency
acquisition remain explicitly excluded from locked runtime-workspace claims.
