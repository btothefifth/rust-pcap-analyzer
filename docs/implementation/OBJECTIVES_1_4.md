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

## PR feedback repair contract

Generation O14-F1 addresses repository-owner review
[5402947055](https://github.com/btothefifth/rust-pcap-analyzer/pull/1#pullrequestreview-5402947055)
and inline comment
[4175032348](https://github.com/btothefifth/rust-pcap-analyzer/pull/1#discussion_r4175032348)
against exact baseline `074952705e48fa414e4cccaf1ede3ceb162b24d1`.
The existing O14-1 receipt remains evidence for its recorded generation;
changed-source proof must be recorded separately before publication.

| Finding / owning seam | Required and preserved outcome | Forbidden outcome / regression boundary |
| --- | --- | --- |
| P1 TABLE_DUMP_V2 series / imported-BGP lane | RFC 8050 RIB ADD-PATH subtypes 8–12 retain the current peer table for a later supported family; unsupported payloads remain opaque and retain exact provenance. Table replacement and unrelated-record invalidation remain effective. | An opaque ADD-PATH record erases valid peer context, or an unrelated series borrows stale peer identity. Test independently encoded mixed series through the parser and source-bound replay where applicable. |
| P2 imported ROUTE-REFRESH / semantic lane | Ordinary subtype 0 remains decoded in its supported Established context. Enhanced subtypes 1/2 require the opposite-direction receiver's valid capability-70 advertisement as evidence for sender layout; no receiver processing or endpoint negotiation is inferred. | Subtypes 3/255 receive decoded enhanced meaning, or missing/stale/reported capability context authorizes it. Exercise actual wire OPENs, reset boundaries and the shared BMP decoder frontier. |
| P2 per-input association / policy lane | Each verified source receives its own relationship option; the existing option applies to the first source, and an absent second option remains unknown. Query and policy behavior retain their own single-input contract. | One input's relationship overrides the other, or a second-input flag silently applies outside association. Test asymmetric source replay through the real persisted CLI and final association output. |

Root owns integration, Cargo scheduling, evidence reconciliation and publication;
each implementation lane owns disjoint source/tests/contracts. Independent
source review and assembled coherence review challenge the finite affected
frontier. Tests are staged before repair to retain intentional baseline failures;
only affected evidence is invalidated until the stabilized aggregate gate.
These are synchronous offline transformations: no external endpoint effect,
lease, asynchronous retry or deployment is introduced. Atomic replay/output and
source-store preservation remain existing acceptance boundaries.

The non-blocking reducer scale finding remains an explicit production-scale
requirement. This repair does not substitute a broad reducer rewrite for the
three correctness fixes. Its actual full-state cloning and debug-accounting
cost must be described in the owning resource contract, with incremental or
transactional replacement and measured parity/cost as the future closure gate.

### Prevention gaps and finite sibling dispositions

The peer-table tests previously stopped at an opaque ADD-PATH record; they
never exercised its following supported RIB consumer. Four mixed-series tests
now cover every registered ADD-PATH RIB subtype, ordinary IPv4/IPv6 neighbors,
table replacement, unrelated boundaries and malformed atomic rejection.
Payload dispatch and normalization admission remain unchanged.

Imported ROUTE-REFRESH admission previously checked length and Established
state without registry or capability evidence. Independently encoded sealed
replays now distinguish subtype, receiver direction, valid/missing/duplicate
OPENs and generation reset. Captured refresh metadata remains non-authoritative;
BMP's UPDATE-only Route Monitoring guard remains effective before reported OPEN
context can qualify type 5. Quarantine follows the existing scoped continuity
gap consumer; decoded and ignored refreshes invent no route action or EOR.

Association reused a single options value at two source loads. The fix keeps
those loads independent; single-input query/policy/replay/state/export and
import callers preserve their existing scope. Regression oracles inspect
effective LOCAL_PREF and exact imported attribute occurrences, including
MRT/BMP mixed pairs, default unknown and captured override rejection.

The staged proof also exposed test-owner defects before broad validation:
a Rust JSON helper reference mismatch, a packet-span lookup where imported
evidence uses occurrence carriers, and a display-case assertion against the
canonical lower-case JSON error code. These failed attempts are retained
separately from intentional production go-red results. The repaired controls
use the real serialized carriers and valid command prerequisites; production
semantics were not weakened to satisfy those tests.

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
| Integrated coherence | assembled source accepted; final receipt governs later narrow amendments | Independent review of assembled diff/callers, cross-lane contracts, evidence and finding dispositions; separate narrow review of final CI repairs. |
| Publication | implementation checkpoint published; final receipt governs validation | Implementation commit `a3764315fb2aac0df127a12df8fcb4b684bf2559` is on PR #1. Later validation and CI repairs are recorded by the final receipt; no merge or release. |

No concurrent writers share a file without an explicit accessor-only grant or
handover. Root classifies review findings and owns acceptance/publication.
One isolated pinned toolchain and shared build target avoid copied environments;
native jobs are scheduled centrally. Disposable captures/witnesses stay tiny.
Storage is measured before expensive operations and monitored with headroom.
Rollback is a bounded revert of the affected implementation increment; source
stores and original captures are never silently deleted or rewritten.

## Test evidence and remaining qualification

The implementation checkpoint is published for review. The O14-1
same-generation selector, narrow repair and resource receipt is
[`evidence/objectives-1-4-validation.json`](../../evidence/objectives-1-4-validation.json).
Its source inventory binds the code and documentation; generated evidence is
excluded from that source inventory to avoid a self-hash cycle. A `PENDING`
receipt is never a passing result. Final hosted CI is tied separately to the
published commit in PR #1; older hosted runs cannot validate this candidate.

The subsequent O14-F1 PR feedback generation uses
[`evidence/pr-feedback-validation.json`](../../evidence/pr-feedback-validation.json)
for its own source-bound focused failures, repaired selectors, independent
review, aggregate validation and resource observations. It does not relabel
the earlier receipt or immutable campaign as proof of changed source.

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
