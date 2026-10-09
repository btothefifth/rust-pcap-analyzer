# Validation evidence

The follow-up receipt is
[`evidence/pr-followup-validation.json`](../evidence/pr-followup-validation.json).
Its `status` field records the validation disposition. Consult the receipt for
the exact source identity and inventory, product/root gate results, independent
coherence outcome, and bounded sample measurements. This document makes no
independent validation claim for a later source generation.

## Current candidate and source-bound samples

Use the receipt's exact source identity and file count when identifying the
candidate that was validated. Do not copy unconfirmed hashes or gate totals from
this page. The follow-up includes bounded source-bound public UPDATE, chronology, and RIB
prefix samples. Read their exact sizes, completeness, missing parent-source
identity, unsupported entries, and retained coverage gaps from the receipt.
These prefixes are samples only and do not establish coverage beyond the records
actually admitted.

## Hosted CI

The repository's hosted CI policy is Linux-only. At the historical `8aa92ad`
source, successful hosted runs exist for root/native, streaming, and product
qualification checks. A separate native attempt was cancelled before runner
acquisition; a product PR attempt reached the 45-minute job limit without step
results, while a same-source product push run succeeded. The
[checks for `8aa92ad`](https://github.com/btothefifth/rust-pcap-analyzer/commit/8aa92ad963b00bbe05fa4374a2f6fb29d40b57b8/checks)
are an immutable historical view.

The [PR checks page](https://github.com/btothefifth/rust-pcap-analyzer/pull/1/checks)
is a mutable current view. Check its reported SHA before using it. The local
receipt does not establish hosted CI for a later PR head. Windows and macOS
receipts below are historical local runs, not current hosted CI.

## Qualification limits

The bounded sample evidence does not qualify representative multi-collector,
multi-date, or real-corpus parity; complete normative protocol coverage;
sustained fuzzing; complete byte-copy behavior; or whole-process CPU, physical
RSS, or peak-memory bounds. Caller-clocked GR/LLGR assessment remains design
pending. Linux CI and local synthetic runs do not establish behavior on untested
platforms, source authenticity, or actual router state.

## Evidence index

| Receipt | Generation and disposition |
|---|---|
| [`pr-followup-validation.json`](../evidence/pr-followup-validation.json) | Current follow-up generation. Read its recorded status, identity, inventory, gate results, coherence, and sample scope from the receipt. |
| [`bgp-imported-analysis-feedback-validation.json`](../evidence/bgp-imported-analysis-feedback-validation.json) | Historical baseline at `8aa92ad`: source identity `9d827ffa7d86ef25d6e12636506c88e36c9fad796c4b032554781b18be40d2b8`, 741 files; 50 product and 14 root gates; 774 debug and 774 release product tests, and 294 debug and 294 release root tests; zero failures or ignored tests. Receipt bytes remain unchanged. |
| [`local-validation.json`](../evidence/local-validation.json), [`bgp-profile-review-validation.json`](../evidence/bgp-profile-review-validation.json), and [`bgp-stream-validation.json`](../evidence/bgp-stream-validation.json) | Earlier source-bound local runs. Their platform, selectors, and hosted status apply only to their recorded generations. |
| [`objectives-1-4-validation.json`](../evidence/objectives-1-4-validation.json), [`pr-feedback-validation.json`](../evidence/pr-feedback-validation.json), [`pr-feedback-round2-validation.json`](../evidence/pr-feedback-round2-validation.json), [`pr-feedback-round3-validation.json`](../evidence/pr-feedback-round3-validation.json), and [`pr-feedback-round4-validation.json`](../evidence/pr-feedback-round4-validation.json) | Earlier objective and PR-feedback generations; see each immutable receipt for its scope. |

Earlier receipts remain available as historical evidence. Do not combine their
gate counts or carry their PASS status to the current candidate.
