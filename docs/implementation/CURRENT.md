# Additive product candidate

Current product scope and limitations: [../product/STATUS.md](../product/STATUS.md).
Qualification commands: [../product/VALIDATION.md](../product/VALIDATION.md).
Design reconciliation and the next implementing-agent package:
[../product/IMPLEMENTATION_HANDOFF.md](../product/IMPLEMENTATION_HANDOFF.md).
The current integration passes the local Rust/Python/JavaScript qualification
matrix described in `STATUS.md`, plus the follow-up root, streaming, product,
FFI and history matrices. C compiler/link execution, Linux live capture,
browser-to-native, full-history, fuzz, scale and normative protocol gates remain
open.

## Follow-up source candidate (not a release promotion)

The additional Rust history crate, deeper service fields, comparison-v2 policy,
worker lifecycle hardening, and qualification harnesses are described in
[../product/FOLLOWUP_STATUS.md](../product/FOLLOWUP_STATUS.md). Their source was
authored against commit `5225e9aa794b91d5d0fdf6d8d313a957d6a337f1`.
The integrated Windows checkout now has fresh native receipts for these Rust
sources and all six checked-in history fixtures pass the release CLI, semantic
replay, independent journal verification and range-query exercise. The candidate
is still not a release promotion: retain fresh receipts and complete the open
platform/scale/fuzz/protocol gates before promoting it.
