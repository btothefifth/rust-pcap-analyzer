# Main audit — 2026-11-10

Reviewed main at `afc5d6d8423e8bf153ff03788dda555c803a9af5`, after PRs #2
and #3 merged. The initial inventory contained 765 tracked paths. Source review
covered capture/container parsing, provenance, wire reconstruction, streaming,
protocol depth, BGP stores and replay, retained history, research, desktop input,
and FFI boundaries. An independent reviewer examined the same frozen baseline.

## Confirmed defects and repairs

| Defect | Owning repair | Regression and preserved behavior |
| --- | --- | --- |
| An unfinished COTP TSDU survived a connection control and joined later data | Continuation rejects the boundary and requires an explicit cut. `CotpSession` discards only the affected scope on connection controls or malformed TPDUs | Both consumers exercise old-fragment/control/new-fragment sequences. Independent scopes, ordinary fragmentation, expedited data and retryable capacity rejection retain their contracts |
| A rejected CIP Multiple Service Packet response required a success body and appeared truncated | Decode the service table for requests, successful responses and embedded-service-error responses. Preserve other error bodies as opaque data | Empty rejection and additional status reach ENIP/CPF decoding. Success and embedded failures retain their child table. Truncated success bodies reject |
| HTTP accepted an empty request target or target containing whitespace/control bytes | Validate the target before constructing metadata | Invalid targets reject. Origin, absolute, authority and asterisk forms remain accepted |
| A non-ASCII desktop Authorization header raised an uncaught `TypeError` | Reject non-ASCII input before the constant-time comparison | A real loopback request returns 403, followed by a successful authorized request |
| Malformed interpretation objects raised `TypeError` during hash validation or set membership | Validate source/hash/status/coverage types at their schema boundary | Malformed JSON types raise `ValueError`. Research import returns 400, followed by successful valid import |

Regressions live in `product/tests/continuation_feedback.rs`,
`product/tests/deep_nonbgp_feedback.rs`, `streaming/tests/contracts.rs`,
`tools/tests/test_product_research.py` and `tools/tests/test_desktop_http.py`.
Each defect produced a failing regression on the baseline before its repair.
Focused Linux native tests, warnings-denied Clippy and Python/HTTP tests pass
with the fixes. Broader validation and independent review results belong to the
PR's exact published revision.

COTP handling follows RFC 1006's transport boundaries. HTTP target validation
follows RFC 9112 section 3.2. CIP handling preserves the embedded-service-error
table described by the implementation vendor's MultipleReq documentation.
[RFC 1006](https://www.rfc-editor.org/rfc/rfc1006),
[RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2),
[MultipleReq](https://www.automation-pros.com/enip1/javadoc/com/automation_pros/odva/cip/requests/MultipleReq.html)

## Architecture and next work

Source evidence is the common contract across the project. Capture offsets,
hashes, packet spans, transport generations, ambiguity and explicit limits carry
through parsing, history and comparison. Protocol support has several depths.
BGP has persistent state and replay, DNP3 has substantial object and workflow
support, and many industrial and IT parsers expose selected fields or envelopes.

The next recommended slice is shared Modbus/TCP PDU decoding and consistent
request/response semantics through existing entrypoints. Wire shape checks in
`src/modbus.rs` overlap field parsing in `src/semantics/modbus.rs`. A separate
draft PR outlines this work, measurement of repeated tail copies in
`deep::reassembly::StreamBuffer`, and a concise source-linked capability inventory.

## Evidence limits

This audit combines broad source inspection with bounded synthetic regressions
and local integration checks. Exhaustive protocol conformance, sustained fuzzing,
representative large-capture performance and live-device qualification remain
open. Historical receipts retain their original source identities. Hosted
checks for these changes must be read from the new PR.

Local work reused the checkout and toolchain. Measured checkout usage was about
24.1 GB, with about 1.9 GB in the existing Rust installation. Small fixtures and
serial bounded processes keep the planned peak below the 50,000,000,000-byte
project ceiling. Build artifacts and logs remain local.
