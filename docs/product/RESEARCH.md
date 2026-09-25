# Parser differentials as a research target

A disagreement is a location to investigate, not an automatic vulnerability or a
vote. Keep the independent engine's output separate from comparison subjects.

## Observation contract

`tools.product.comparison` validates a `pcap-evidence.interpretation.v1` document
using normalization `source-anchored-fields-v1`. Source identity contains exact
byte count and SHA-256. Producer identity records implementation/version/origin,
configuration identity and declared execution lineage. Observations have a layer,
source anchor, evidence status, normalized values and packet/span/event witnesses.

Layers are ordered: capture_record, packet_bytes, timestamp, link_layer,
network_layer, fragment_set, transport_identity, tcp_reconstruction, stream_bytes,
protocol_detection, protocol_message, transaction, higher_order.

`compare_fields` compares common normalized fields and preserves ordered arrays,
duplicates and competing alternatives. An uncollected field is not a negative
observation. Unsupported/opaque semantics are not comparable. Evidence-state
differences remain differences even when values match. Identical answers establish
agreement only; no correctness ranking, confidence percentage or consensus appears.

The first observed disagreement carries raw/source witnesses and lists unresolved
earlier layers. `earliest_within_declared_coverage` must never be relabeled globally
earliest parser/endpoint divergence. Complete upstream instrumentation and comparable
adapter fields are necessary before making a stronger statement.

## Actual adapter scope

Container reference: record framing, packet bytes/hashes, clocks, lengths and link
metadata from independent Python construction/parsing. Product adapter: selected
native event fields normalized from hash-chained NDJSON. TShark: a fixed selected
capture/time/network/transport field set, with output/version artifacts and explicit
local executable identity. None is the semantic authority of the Rust core.

These adapters do not yet normalize every supported protocol/state transition.
The inherited Zeek/Suricata collection helpers are not complete semantic adapters.
Tool preference/decoder configuration capture also needs deeper qualification beyond
the recorded argv/version/binary identity. Shared upstream dependencies should be
recorded before treating implementations as independent witnesses.

A crash, timeout, missing executable, output budget error, malformed adapter output,
and a semantic disagreement are separate outcomes. Input documents cannot authorize
commands. Adapters run only explicitly configured local executables without a shell.
They are process boundaries, not complete OS CPU/memory/network sandboxes.

## Case maintenance and native probe

```sh
python -m tools.research audit
cargo build --manifest-path product/Cargo.toml --locked --offline --example research_probe
python -m tools.research case bgp.framing-kat --binary product/target/debug/examples/research_probe
```

Use actual case IDs from `product/research/catalog.json`; case lookup rejects guessed
IDs. The ledger has 68 subjects and 136 records, with independent synthetic bytes,
source/rights notes, specification references, assertions, properties, fuzz targets
and adapter coverage. An audit PASS means maintained references/hashes/selectors,
not normative review, native execution, complete conformance or security assurance.
Primary standard editions and exact normative clauses remain pending for many cases.
Generic short-input mutation tests are not exhaustive adversarial ambiguity suites.

## Compare, reduce and retain witnesses

```sh
python -m tools.research run container sample.pcap --output /new/container-run
python -m tools.research run product sample.pcap --binary /trusted/pcap-product --output /new/product-run
python -m tools.research run tshark sample.pcap --binary /trusted/tshark --output /new/tshark-run
python -m tools.research compare /new/product-run/interpretation.json /new/tshark-run/interpretation.json
python -m tools.research minimize sample.pcap /new/reduction --left product --left-binary /trusted/pcap-product --right tshark --right-binary /trusted/tshark --max-calls 40
```

Research is intentionally restricted to bounded captures (normally at most 32 MiB;
the native adapter additionally bounds packets/events). Narrow a large investigation
to an authorized research case first. The reducer preserves the first differing
layer/field/reason/values, not merely any error. Frame renumbering is documented.
A final recheck must reproduce the same fingerprint. Operational failures abort.
Single-deletion minimality is claimed only after a fresh full no-deletion pass.

Reduction preserves selected packet bytes but creates a derived container: only
capture/section/interface headers are retained and finite section lengths become
unknown. It is not archival copying or malformed-container repair. Original and
derived source identities, original-to-derived frame maps and trial comparison
hashes are retained. Intermediate raw external outputs are not all retained by the
reducer; rerun adapters on the final witness before adjudication/export.

Adjudication bundles retain the original research capture, both attributed views,
comparison, referenced standards and exact packet/range witnesses. Verification
recomputes the diff and checks ranges through the independent container map.
Structurally malformed captures can remain bundle subjects; unresolved packet
references stay unresolved. The GUI export requires explicit raw-capture consent.

```sh
python -m tools.research bundle sample.pcap left.json right.json --specifications specifications.json --output /new/finding.zip
python -m tools.research verify-bundle /new/finding.zip
```

Hashes and deterministic verification establish identity/integrity, not authorship,
endpoint truth, parser correctness, attack attribution or exploitability. Human
adjudication must explain the specification/invariant, raw bytes, state/policy,
competing observations, supported conclusion and remaining ambiguity. No new
external parser vulnerability was established by the authoring tests.
