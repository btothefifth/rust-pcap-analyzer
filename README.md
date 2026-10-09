# rust-pcap-analyzer

A Rust toolkit for offline PCAP and PCAPNG inspection and protocol evidence. The
core library preserves packet locations and bounded parsing decisions so that
results can be checked against the source capture.

## Included tools

- **`pcap-evidence`** is the core library and command-line analyzer. It reads
  classic PCAP and PCAPNG, inspects packets, reconstructs bounded TCP streams,
  and reports protocol observations. Its protocol list is in the
  [protocol matrix](docs/PROTOCOL_MATRIX.md).
- **`pcap-evidence-stream`** provides bounded-window streaming analysis and
  event output. Its coverage and history limits are described in the
  [streaming contract](docs/streaming/CONTRACT.md).
- **`pcap-depth`**, in the opt-in `product/` workspace, adds bounded offline
  protocol analysis and source-bound BGP capture, MRT, and BMP stores. It can
  replay, query, export, and analyze persisted route evidence. See the
  [BGP completion contract](docs/product/BGP_COMPLETION.md),
  [MRT store contract](docs/product/BGP_MRT_STORE.md),
  [BMP contract](docs/product/BGP_BMP.md), and
  [persisted consumer contract](docs/product/BGP_PERSISTED.md).

The root CLI offers a quick inspection of a checked-in synthetic capture:

```sh
cargo run --locked --offline -- inspect tests/fixtures/mixed_sections.pcapng
```

For bounded product analysis of a capture, use a new workspace directory:

```sh
cargo run --manifest-path product/Cargo.toml --locked --offline --bin pcap-depth -- analyze capture.pcap --workspace depth-run --format ndjson
cargo run --manifest-path product/Cargo.toml --locked --offline --bin pcap-depth -- bgp state depth-run/bgp.journal --output bgp-state.json
```

The second command reads the sealed journal produced by the first. Product
outputs use no-overwrite publication; choose new output paths. MRT and BMP
imports have separate source-store commands documented in their contracts.

## Supported scope and limits

The analyzer is an offline evidence tool. The core parser handles supported
capture containers, link and network layers, transport reconstruction, and the
protocol subsets listed in the [protocol matrix](docs/PROTOCOL_MATRIX.md).
Unsupported or incomplete data remains explicit where the format permits; gaps,
conflicts, ambiguous identities, and uncertain timestamps are not filled in by
guesswork.

BGP outputs describe source-bound observations and candidate route state. They
do not prove source authenticity, bilateral endpoint negotiation, actual router
state, route installation, reachability, causality. The
streaming path reports bounded-window coverage and does not reconstruct complete
history across discarded windows. See [limitations](docs/LIMITATIONS.md) before
using the tools on real captures.

Captures may contain credentials, personal data, or other sensitive payloads.
Payload output is opt-in for the core CLI; handle source files and generated
reports under the appropriate authority. The checked-in fixtures are synthetic.
The public corpus manifest does not fetch captures by default.

## Build and reference

The repository pins Rust 1.85.1 in `rust-toolchain.toml`. The core CLI can be
built and run offline once that toolchain is available. Python is used for
repository validation and fixture tooling, not by the Rust application.

- [Library API](docs/API.md) and [file formats](docs/FORMAT.md)
- [Current implementation pointer](docs/implementation/CURRENT.md) and
  [validation evidence](docs/VALIDATION.md)
- [Engineering contract](docs/ENGINEERING.md) and [source references](docs/SOURCES.md)
- [MIT license](LICENSE)
