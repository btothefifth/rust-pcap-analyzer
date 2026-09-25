# Add a protocol without editing the reconstruction driver

The complete native example is `streaming/examples/custom_plugin.rs`. It implements
`ProtocolDetector`, an `AnalyzerPlugin` factory and a `DatagramAnalyzer` for an
illustrative `ECHOX01`-prefixed UDP payload. It does not require a known port, export
payload secrets, perform network I/O or modify `runner.rs`.

After native build gates pass:

```sh
cargo run --manifest-path streaming/Cargo.toml --locked --offline --example custom_plugin -- capture.pcap
```

Replace the example marker and metadata with specification-backed parsing. Keep
NoMatch separate from NeedMore and errors. Match lengths must refer to inspected
bytes; a marker is not authentication. Always propagate `Output` errors.

For TCP, implement `StreamAnalyzer` with a bounded buffer and explicit `push`,
`gap`, `finish` and `retained_bytes`. Data is only contiguous within a supplied
chunk; never bridge an emitted gap or history cut. A protocol frame can span several
source packets and must retain their exact `EvidenceBytes` mappings. A complete
framing claim is not necessarily complete protocol semantics.

An optional `CorrelationHint` lets the default bounded identifier correlator refer
to message event IDs. Provide role and compatibility evidence, not an invented
confidence score. Reused identifiers or conflicting directions must stay ambiguous.
Replace `TransactionCorrelator` for protocol-specific matching without changing the
capture/TCP engine. Register all supported interpretations; do not remove competing
detectors merely to make one candidate appear unambiguous.

The registry executes trusted code. Output limits and `retained_bytes` reporting do
not sandbox a malicious plugin. Review code/dependencies and apply OS resource
limits before exposing any parser as an upload-facing service. Custom plugin logs
require a matching trusted replay implementation; the provided built-in CLI replay
verifier is not an automatic verifier for arbitrary plugin binaries.
