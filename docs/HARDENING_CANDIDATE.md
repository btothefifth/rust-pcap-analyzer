# Hardening status

This document records the hardening work added after the initial 0.1.0 baseline. It
is a source status note, not a release certificate.

Implemented changes include configured-port, datagram-local DNP3 analysis
(`Analysis.datagrams`, JSON `udp_applications`); advisory content probes that do
not change configured dispatch; stronger Modbus field and candidate consistency;
IPv6 fragment key and offset-zero semantics; bounded-state admission fixes;
FIN/idle-generation fixes; incremental checksums; provenance hot-path changes; and
regression/fuzz tooling.

The full analyzer remains bounded and snapshot-based. UDP records are not a
reliable byte stream and are not automatically correlated as TCP transactions.
DNP3 object bodies remain opaque. Probe matches are advisory, not probabilities or
authenticated identities. Logical budgets still do not provide an aggregate
process-RAM ceiling.

Local proof for this candidate includes Rust 1.85.1/MSVC formatting, offline check,
debug and release tests, warnings-denied Clippy, documentation and binary builds,
the independent CLI checks, a 93-case hardening CLI oracle, and semantic mutation
checks. The manifest contains 130 selectors; 128 native tests ran on Windows, with
two Unix-only selectors not collected, and the focused hardening suite contains 37
tests.

The optional fuzz campaign remains blocked in this environment because it requires
a POSIX worker and `libfuzzer-sys` is not cached for offline use. Cross-platform CI,
real-capture replay, performance qualification, aggregate memory envelopes and
production security review remain open. Keep those limits visible in
`docs/VALIDATION.md`, `docs/LIMITATIONS.md` and `docs/CURRENT.md`.
