# Changelog

## 0.1.0 — hardening follow-up, 2026-09-18

Added configured-port, datagram-local UDP DNP3 analysis with preserved packet
provenance; IPv6 fragment identity and offset-zero protocol handling; stricter
Modbus common-function shape and response consistency checks; bounded TCP, fragment
and protocol-state fixes; incremental checksum support; optimized provenance
slicing; advisory protocol probes; eight fuzz targets; and an independent synthetic
CLI hardening oracle.

The local Windows evidence now covers 128 executed native tests from 130 selectors,
including 37 focused hardening regressions, plus the 93-case compiled-CLI oracle.
The optional fuzz campaign remains unexecuted because this Windows host has no POSIX
libFuzzer worker and the pinned fuzz dependency is not cached offline. Real-world
captures, cross-platform CI observations, performance qualification, and security
review remain open.

## 0.1.0 — first working local baseline, 2026-09-16

Implemented offline capture readers/writers, exact clocks, packet and stream
reconstruction, DNP3/Modbus framing, provenance, transaction/attempt candidates,
source-verified indexing, JSON CLI and conservative filesystem publication.
Included synthetic fixtures, native tests, independent Python checks, semantic
mutation targets, fuzz harnesses and multi-platform CI configuration.

**Historical baseline validation:** the initial configured Windows gate passed with
Rust 1.85.1 and the native linker. Later hardening evidence is recorded above and
in `docs/VALIDATION.md`; no claims of equivalence to Arkime/Wireshark or success on
an external capture corpus are made.
