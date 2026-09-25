# Sources and version boundaries

References consulted for format/design work. URLs are navigation to external
primary sources, not vendored specification text. Internet-Drafts are work in
progress, not asserted to be final RFCs. No third-party implementation is bundled
into the runtime source.

| Subject | Primary reference | Use / boundary |
|---|---|---|
| Classic PCAP | https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-08.html | Header/record structure, units, link-field semantics |
| PCAPNG | https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-05.html | Sections, interfaces, block bounds, option layout and timestamps |
| TCP | https://www.rfc-editor.org/rfc/rfc9293.html | Sequence-space and transport concepts; no claim of full endpoint state-machine emulation |
| DNP3 implementation guidance | https://www.snort.org/document/readme-dnp3 | Passive framing context; not a full IEEE1815 semantic-conformance claim |
| DNP3 link-control reference | https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-dnp.c | Non-authoritative comparison for bit masks and data-link names; never the correctness oracle, vendored source or runtime dependency |
| DNP3 function classifications | https://docs.stepfunc.io/dnp3/0.9.0/java/io/stepfunc/dnp3/FunctionCode.html | Request/response/unsolicited distinctions |
| Modbus documents | https://www.modbus.org/specs.php | Application/TCP framing references; opaque/unsupported semantics remain explicit |
| CRC16 DNP check value | https://docs.rs/crc16/latest/crc16/ | Independent known-answer convention; no dependency or implementation copied |
| libFuzzer Rust harness dependency | https://docs.rs/libfuzzer-sys/0.4.10/libfuzzer_sys/ | Optional fuzz workspace pins 0.4.10; not a runtime dependency |
| Capture offload caveats | https://wiki.wireshark.org/CaptureSetup/Offloading | Reason checksum observation is distinct from an on-wire-invalid assertion |
Historical ecosystem bug reports were used as motivation for timestamp, reassembly,
metadata-preservation and malformed-input regression families. This repository does
not claim those historical bugs persist in the latest releases of other projects,
or that implementing similar-looking tests establishes comparative superiority.
