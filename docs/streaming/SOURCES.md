# Primary references and implementation boundaries

These are review references, not a claim that every supported behavior has passed
independent conformance testing. Protocol depth is specified by the implementation
matrix and emitted unsupported/incomplete states.

- Reviewed base revision: `b3282abb677431e21923ea1321d1fbbc2ff08989`.
- PCAP / PCAPNG: https://www.tcpdump.org/manpages/pcap-savefile.5.html and https://github.com/pcapng/pcapng (the specification project); original root parser is reused.
- TCP: https://www.rfc-editor.org/rfc/rfc9293 ; original conservative offline tracker is reused, not claimed to emulate every endpoint.
- IPv6 / fragmentation: https://www.rfc-editor.org/rfc/rfc8200
- DNS: https://www.rfc-editor.org/rfc/rfc1035
- HTTP/1.1 framing: https://www.rfc-editor.org/rfc/rfc9112
- TLS ClientHello: https://www.rfc-editor.org/rfc/rfc8446 ; no TLS decryption is implemented.
- QUIC: https://www.rfc-editor.org/rfc/rfc9000 ; only long invariant headers/metadata are implemented.
- GRE: https://www.rfc-editor.org/rfc/rfc2784 and https://www.rfc-editor.org/rfc/rfc2890
- VXLAN: https://www.rfc-editor.org/rfc/rfc7348
- GENEVE: https://www.rfc-editor.org/rfc/rfc8926
- DHCPv4 / DHCPv6: https://www.rfc-editor.org/rfc/rfc2131 and https://www.rfc-editor.org/rfc/rfc8415
- SCTP: https://www.rfc-editor.org/rfc/rfc9260 ; no SCTP association/stream reassembly.
- Radiotap: https://www.radiotap.org/ ; only documented common data paths are handled.
- SMB2: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ ; first-header metadata only.
- Independent Rust parser: https://github.com/rusticata/pcap-parser ; optional oracle pins 0.17.0, ordinary runtime does not depend on it.
- Upstream DHCP fixture: https://github.com/wireshark/wireshark/blob/master/test/captures/dhcp.pcap ; expected Git blob a42d6102e8a27868cf17b3da7a31af47d3140f5f and SHA-256 are pinned in corpus/manifest.json. Acquisition context/licensing still requires review before redistribution.

No external manual text or third-party packet capture is bundled here. New source
is an integration contribution to the existing MIT repository. Optional upstream
tooling and any subsequently acquired corpus retain their own licenses.
