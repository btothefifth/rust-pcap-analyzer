# Independent evidence root, additive product surfaces

```text
immutable capture bytes
  ├─ existing Rust container/wire/fragment/TCP/evidence engine
  │    └─ existing bounded streaming registry/event API
  │         └─ additional trusted framing plugins + supplemental L2 observations
  │              ├─ NDJSON or typed TLV sink
  │              └─ isolated job → checked event projection → SQLite → query API → GUI
  └─ independent comparison implementations
       └─ attributed observations → first-field divergence → raw-witness bundle
```

The two branches are never merged into a consensus result. The independently
implemented Rust pipeline remains the canonical engine interpretation. A checksum
failure, unsupported link or coverage boundary is not deleted because another
plugin produces a plausible high-level result. Supplemental link observations may
coexist with an upstream unsupported diagnostic; this is intentionally visible.

## Source ownership

The root and `streaming/` crates remain unchanged. `product/` is a standalone
workspace using local path dependencies. Source archive/interval storage, analytics,
research comparisons and the GUI belong above the parser. No remote service or
third-party parser becomes a runtime dependency of the Rust evidence root.

`tools/evidence/` files included in the ZIP are baseline reference support for the
standalone Python workbench. Integration must retain the current repository's
versions rather than blindly replace them. Tests validate compatibility at that
boundary. Copied support is not described as new authoring work.

## CLI and profile contract

The new executable is `pcap-product`; old CLIs retain their names and behavior.
`analyze` accepts an ordinary saved capture, emits NDJSON by default, and can create
one new output file atomically using a temporary file and a no-clobber hard link.
The destination parent must be trusted/stable and the filesystem support hard links.
Source files are never rewritten. Generic stdout can contain a consumed prefix if
an I/O error occurs; it is not a completed run without the terminal event.

Profiles extend the existing nine built-in streaming analyzers. They are **not a
security allowlist that disables every other engine protocol**:

| Profile | Additional framing groups |
|---|---|
| it-light | standard |
| it-full | standard, extensions |
| ics-core | standard, industrial |
| ics-full | standard, extensions, industrial, industrial-full |

Supplemental link decoders follow compiled feature availability, not the stream
profile. The `registry` command reports additional decoder availability, not a
complete inventory of inherited engine capabilities. Feature gates control
availability/registration and decoder admission; they do not yet physically remove
all parser function machine code from a no-default-features build.

Repeated `--dnp3-port`/`--modbus-port` arguments and comma lists are accumulated,
sorted and deduplicated. The first explicit argument replaces that protocol's
inherited default. Values use the same u16 domain as library configuration,
including zero; a port is merely a configured hint. Hints remain disabled unless
`--allow-port-hints` is explicit. The base validator rejects overlapping DNP3 and
Modbus selection ports. Content matches are not discarded in favor of a port.

## Evidence and plugin boundaries

Additional `Decoded` values expose the consumed frame extent, named metadata,
field-relative source ranges, issues, decoder version and `metadata-only` support.
They never imply complete object/device semantics. The plugin adapter uses
`EvidenceBytes` so message-relative field ranges can be composed with source spans.
Conflicting detector matches retain ambiguity through the existing registry.

The product sink rereads each selected raw packet through a separate file handle,
checks its packet hash, and emits supplemental L2 evidence with exact source ranges.
The independent handle is essential: a cloned file handle may share its cursor with
the streaming reader. This correctness-first reread incurs extra I/O; performance
has not been qualified. The UI worker additionally verifies capture binding at EOF.

New metadata parsers do not fabricate request/response correlation. Existing DNP3/
Modbus correlation remains inherited. Decoder/plugin failure is reported rather
than bridging a lost frame boundary or concatenating unrelated UDP datagrams.
In-process Rust plugins are trusted code, not preemptively sandboxed execution.

## History semantics

`tools.product.history.archive` streams source bytes into bounded chunks and a
streaming chunk index. The terminal manifest binds all bytes and index hashes.
`StreamStore` persists source-backed intervals for caller-supplied scope/direction
and unwrapped positions, then emits bounded reconstructed pieces, gaps and
conflicting alternatives. It cannot decide TCP generation identities for its caller.

Archive completion, source integrity, parser correctness and endpoint truth are
four separate claims. The former two can be checked without proving the latter two.
See `HISTORY.md` and `STATUS.md` before enabling any stronger full-history claim.
