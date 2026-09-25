# Product schema compatibility

These schemas supplement, not replace, `docs/streaming/event.schema.json`. New product metadata lives inside the existing event data field. Unknown top-level event kinds must follow the owning version contract; do not silently coerce unknown statuses to observed.

Structural validation does not check source identity, event hash chains, cross-field ranges, raw packet bytes, ordered state transitions, transitive provenance, semantic replay or producer authenticity. Runtime validators enforce their own stricter limits. Candidate v1 compatibility must be frozen only after golden native cross-language tests.
