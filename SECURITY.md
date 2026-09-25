# Security and trust boundaries

This source has passed the documented local Windows native build and test gates, but
it has not undergone an independent security audit, fuzz campaign, or
representative-corpus qualification. It is not a hardened service ready to accept
arbitrary public uploads. Use resource-isolated local processing until those gates
establish the intended deployment envelope.

The parser forbids unsafe Rust in this crate and uses checked slices/lengths.
That does not prove absence of logic bugs, panics, allocation failure, denial of
service, or defects in dependencies/toolchains. Logical caps are not an RSS bound.
Default source analysis is limited to 256 MiB; reports and retained reconstructions
add memory. OS process memory/CPU/time limits remain recommended for hostile input.

No live capture, packet sending, remote execution, secret collection, telemetry,
or remote storage is implemented. Metadata and packet payloads can themselves be
sensitive. JSON redacts Decryption Secrets Block bytes even with payload export;
this is not general secret detection/redaction inside packet payloads or metadata.
`packet` deliberately exports bytes of the selected packet.

Filesystem publication uses a new temporary file in an existing destination parent,
file sync, and no-overwrite hard-link publication. On Unix it starts with owner-only
permissions and syncs the parent directory. It requires a trusted, stable parent
directory and a filesystem supporting these operations. There is no unsafe
rename-overwrite fallback. A failure after the commit point is explicitly reported
as potentially committed; inspect the destination instead of blindly retrying.
No claim of equivalent directory durability is made on non-Unix systems.

SHA-256 identifies content and detects changes. It is not an authenticity signature
or proof of capture origin. Index loading re-parses the source to prevent a
self-consistent forged sidecar from controlling packet extraction. External labels
are untrusted claims and can create only candidate correlations.

For a suspected vulnerability, contact the repository owners privately using their
chosen channel. No dedicated security address or bounty program has been established
for this repository. Do not put credentials or private captures in public issues.
Provide a minimized synthetic reproducer, exact revision/toolchain, stable error,
resource bounds, and expected versus actual behavior when safe to do so.
