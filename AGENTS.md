# Repository working constraints

## Local disk footprint

The current owner constraint is to keep this project's **total local disk usage
strictly below 50 GB (50,000,000,000 bytes)**. This is a ceiling, not a target.
Keep ordinary work small.

- Count the checkout, `.git`, ignored build trees, captures, generated reports,
  archives, journals, indexes, databases, logs, fuzz artifacts, temporary files,
  and any project-specific storage placed outside this directory together.
- Prefer this one checkout and branches. Do not make full repository/release
  copies, large source archives, or duplicate capture collections.
- Use checked-in synthetic fixtures and small minimized witnesses. Do not
  download large corpora or generate large PCAP/MRT files for routine work.
- Before a build, replay, fuzz campaign, packaging run, or dataset expansion,
  measure current occupancy and estimate the operation's peak, including
  temporary coexistence of inputs, outputs, sort runs, and recovery workspaces.
  Do not start an operation whose peak could reach the ceiling.
- Give scratch space one explicit owner and a bounded path. Disable unnecessary
  bytecode/cache creation. Reuse available tools; avoid installing toolchains or
  duplicating dependency caches solely for a review.
- Use explicit source, disk, output, record, and time limits when executing the
  analyzers. Some application defaults permit much more than this local ceiling;
  they do not authorize using that space here.
- Monitor usage during operations that can grow and stop with headroom before
  the ceiling. Remove only exact artifacts known to have been created as
  disposable by the current task. Preserve original captures, user files,
  retained evidence, and other tasks' build/cache directories.

These are agent operating constraints; they are not a filesystem quota or proof
that the applications enforce an aggregate storage budget.

## Review and continuation

Start with `docs/implementation/CURRENT.md`. The repository-wide review and
ordered follow-up work are in
`docs/implementation/REPOSITORY_REVIEW_2026-10-02.md`.
Resolve historical status text against current code, contracts, exact source
identities, and executed receipts. Keep local checks, hosted CI, normative
qualification, scale evidence, and endpoint/source authority distinct.
