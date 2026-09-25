---
name: Incorrect decoding or reconstruction
about: Report the first reproducible evidence divergence, without uploading secrets
---
## Expected observation and independent oracle
Which exact packet bytes, field value, stream span or protocol boundary is wrong?

## Reproduction
- Commit / ZIP SHA-256:
- `rustc --version`, OS and filesystem:
- Command and all policy flags:
- Capture SHA-256 and smallest sanitized/synthetic reproducer:
- First diverging layer and exact packet/frame IDs:

## Actual behavior
Attach structured diagnostics and native test output. Redact addresses, payloads,
credentials and decryption secrets before posting. A closed tracker issue or a
matching Wireshark label alone is not an oracle.

## Nearest valid case / counterexample
What must continue to work after the fix?
