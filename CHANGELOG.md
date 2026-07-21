# Changelog

## [0.4.1] - 2026-07-20

### Fixed
- **`fingerprint_id` no longer flips on a benign chat-template / token-accounting
  change.** `_fp()` hashed the raw tokenizer vector (raw `prompt_tokens`), so a
  constant per-probe overhead shift from an endpoint changing its chat template
  or token accounting produced a new fingerprint — a false "backend changed"
  drift. The fingerprint now hashes the overhead-invariant *shape* of the vector
  (each probe minus the vector's own minimum), which cancels a constant offset
  while preserving the relative structure that distinguishes tokenizer families.
- **`monitor` no longer reports a critical `tokenizer_vector` drift on the same
  benign overhead shift.** Its direct probe-count diff now compares the
  overhead-corrected shape instead of raw counts, matching the fingerprint fix.
  A genuine change in relative token structure still drifts.

### Added
- `tokenizer.shape_vector()` — reference-free overhead-invariant form of a probe
  vector, used by both `_fp()` and `monitor`.
- First automated test suite (`tests/`, `pip install -e '.[test]'`): 12
  characterization tests pinning the three contracts downstream tooling depends
  on — fingerprint overhead-invariance, `monitor` exit-2 drift semantics
  (including no-false-drift on benign overhead), and tokenizer family match
  against the shipped Qwen2 reference.
