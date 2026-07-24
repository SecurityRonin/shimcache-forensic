# 2. `forbid(unsafe)` and panic-free bounds-checked decoding

Date: 2026-07-24
Status: Accepted

## Context

The AppCompatCache blob is **untrusted, attacker-controllable input**: it is read
verbatim from a `SYSTEM` hive that could be malformed, truncated, or hostile. The
fleet Paranoid Gatekeeper standard (`ronin-issen/CLAUDE.md`, "Security &
Robustness Standard") requires every `*-core`/`*-forensic` crate to never panic,
never read out of bounds, and never trust a length field. The global unsafe law
(`CLAUDE.core.md`, "`unsafe` Is an Avoidable Cost-Benefit Exception") makes
`forbid(unsafe)` the default and the goal; it is downgraded only when a real
benefit (e.g. an `mmap`) justifies a bounded per-site allow.

This decoder does pure in-memory byte arithmetic over a `&[u8]` — it never mmaps,
never calls FFI, and has no performance path that would benefit from unsafe.

## Decision

1. **`unsafe_code = "forbid"`** workspace-wide (`Cargo.toml`
   `[workspace.lints.rust]`), reasserted with `#![forbid(unsafe_code)]` at the
   top of every crate/binary. There is no bounded-allow exception; the README
   carries the `unsafe forbidden` badge honestly.
2. **Panic-free by construction.** Every field read goes through bounds-checked
   little-endian helpers (`read_u16`/`read_u32`/`read_u64` in `core/src/lib.rs`)
   that return `Option` via `slice::get(..)` and `try_into`, never indexing.
   Offset arithmetic that could overflow uses `checked_add`
   (`read_utf16_inline`) and `saturating_mul` (the bitness detectors). A
   malformed blob yields a `ShimcacheError` or a skipped entry (`else { break }`
   / `else { continue }` guard arms), never a panic.
3. **Panic lints as the static backstop:** `unwrap_used` and `expect_used` are
   `deny` in production (`[workspace.lints.clippy]`); tests are exempted via
   `clippy.toml` (`allow-unwrap-in-tests`/`allow-expect-in-tests`) rather than
   scattering `#[allow]`.
4. **Fuzzing as the empirical partner:** `fuzz/` ships `fuzz_parse` and
   `fuzz_forensic` cargo-fuzz targets over the untrusted parsers (commit
   `192676b`), so the panic-free posture is *tested*, not merely asserted.

## Consequences

- No input can trigger memory corruption or a crash in the decoder — the
  robustness guarantee is provable (`forbid`) and continuously fuzzed.
- The README's differentiator is "input-fuzzed" (measured) with "panic-free by
  lint / bounds-checked readers" as the qualified static half, per the fleet
  robustness-wording rule.
- **Known divergence from the fleet standard:** the standard mandates routing
  fixed-width reads through the shared `safe-read` crate rather than hand-rolling
  a per-crate reader. This repo hand-rolls `read_u16/u32/u64` in
  `core/src/lib.rs` instead. The helpers are correct and bounds-checked, but the
  DRY intent of the standard argues for migrating to `safe-read`. *Rationale for
  hand-rolling rather than depending on `safe-read` was not recovered in
  available history* — flag it for a follow-up migration.
