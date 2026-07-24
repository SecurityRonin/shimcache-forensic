# 1. Reader/analyzer split — `shimcache-core` + `shimcache-forensic`

Date: 2026-07-24
Status: Accepted

## Context

This repo decodes and analyzes the Windows AppCompatCache (ShimCache) value.
Two distinct concerns live here: (1) turning the raw versioned binary blob into
typed entries, and (2) grading those entries for forensically interesting
patterns and driving a CLI. The fleet Crate-structure standard
(`ronin-issen/CLAUDE.md`, "Crate-structure standard — reader/analyzer split")
requires a single-format repo to be exactly two crates — `<x>-core` (the raw
reader, no findings) and `<x>-forensic` (the anomaly auditor) — under one
workspace named `<x>-forensic` (Pattern A of the Crate naming grammar).

ShimCache fits Pattern A cleanly: one artifact family, one reader, one analyzer.
The decoder is broadly reusable (anyone holding the raw value bytes wants typed
entries) and must not drag in a hive parser or a findings model.

## Decision

Two workspace members (`Cargo.toml` `members = ["core", "forensic"]`):

1. **`core/` → `shimcache-core`** — the pure decoder. `parse(&[u8]) ->
   Result<Vec<ShimcacheEntry>, ShimcacheError>` plus `detect_format`
   (`core/src/lib.rs`). Zero dependencies (`core/Cargo.toml` has an empty
   `[dependencies]`), no registry/hive knowledge, emits no findings. Imported as
   `shimcache_core` — the bare `[lib] name` is left unchanged rather than
   claiming `shimcache`, since the crate is scoped to AppCompatCache, not "shim"
   in general.
2. **`forensic/` → `shimcache-forensic`** — `analyze_blob` + `audit` producing
   graded `forensicnomicon` findings, and the `shimcache4n6` binary
   (`forensic/src/bin/shimcache4n6.rs`). Depends on `shimcache-core`
   (`forensic/Cargo.toml`).

Versions are intentionally **not** hoisted to `[workspace.package]` (see the
comment in `Cargo.toml`): core and forensic version independently, so each keeps
its own inline `version`.

## Consequences

- The decoder is a standalone, zero-dep primitive any consumer can link without
  pulling a hive parser or the report model. `shimcache-forensic` re-exports
  `ShimcacheEntry`/`ShimcacheFormat` so a findings consumer needs only the one
  crate (`forensic/src/lib.rs`).
- Two crates publish and version separately via release-plz (commit `0c8f4d6`),
  matching the fleet's independent-crate release model.
- The forensic layer here builds *on* `shimcache-core` (its reader API already
  exposes raw path/timestamp/exec-flag, so no lower-level re-parse is needed) —
  the default per the standard, not the exception.
