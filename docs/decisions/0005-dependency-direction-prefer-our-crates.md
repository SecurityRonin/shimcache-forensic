# 5. Dependency direction — registry-free core, hive access via our own `winreg-core`

Date: 2026-07-24
Status: Accepted

## Context

Reading the AppCompatCache value out of a `SYSTEM` hive requires a REGF parser.
The decoder itself needs only the extracted value bytes. The fleet PARSER
dependency rules (`ronin-issen/CLAUDE.md`, "Dependency rules") keep a parser
medium-agnostic — it accepts `&[u8]`, never imports the container/reader that
located the bytes. The fleet Dependency-Preference rule (binding) additionally
requires reaching for our own (SecurityRonin/`h4x0r`) crates over third-party
ones when an equivalent exists.

## Decision

1. **`shimcache-core` stays registry-free** — an empty `[dependencies]`
   (`core/Cargo.toml`). It parses value bytes and knows nothing about hives.
2. **The hive read lives at the CLI edge, using our own `winreg-core`.** The
   `shimcache4n6` binary opens the hive with `winreg_core::hive::Hive`, walks
   `ControlSet001` then `ControlSet002` (the standard forensic order),
   extracts the `AppCompatCache` value's raw bytes, and hands the blob to
   `analyze_blob` (`forensic/src/bin/shimcache4n6.rs`). `winreg-core` is the
   fleet's own REGF reader (`winreg-core = "0.2"` in `[workspace.dependencies]`),
   chosen over any third-party registry crate per the Dependency-Preference rule.
3. **The findings model is `forensicnomicon`** (`= "1"`, full default features —
   batteries-included), the fleet's shared report/knowledge leaf.
4. **`analyze_blob` remains a pure `&[u8]` -> report function** in the library
   (`forensic/src/lib.rs`), so a consumer that already has a hive open does the
   same 5-line extraction and calls the library directly — the hive read is not
   welded into the analysis path.

## Consequences

- Dependency arrows point only downward: `shimcache4n6` → `shimcache-forensic` →
  `shimcache-core`; the hive dependency (`winreg-core`) sits at the binary/edge,
  not inside the decoder.
- The decoder is reusable in memory-image and mounted-image contexts where the
  value bytes arrive by a different route.
- Every dependency (`winreg-core`, `forensicnomicon`) is a fleet crate; no
  third-party equivalent is pulled where ours exists. Once inter-crate paths are
  published, dependents move to the registry version per the fleet path-vs-registry
  rule; the intra-workspace `shimcache-core` dep carries both `path` and `version`
  for that transition (`[workspace.dependencies]`).
