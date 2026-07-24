# 8. MSRV floor 1.85, dev toolchain pinned to 1.96.0

Date: 2026-07-24
Status: Accepted

## Context

The fleet Rust MSRV & Toolchain policy (`CLAUDE.core.md` +
`CLAUDE.personal.md`) separates the **dev toolchain** (one pinned current stable
across the fleet, in `rust-toolchain.toml`) from the **declared MSRV**
(`rust-version`, a downstream promise). Apps declare MSRV = the pinned toolchain;
published libraries keep a low, CI-verified MSRV so third-party consumers are not
forced onto the newest compiler. `shimcache-core` is a published library
(reusable decoder); `shimcache-forensic` ships the `shimcache4n6` binary.

## Decision

1. **`rust-toolchain.toml` pins the dev toolchain to `1.96.0`** with `clippy` and
   `rustfmt` components declared in the toml (single source of truth for CI and
   local, per the fleet toolchain-precedence rule).
2. **Declared MSRV is `1.85`, hoisted once** to `[workspace.package].rust-version`
   and inherited by both members via `rust-version.workspace = true`
   (`Cargo.toml`, `core/Cargo.toml`, `forensic/Cargo.toml`). Edition is `2021`.
   The single hoisted floor keeps core and forensic on one number even though
   their `version`s are independent.

## Consequences

- The library floor (1.85) sits below the dev pin (1.96), so a downstream
  consumer is not dragged onto the newest stable to link `shimcache-core`.
- One workspace edit moves the MSRV; CI verifies it.
- **Rationale not fully recovered:** the fleet's low-MSRV convention cites
  1.75/1.80 as the library floor, whereas this repo floors at 1.85. Whether 1.85
  is the true minimum that compiles (e.g. forced by a `forensicnomicon`/toolchain
  feature) or simply the value chosen at bootstrap was *not recovered in
  available history*. If the crates in fact build on 1.80, lowering the floor
  would widen the core decoder's audience — flag for verification.
