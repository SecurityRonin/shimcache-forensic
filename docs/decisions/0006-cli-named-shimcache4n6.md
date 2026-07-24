# 6. The CLI is `shimcache4n6` (renamed from `shim4n6`)

Date: 2026-07-24
Status: Accepted

## Context

The fleet front-end convention (`ronin-issen/CLAUDE.md`, Crate naming grammar)
names an examiner-facing binary `<x>4n6`, where `<x>` is the artifact the analyst
recognizes (br4n6 = browser, ev4n6 = winevt, mem4n6 = memory, disk4n6 = disk).
The binary was first shipped as `shim4n6` (commit `42c24d3`, "feat(forensic):
GREEN — ShimCache analyzer + shim4n6 CLI"). `shim` is ambiguous — it reads as
generic Windows shimming, not the specific AppCompatCache/ShimCache artifact this
tool works on.

## Decision

Rename the binary to **`shimcache4n6`** (commit `cc09553`, "rename shim4n6 CLI to
shimcache4n6 (full-artifact-name convention)"). The `<x>` slug is the full
artifact family name, `shimcache`, matching how an analyst names the artifact and
keeping the binary self-describing on crates.io and on `$PATH`
(`forensic/src/bin/shimcache4n6.rs`; `README.md` "Run it"). The crate stays
`shimcache-forensic` (the analyzer is the headline, per Pattern A).

## Consequences

- The runnable surface is `shimcache4n6 <SYSTEM-hive> [--list]`, unambiguous about
  the artifact it reads.
- The rename happened before the first crates.io publish, so no published binary
  name was orphaned.
- Matches the fleet `<x>4n6` family for one consistent naming grammar across
  tools.
