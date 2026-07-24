# 4. Shared DFIR knowledge lives in `forensicnomicon`, not baked into the analyzer

Date: 2026-07-24
Status: Accepted

## Context

The two graded findings depend on two pieces of DFIR domain knowledge: the set of
Windows system-binary names (to detect a `svchost.exe` masquerading outside
`System32`) and the set of directories commonly used to stage malware (Temp,
Downloads, `$Recycle.Bin`, …). Both are cross-cutting facts many analyzers in the
fleet need. Baking a hardcoded name/path allow-list into this crate would be the
"hardcoded constants tied to known inputs" smell (global "No Special Cases") and
would duplicate knowledge that other analyzers must keep in sync (DRY).
`forensicnomicon` is the fleet KNOWLEDGE leaf — the single home for shared format
facts and DFIR baselines.

## Decision

`audit` (`forensic/src/lib.rs`) delegates both classifications to
`forensicnomicon`:

- `forensicnomicon::processes::is_system32_binary(&name)` — the system-binary
  baseline;
- `forensicnomicon::heuristics::paths::is_suspicious_exec_path(&e.path)` — the
  staging-directory list.

The `System32`/`SysWOW64` legitimacy check is a local structural test
(`upper.contains(r"\SYSTEM32\")`), not a data list, so it stays inline. No
name or path literal is baked into this crate.

## Consequences

- The baselines update fleet-wide in one place; this analyzer inherits
  improvements without a code change (a `forensicnomicon` minor bump).
- The two findings are **high-precision by design** — they fire only on a
  genuinely anomalous pattern (system binary off `System32`; entry in a staging
  dir) and stay quiet on benign `System32` entries, keeping the analyzer a triage
  signal rather than a noise source (`ShimcacheAnomaly` doc comment).
- This crate carries only the *policy* (what to flag, at what severity); the
  *knowledge* stays in the leaf every consumer already depends on.
