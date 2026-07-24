# 7. Findings are graded `forensicnomicon` observations, never verdicts

Date: 2026-07-24
Status: Accepted

## Context

ShimCache is a notorious over-interpretation trap: an AppCompatCache entry proves
the file was *present* on a shimmed path, but presence alone is **not** proof of
execution — only the Windows 7/8 execution flag (`insertion_flags & 0x2`) is an
execution witness, and Windows 10 dropped that flag entirely. The fleet Reporting
Model and the global Expert-Witness discipline require analyzers to emit
observations ("consistent with …"), leaving legal/causal conclusions to the
analyst or tribunal. The analyzer must also normalize its output into the shared
`forensicnomicon::report` vocabulary so ORCHESTRATION and a future GUI render every
fleet analyzer uniformly.

## Decision

1. **Two graded finding codes**, each an `Observation` impl on `ShimcacheAnomaly`
   (`forensic/src/lib.rs`): `SHIMCACHE-SYSTEM-BINARY-RELOCATED`
   (High, `Category::Concealment`, MITRE `T1036.005`) and
   `SHIMCACHE-SUSPICIOUS-PATH` (Medium, `Category::Threat`, MITRE `T1204`). Codes
   are scheme-prefixed SCREAMING-KEBAB, the published-contract form.
2. **Observation wording, not verdicts.** Every `note()` is phrased "consistent
   with masquerading" / "consistent with suspicious execution"; MITRE refs are
   "consistent with", never a determination. The README and both library doc
   comments state the ShimCache presence-vs-execution caveat explicitly.
3. **The execution flag is surfaced faithfully as tri-state.**
   `ShimcacheEntry.executed` is `Some(true)`/`Some(false)` on Win7/8 and `None`
   on Win10 (`core/src/lib.rs`); `None` ("format cannot say") is kept distinct
   from `Some(false)` ("format says not executed"), and the suspicious-path
   finding carries the flag so the reader sees whether execution is witnessed.
4. **Normalize into `forensicnomicon::report`** — `to_finding` assembles a
   `Finding` with `Source`, `SubjectRef`, severity, category, and MITRE refs, so
   the output aggregates into a fleet `Report` alongside every other analyzer.

## Consequences

- The tool grades triage severity but never asserts guilt; downstream correlation
  or an examiner draws conclusions.
- The tri-state `executed` prevents the classic "ShimCache = it ran" error at the
  data-model level.
- New anomaly kinds get new codes (never re-purpose a shipped code); the
  `Observation` trait keeps grading logic in one place per variant.
