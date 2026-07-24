# shimcache-forensic — Product Requirements

*Reverse-written from the shipped code, README, and git history (2026-07-24).
Every current-state claim below is grounded in a same-session read of `core/src/`,
`forensic/src/`, and the workspace manifests. The load-bearing decisions live as
ADRs [0001](decisions/0001-core-forensic-split.md)–[0008](decisions/0008-msrv-floor-and-toolchain-pin.md)
under [`docs/decisions/`](decisions/).*

## Executive Summary

`shimcache-forensic` proves **what executables were present on a Windows box —
and, on Windows 7/8, which of them *ran*** — straight from the `SYSTEM` hive's
AppCompatCache (ShimCache), on any host OS. The examiner runs one command:

```console
$ shimcache4n6 /path/to/SYSTEM
```

and gets the decoded cache (each executable's path, last-modification `FILETIME`,
and execution state) plus a short list of graded findings — a system binary
running from the wrong directory (masquerading), or an executable staged in a Temp
/ Downloads / `$Recycle.Bin` directory. Decoding covers every AppCompatCache
version from Windows XP through 11. The decoder is panic-free by construction
(`#![forbid(unsafe_code)]`, bounds-checked, fuzzed), and every finding is an
observation ("consistent with …"), never a verdict.

The product is two crates: **`shimcache-core`** (a reusable, zero-dependency
decoder) and **`shimcache-forensic`** (the analyzer plus the `shimcache4n6` CLI).

## 1. Problem

ShimCache is one of the highest-value Windows execution/presence artifacts, but it
is awkward and dangerous to use:

- **The blob has ~eight incompatible layouts** across Windows versions, several
  without an explicit pointer-width field. A parser that gets a stride or offset
  wrong silently emits garbage paths.
- **It is easy to over-interpret.** A ShimCache entry proves presence on a shimmed
  path, not execution; only the Windows 7/8 execution flag witnesses a run, and
  Windows 10 dropped that flag. Tools that render every entry as "executed"
  manufacture false conclusions.
- **Existing parsers dump raw entries** and leave the analyst to eyeball hundreds
  of paths for the one that matters (a `svchost.exe` outside `System32`, a binary
  in a staging directory).

## 2. Users and use cases

- **DFIR analysts / incident responders** triaging a `SYSTEM` hive pulled from an
  image or live collection: "what ran/was present, and what looks wrong?" —
  answered in one command, cross-platform (the tool never needs to run on
  Windows).
- **Forensic examiners** who need a defensible, spec-grounded decode with an
  auditable finding vocabulary ("consistent with masquerading", MITRE-tagged) for
  a report.
- **Fleet/tool developers** who need the raw decoder as a library — linking
  `shimcache-core` to turn AppCompatCache value bytes (from a hive, a memory
  image, or a mounted volume) into typed entries, with no registry or findings
  dependency.

## 3. What it does

- **Decodes the AppCompatCache value** at
  `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` into typed
  entries — executable path (with the `\??\` device prefix stripped), last-mod
  `FILETIME`, and a tri-state execution flag (`Some(true/false)` on Win7/8, `None`
  on Win10). Formats: XP, Server 2003 / Vista / 2008 (32/64-bit), 7 (32/64-bit),
  8.0, 8.1, 10/11 ([ADR 0003](decisions/0003-signature-detection-structural-bitness.md)).
- **Reads the value out of a `SYSTEM` hive** with our own `winreg-core`, checking
  `ControlSet001` then `ControlSet002`
  ([ADR 0005](decisions/0005-dependency-direction-prefer-our-crates.md)).
- **Grades two high-precision findings**
  ([ADR 0007](decisions/0007-findings-are-observations.md)):

  | Code | Severity | MITRE | Fires when |
  |---|---|---|---|
  | `SHIMCACHE-SYSTEM-BINARY-RELOCATED` | High | T1036.005 | A Windows system-binary name recorded at a non-`System32`/`SysWOW64` path (masquerading). |
  | `SHIMCACHE-SUSPICIOUS-PATH` | Medium | T1204 | An entry whose path is a common staging directory (Temp, Downloads, `$Recycle.Bin`, …). |

  The system-binary baseline and staging-directory list are shared DFIR knowledge
  from `forensicnomicon`, not baked in
  ([ADR 0004](decisions/0004-dfir-knowledge-in-forensicnomicon.md)).
- **Renders** a one-line format/control-set/count summary, the graded findings,
  and — with `--list` — every cache entry with its last-modification time and
  execution state (`forensic/src/bin/shimcache4n6.rs`).

## 4. Scope / non-goals

**In scope:** decoding every AppCompatCache version; the hive extraction at the CLI
edge; the two masquerading/staging findings; a reusable zero-dep decoder library;
panic-free, fuzzed parsing of untrusted blobs.

**Non-goals:**

- **No proof of execution beyond the format's own witness.** The tool surfaces the
  Win7/8 execution flag and states the presence-vs-execution caveat; it never
  claims an entry "ran" on Windows 10, where the format cannot say
  ([ADR 0007](decisions/0007-findings-are-observations.md)).
- **No verdicts.** Findings are observations for correlation/tribunal, never a
  determination of malice.
- **No registry parsing in the core decoder.** `shimcache-core` takes value bytes;
  hive/REGF handling is `winreg-core`'s job at the edge
  ([ADR 0005](decisions/0005-dependency-direction-prefer-our-crates.md)).
- **No broad "shimming" analysis** (SDB/shim database inspection) — this tool is
  the AppCompatCache artifact only.
- **No timeline correlation across artifacts** — that is ORCHESTRATION's (issen's)
  job; this crate emits `forensicnomicon` findings that aggregate upward.

## 5. Artifact family

The single Windows AppCompatCache (ShimCache) registry value, all header versions
XP → 11. Per entry: executable path, last-modification `FILETIME`, and the Win7/8
execution flag (`insertion_flags & 0x2`). Layouts follow libyal's authoritative
dtfabric spec (`winreg-kb/winregrc/appcompatcache.yaml`).

## 6. Validation approach

Tier-1 against **real data with two independent oracles**: the Windows 7 64-bit
AppCompatCache from the NIST **CFReDS** "Data Leakage" `SYSTEM` hive (public
domain) — all 292 entries decode, with `LogonUI.exe`/`bfsvc.exe` matching both
Mandiant's `ShimCacheParser` and a from-spec read of the dtfabric layout, and
`shimcache4n6` reproducing the same result end-to-end from the hive. The XP,
2003/Vista, 8.0, 8.1, and 10 paths (no public corpus with ground truth) are
validated with spec-faithful synthetic fixtures as deterministic CI regression
tests. Untrusted-input robustness is covered by the `fuzz_parse` / `fuzz_forensic`
cargo-fuzz targets. Details: [`docs/validation.md`](validation.md) and
`core/tests/data/README.md`.
