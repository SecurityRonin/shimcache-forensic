# shimcache-forensic

[![CI](https://github.com/SecurityRonin/shimcache-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/shimcache-forensic/actions)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Prove what was on a Windows box — and, on Windows 7/8, what *ran* — straight from the `SYSTEM` hive's AppCompatCache (ShimCache), on any OS.** A panic-free decoder (Windows 7/8.0/8.1/10) plus an analyzer that flags masquerading and execution from staging directories.

## Run it

```console
$ cargo install shimcache-forensic          # installs the shim4n6 binary
$ shim4n6 /path/to/SYSTEM
AppCompatCache: Win7_64, ControlSet001, 292 entries
Findings (29):
  [MEDIUM] SHIMCACHE-SUSPICIOUS-PATH  C:\Users\INFORM~1\AppData\Local\Temp\eraserInstallBootstrapper\dotNetFx40_Full_setup.exe
    dotNetFx40_Full_setup.exe at …\eraserInstallBootstrapper\… sits in a directory commonly used to stage malware (execution flag set) — consistent with suspicious execution.
  [MEDIUM] SHIMCACHE-SUSPICIOUS-PATH  C:\$Recycle.Bin\S-1-5-21-…-1000\$RJEMT64.exe
    $RJEMT64.exe at C:\$Recycle.Bin\… sits in a directory commonly used to stage malware (no execution flag) — consistent with suspicious execution.
```

`--list` dumps every cache entry with its last-modification time and execution state.

## What it decodes

The AppCompatCache value at `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`. Per entry: the **executable path**, the file's **last-modification `FILETIME`**, and — on Windows 7/8 — the **execution flag** (`insertion_flags & 0x2`). Windows 10 dropped the flag, so `executed` is `None` there. Supported formats: **Windows 7 (32/64-bit), 8.0, 8.1, 10/11**. Legacy XP/2003/Vista return a *named* error rather than a silent miss.

> **ShimCache is not proof of execution by itself.** An entry means the file was present on a shimmed path; the Windows 7/8 execution flag is the execution witness. Findings are observations ("consistent with …"), never verdicts.

## Layers

- **`shimcache-core`** — the pure decoder: `parse(&[u8]) -> Vec<ShimcacheEntry>`. No registry dependency, `#![forbid(unsafe_code)]`, panic-free (bounds-checked). Reusable anywhere the raw value bytes are in hand.
- **`shimcache-forensic`** — `analyze_blob` + `audit` (graded `forensicnomicon` findings) and the `shim4n6` CLI, which reads the value out of a hive with [`winreg-core`](https://crates.io/crates/winreg-core).

## Validation

Tier-1 against a **real** Windows 7 64-bit AppCompatCache from the NIST **CFReDS** "Data Leakage" `SYSTEM` hive (public domain): all **292 entries** decode with `LogonUI.exe`/`bfsvc.exe` matching two independent oracles — Mandiant's `ShimCacheParser` and a from-spec read of libyal's dtfabric `appcompatcache.yaml`. `shim4n6` reproduces the same result end-to-end from the hive, surfacing the case's Temp/`$Recycle.Bin` executions. See `core/tests/data/README.md`.

## Findings

| Code | Severity | MITRE | Fires when |
|---|---|---|---|
| `SHIMCACHE-SYSTEM-BINARY-RELOCATED` | High | T1036.005 | A Windows system-binary name recorded at a non-`System32`/`SysWOW64` path (masquerading). |
| `SHIMCACHE-SUSPICIOUS-PATH` | Medium | T1204 | An entry whose path is a common staging directory (Temp, Downloads, `$Recycle.Bin`, …). |

---

[Privacy Policy](https://securityronin.github.io/shimcache-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/shimcache-forensic/terms/) · © 2026 Security Ronin Ltd
