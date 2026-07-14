# shimcache-core test data — provenance

| File | `win7_appcompatcache.bin` |
|---|---|
| **What** | The raw `AppCompatCache` registry value blob (Windows 7 64-bit AppCompatCache, signature `0xbadc0fee`, 60 816 bytes, 292 cached entries). |
| **Source** | Extracted from the `SYSTEM` hive of the **NIST CFReDS "Data Leakage" case** (`\ControlSet001\Control\Session Manager\AppCompatCache\AppCompatCache`). |
| **Origin** | NIST Computer Forensic Reference Data Sets — <https://cfreds.nist.gov/>. US Government work, **public domain**; freely redistributable. |
| **MD5** | `45e0bc963894a8bc8f4d52e2797c98d3` |
| **How extracted** | `regipy` read of the `AppCompatCache` REG_BINARY value from the case `SYSTEM` hive. |
| **Ground truth / oracle** | Cross-confirmed by two independent implementations: Mandiant `ShimCacheParser` (identifies "64bit Windows 7/2k8-R2", parses 291 entries) and a from-spec read against libyal dtfabric `winreg-kb/winregrc/appcompatcache.yaml` (292 entries; Mandiant excludes one trailing record). Both agree on entry content: e.g. `C:\Windows\system32\LogonUI.exe`, `FILETIME` `129347834495725262` (2010-11-21 03:24:09 UTC), executed. |
| **Used by** | `tests/win7_real.rs` (Tier-1 real-corpus validation of the Windows 7 64-bit path). |

The blob is small (≈ 59 KiB) and public-domain, so it is committed directly rather than gitignored.
