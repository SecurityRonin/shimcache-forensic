# Validation

`shimcache-core` is validated against the authoritative format specification and, for the
dominant Windows 7 64-bit format, against **real-world data with two independent oracles**.

## Format specification

All version layouts (XP, Server 2003 / Vista / 2008, Windows 7, 8.0, 8.1, 10/11) follow libyal's
authoritative dtfabric definition, `winreg-kb/winregrc/appcompatcache.yaml`.

## Tier-1 (real data + independent oracles)

| Format | Corpus | Oracles | Result |
|---|---|---|---|
| Windows 7 64-bit | Real `AppCompatCache` value from the NIST **CFReDS** "Data Leakage" `SYSTEM` hive (public domain) | Mandiant `ShimCacheParser` **and** a from-spec read of the dtfabric layout | All **292 entries** decode; `LogonUI.exe` / `bfsvc.exe` match both oracles byte-for-byte. `shimcache4n6` reproduces the same result end-to-end from the hive. |

The committed fixture and its provenance are documented in `core/tests/data/README.md`.

## Spec-validated (synthetic, no public corpus)

The Windows XP, 2003/Vista, 8.0, 8.1, and 10 paths are validated with spec-faithful synthetic
fixtures built to the dtfabric layout (these versions have no readily available public corpus with
ground truth — XP/Vista are end-of-life). Each is a deterministic, CI-checked regression test.
