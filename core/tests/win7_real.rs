//! Tier-1 validation against a **real** Windows 7 64-bit AppCompatCache value blob extracted
//! from the NIST CFReDS "Data Leakage" case `SYSTEM` hive (public domain).
//!
//! Ground truth is cross-confirmed by two independent implementations: Mandiant's
//! `ShimCacheParser` (which parsed 291 entries and identifies the blob as "64bit Windows
//! 7/2k8-R2") and a from-spec read against libyal's dtfabric `appcompatcache.yaml`. The header
//! records `number_of_cached_entries = 292`; both spec-faithful reads yield 292 entries (Mandiant
//! excludes one trailing record). We assert the header-authoritative count of 292 and the exact
//! path + `FILETIME` + execution flag of specific entries both oracles agree on.
//!
//! Provenance: `core/tests/data/README.md`.
#![allow(clippy::unwrap_used)]

use shimcache_core::{detect_format, parse, ShimcacheFormat};

const BLOB: &[u8] = include_bytes!("data/win7_appcompatcache.bin");

#[test]
fn cfreds_win7_blob_is_detected_as_win7_64bit() {
    assert_eq!(detect_format(BLOB), Some(ShimcacheFormat::Win7_64));
}

#[test]
fn cfreds_win7_blob_decodes_all_292_entries_with_known_values() {
    let entries = parse(BLOB).unwrap();
    assert_eq!(entries.len(), 292, "header records 292 cached entries");

    // First entry — LogonUI.exe, executed, last-modified FILETIME 129347834495725262
    // (2010-11-21 03:24:09 UTC), agreed by Mandiant + the from-spec read.
    assert_eq!(entries[0].path, r"C:\Windows\system32\LogonUI.exe");
    assert_eq!(entries[0].last_modified_filetime, 129_347_834_495_725_262);
    assert_eq!(entries[0].executed, Some(true));

    // Second entry — SearchFilterHost.exe.
    assert_eq!(entries[1].path, r"C:\Windows\system32\SearchFilterHost.exe");
    assert_eq!(entries[1].last_modified_filetime, 128_920_091_770_490_000);

    // Last entry — bfsvc.exe.
    let last = entries.last().unwrap();
    assert_eq!(last.path, r"C:\Windows\bfsvc.exe");
    assert_eq!(last.last_modified_filetime, 129_347_834_628_481_495);
    assert_eq!(last.executed, Some(true));

    // The '\??\' device prefix must be stripped on every entry.
    assert!(entries.iter().all(|e| !e.path.starts_with(r"\??\")));
}
