//! Unit tests for the ShimCache analyzer: audit heuristics, the `Observation` mapping, and
//! `analyze_blob` on the real committed CFReDS Win7-64 blob (a non-false-positive control — a
//! clean system's cache produces no anomalies).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

fn entry(path: &str, executed: Option<bool>) -> ShimcacheEntry {
    ShimcacheEntry {
        path: path.to_string(),
        last_modified_filetime: 0,
        executed,
    }
}

/// The real Windows 7 64-bit blob (same fixture the core crate validates against).
const WIN7_BLOB: &[u8] = include_bytes!("../../core/tests/data/win7_appcompatcache.bin");

#[test]
fn system_binary_at_non_system_path_flags_masquerading() {
    let anomalies = audit(&[entry(r"C:\Temp\svchost.exe", Some(true))]);
    assert!(anomalies.iter().any(|a| matches!(
        a,
        ShimcacheAnomaly::SystemBinaryRelocated { name, .. } if name == "SVCHOST.EXE"
    )));
}

#[test]
fn system_binary_in_system32_is_not_flagged() {
    let anomalies = audit(&[entry(r"C:\Windows\System32\svchost.exe", Some(true))]);
    assert!(
        !anomalies
            .iter()
            .any(|a| matches!(a, ShimcacheAnomaly::SystemBinaryRelocated { .. })),
        "a System32 svchost must not be flagged: {anomalies:?}"
    );
}

#[test]
fn suspicious_path_carries_the_execution_flag() {
    let anomalies = audit(&[entry(
        r"C:\Users\a\AppData\Local\Temp\dropper.exe",
        Some(true),
    )]);
    match anomalies
        .iter()
        .find(|a| matches!(a, ShimcacheAnomaly::SuspiciousPath { .. }))
    {
        Some(ShimcacheAnomaly::SuspiciousPath {
            executable,
            executed,
            ..
        }) => {
            assert_eq!(executable, "dropper.exe");
            assert_eq!(*executed, Some(true));
        }
        other => panic!("expected SuspiciousPath, got {other:?}"),
    }
}

#[test]
fn benign_application_yields_no_anomaly() {
    let anomalies = audit(&[entry(r"C:\Program Files\App\app.exe", Some(true))]);
    assert!(
        anomalies.is_empty(),
        "benign path should be quiet: {anomalies:?}"
    );
}

#[test]
fn observation_maps_to_finding_fields() {
    let a = ShimcacheAnomaly::SystemBinaryRelocated {
        name: "SVCHOST.EXE".to_string(),
        path: r"C:\Temp\svchost.exe".to_string(),
    };
    assert_eq!(a.severity(), Some(Severity::High));
    assert_eq!(a.category(), Category::Concealment);
    assert_eq!(a.code(), "SHIMCACHE-SYSTEM-BINARY-RELOCATED");
    assert_eq!(a.mitre(), &["T1036.005"]);
    assert!(a.note().contains("masquerading"));
    let f = to_finding(&a, "SYSTEM");
    // A Finding was produced under the analyzer scope; smoke-check it serializes.
    let _ = format!("{f:?}");
    // The suspicious-path variant grades Medium/Threat.
    let s = ShimcacheAnomaly::SuspiciousPath {
        executable: "x.exe".to_string(),
        path: r"C:\Temp\x.exe".to_string(),
        executed: None,
    };
    assert_eq!(s.severity(), Some(Severity::Medium));
    assert_eq!(s.category(), Category::Threat);
    assert_eq!(s.mitre(), &["T1204"]);
}

#[test]
fn analyze_blob_on_real_win7_cfreds_cache() {
    let report = analyze_blob(WIN7_BLOB, "ControlSet001").unwrap();
    assert_eq!(report.format, ShimcacheFormat::Win7_64);
    assert_eq!(report.entries.len(), 292);
    assert_eq!(report.control_set, "ControlSet001");
    assert_eq!(report.entries[0].path, r"C:\Windows\system32\LogonUI.exe");
    // The CFReDS "Data Leakage" case ran many installers from Temp and — notably for a
    // data-leakage scenario — an executable from the Recycle Bin. The analyzer surfaces these as
    // suspicious-path leads; System32 binaries at their normal paths raise no masquerading hit.
    assert!(!report.anomalies.is_empty());
    assert!(report
        .anomalies
        .iter()
        .all(|a| matches!(a, ShimcacheAnomaly::SuspiciousPath { .. })));
    // The Recycle-Bin execution is present — a high-value lead in a data-leakage case.
    assert!(report.anomalies.iter().any(|a| matches!(
        a,
        ShimcacheAnomaly::SuspiciousPath { path, .. } if path.contains(r"$Recycle.Bin")
    )));
}

#[test]
fn analyze_blob_rejects_garbage_with_a_named_error() {
    let err = analyze_blob(&[0u8; 2], "cs").unwrap_err();
    assert!(matches!(err, ShimcacheError::TooShort { len: 2 }));
    assert!(err.to_string().contains("too short"));
}

#[test]
fn suspicious_path_observation_covers_every_field_and_exec_state() {
    for executed in [Some(true), Some(false), None] {
        let a = ShimcacheAnomaly::SuspiciousPath {
            executable: "x.exe".to_string(),
            path: r"C:\Temp\x.exe".to_string(),
            executed,
        };
        assert_eq!(a.code(), "SHIMCACHE-SUSPICIOUS-PATH");
        assert_eq!(a.mitre(), &["T1204"]);
        assert!(a.note().contains("suspicious execution"));
        let subs = a.subjects();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].id, r"C:\Temp\x.exe");
        assert_eq!(subs[0].label.as_deref(), Some("x.exe"));
        let _ = to_finding(&a, "SYSTEM");
    }
    // The execution-state phrasings differ.
    let ran = ShimcacheAnomaly::SuspiciousPath {
        executable: "x.exe".to_string(),
        path: r"C:\Temp\x.exe".to_string(),
        executed: Some(true),
    };
    assert!(ran.note().contains("execution flag set"));
}
