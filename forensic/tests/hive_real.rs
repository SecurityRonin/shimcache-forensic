//! Tier-1 end-to-end validation of the `shim4n6` binary against a real `SYSTEM` hive — exercises
//! the `winreg-core` control-set navigation + `AppCompatCache` value extraction that the library's
//! `analyze_blob` does not. Env-gated on `SHIMCACHE_TEST_SYSTEM_HIVE`.
//!
//! Point it at the NIST CFReDS "Data Leakage" `SYSTEM` hive (public domain) — the same blob that
//! `core/tests/data/win7_appcompatcache.bin` was extracted from, so the whole-hive path must yield
//! the identical 292 entries plus the Recycle-Bin suspicious-execution lead.
#![allow(clippy::unwrap_used)]

#[test]
fn shim4n6_analyzes_a_real_system_hive_end_to_end() {
    let Ok(path) = std::env::var("SHIMCACHE_TEST_SYSTEM_HIVE") else {
        eprintln!("SKIP: set SHIMCACHE_TEST_SYSTEM_HIVE to a real SYSTEM hive (e.g. CFReDS)");
        return;
    };
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_shim4n6"))
        .arg(&path)
        .output()
        .expect("run shim4n6");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "shim4n6 failed: {:?}", out.status);
    // The whole-hive path reads Win7-64 AppCompatCache from ControlSet001 → 292 entries.
    assert!(
        stdout.contains("Win7_64, ControlSet001, 292 entries"),
        "unexpected summary; got: {stdout}"
    );
    // …and surfaces the Recycle-Bin execution lead (high-value in a data-leakage case).
    assert!(
        stdout.contains(r"$Recycle.Bin") && stdout.contains("SHIMCACHE-SUSPICIOUS-PATH"),
        "expected the Recycle-Bin suspicious-path finding; got: {stdout}"
    );
}
