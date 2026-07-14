//! `shimcache4n6` — read a Windows `SYSTEM` hive's AppCompatCache (ShimCache) and print the shimmed
//! executables (path, last-modification time, execution flag) plus graded findings.
//!
//! The decoding + analysis live in the `shimcache_forensic` / `shimcache_core` libraries; this
//! binary only wires `winreg-core` (open the hive, extract the `AppCompatCache` value) to
//! [`shimcache_forensic::analyze_blob`] and renders the result.
#![forbid(unsafe_code)]

use std::io::Cursor;
use std::process::ExitCode;

use forensicnomicon::report::Observation;
use shimcache_forensic::{analyze_blob, ShimcacheAnomaly, ShimcacheReport};
use winreg_core::hive::Hive;
use winreg_core::key::filetime_to_datetime;

/// The AppCompatCache key path within a control set. `Session Manager` has a space; `winreg-core`
/// splits the path on backslashes.
const APPCOMPAT_SUBPATH: &str = r"Control\Session Manager\AppCompatCache";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let list = args.iter().any(|a| a == "--list");
    let Some(hive_path) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("usage: shimcache4n6 <SYSTEM-hive> [--list]   (--list dumps every cache entry)");
        return ExitCode::from(2);
    };

    match run(hive_path) {
        Ok(report) => {
            print_report(&report, list);
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("shimcache4n6: {hive_path}: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// Open the hive, extract the AppCompatCache value, and analyze it. Returns a human message on
/// any failure (the binary reports it and exits non-zero).
fn run(hive_path: &str) -> Result<ShimcacheReport, String> {
    let hive = Hive::from_path(std::path::Path::new(hive_path)).map_err(|e| format!("{e}"))?;
    let (control_set, blob) = appcompatcache_blob(&hive)?;
    analyze_blob(&blob, control_set).map_err(|e| format!("{e}"))
}

/// Find the `AppCompatCache` value across the hive's control sets (`ControlSet001` then `002`,
/// the standard forensic order). Returns the control-set name and the raw blob.
fn appcompatcache_blob(hive: &Hive<Cursor<Vec<u8>>>) -> Result<(String, Vec<u8>), String> {
    for cs in ["ControlSet001", "ControlSet002"] {
        let key_path = format!("{cs}\\{APPCOMPAT_SUBPATH}");
        let Some(key) = hive.open_key(&key_path).map_err(|e| format!("{e}"))? else {
            continue;
        };
        if let Some(value) = key.value("AppCompatCache").map_err(|e| format!("{e}"))? {
            let blob = value.raw_data().map_err(|e| format!("{e}"))?;
            if !blob.is_empty() {
                return Ok((cs.to_string(), blob));
            }
        }
    }
    Err("no AppCompatCache value found (checked ControlSet001/002 Session Manager)".to_string())
}

fn print_report(report: &ShimcacheReport, list: bool) {
    println!(
        "AppCompatCache: {:?}, {}, {} entries",
        report.format,
        report.control_set,
        report.entries.len()
    );

    if report.anomalies.is_empty() {
        println!("Findings: none");
    } else {
        println!("Findings ({}):", report.anomalies.len());
        for a in &report.anomalies {
            let sev = a
                .severity()
                .map_or_else(|| "INFO".to_string(), |s| format!("{s:?}").to_uppercase());
            println!("  [{sev}] {}  {}", a.code(), subject_path(a));
            println!("    {}", a.note());
        }
    }

    if list {
        println!("\nEntries (most-recent first):");
        for e in &report.entries {
            let when = filetime_to_datetime(e.last_modified_filetime)
                .map_or_else(|| "-".to_string(), |t| t.to_string());
            let exec = match e.executed {
                Some(true) => "executed",
                Some(false) => "present",
                None => "-",
            };
            println!("  {when}  {exec:<8}  {}", e.path);
        }
    }
}

/// The path a finding points at (for the one-line summary).
fn subject_path(a: &ShimcacheAnomaly) -> &str {
    match a {
        ShimcacheAnomaly::SystemBinaryRelocated { path, .. }
        | ShimcacheAnomaly::SuspiciousPath { path, .. } => path,
    }
}
