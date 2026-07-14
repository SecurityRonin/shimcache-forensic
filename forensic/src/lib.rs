//! Windows **AppCompatCache** (ShimCache) forensic analyzer.
//!
//! ShimCache records, for each executable the OS shimmed, the file's path and last-modification
//! `FILETIME` — and, on Windows 7/8, whether it was *executed*. [`analyze_blob`] decodes an
//! AppCompatCache value blob (with [`shimcache_core`]) and [`audit`] adds a small set of
//! *high-precision* graded findings: a Windows system-binary name recorded at a non-`System32`
//! path (masquerading) and an entry in a known-suspicious directory.
//!
//! This is a *pure* library: it takes the already-extracted AppCompatCache value bytes. Reading
//! that value out of a `SYSTEM` hive is `winreg-core`'s job — the bundled `shimcache4n6` binary wires
//! the two together (`winreg-core` → this crate), so a consumer that already has a hive open can
//! do the same 5-line extraction with `winreg-core` and call [`analyze_blob`].
//!
//! Findings are observations, never verdicts: ShimCache establishes that a binary at a given path
//! was shimmed (and, on Win7/8, executed) — whether that is malicious is a correlation/tribunal
//! question. Note the well-known caveat that ShimCache *presence* alone is not proof of execution
//! (the file may only have been browsed to); the Windows 7/8 execution flag is the execution
//! witness, and Windows 10 dropped it entirely.
//!
//! Built on [`shimcache_core`]; findings use [`forensicnomicon::report`].

#![forbid(unsafe_code)]

use forensicnomicon::report::{Category, Finding, Observation, Severity, Source, SubjectRef};
use shimcache_core::ShimcacheError;

// Re-export the core types that appear in this crate's public API so consumers need only depend
// on `shimcache-forensic`.
pub use shimcache_core::{ShimcacheEntry, ShimcacheFormat};

/// The result of analyzing an AppCompatCache value.
#[derive(Debug, Clone)]
pub struct ShimcacheReport {
    /// The control set the value was read from (e.g. `ControlSet001`), for provenance.
    pub control_set: String,
    /// The detected AppCompatCache format.
    pub format: ShimcacheFormat,
    /// The decoded cache entries, in cache order (most-recent first).
    pub entries: Vec<ShimcacheEntry>,
    /// Graded anomalies (may be empty).
    pub anomalies: Vec<ShimcacheAnomaly>,
}

/// A graded ShimCache finding. Each variant is a *high-precision* triage signal — it stays quiet
/// on benign entries (a normal `System32` binary) and fires only on a genuinely anomalous pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShimcacheAnomaly {
    /// A Windows system-binary *name* recorded at a path that is not under `System32`/`SysWOW64`
    /// — consistent with masquerading (`T1036.005`).
    SystemBinaryRelocated {
        /// The system-binary base name (e.g. `SVCHOST.EXE`).
        name: String,
        /// The full path ShimCache recorded.
        path: String,
    },
    /// An entry whose path is a directory commonly used to stage malware (Temp, Downloads,
    /// `$Recycle.Bin`, …) — `T1204`. `executed` carries the Win7/8 execution flag when known.
    SuspiciousPath {
        /// The executable base name.
        executable: String,
        /// The suspicious path.
        path: String,
        /// Whether the entry's execution flag was set (`None` on Windows 10).
        executed: Option<bool>,
    },
}

/// Decode an AppCompatCache value blob and audit it. `control_set` is recorded on the report for
/// provenance (pass e.g. `"ControlSet001"`, or `""` if unknown).
///
/// # Errors
/// [`ShimcacheError`] if the blob is not a recognized AppCompatCache format.
pub fn analyze_blob(
    blob: &[u8],
    control_set: impl Into<String>,
) -> Result<ShimcacheReport, ShimcacheError> {
    let entries = shimcache_core::parse(blob)?;
    // parse() succeeding implies a recognized signature, so detect_format is Some; guard anyway.
    let format =
        shimcache_core::detect_format(blob).ok_or(ShimcacheError::TooShort { len: blob.len() })?;
    let anomalies = audit(&entries);
    Ok(ShimcacheReport {
        control_set: control_set.into(),
        format,
        entries,
        anomalies,
    })
}

/// Audit decoded ShimCache entries for graded anomalies (may be empty).
#[must_use]
pub fn audit(entries: &[ShimcacheEntry]) -> Vec<ShimcacheAnomaly> {
    let mut out = Vec::new();
    for e in entries {
        let name = base_name(&e.path);
        let upper = e.path.to_uppercase();
        let in_system = upper.contains(r"\SYSTEM32\") || upper.contains(r"\SYSWOW64\");
        // System-binary baseline + suspicious-location list are shared DFIR knowledge — they
        // live in forensicnomicon, not baked in here.
        if forensicnomicon::processes::is_system32_binary(&name) && !in_system {
            out.push(ShimcacheAnomaly::SystemBinaryRelocated {
                name: name.to_uppercase(),
                path: e.path.clone(),
            });
        }
        if forensicnomicon::heuristics::paths::is_suspicious_exec_path(&e.path) {
            out.push(ShimcacheAnomaly::SuspiciousPath {
                executable: name,
                path: e.path.clone(),
                executed: e.executed,
            });
        }
    }
    out
}

/// The base name (last `\`/`/`-component) of a Windows path.
fn base_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

impl Observation for ShimcacheAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(match self {
            ShimcacheAnomaly::SystemBinaryRelocated { .. } => Severity::High,
            ShimcacheAnomaly::SuspiciousPath { .. } => Severity::Medium,
        })
    }

    fn category(&self) -> Category {
        match self {
            ShimcacheAnomaly::SystemBinaryRelocated { .. } => Category::Concealment,
            ShimcacheAnomaly::SuspiciousPath { .. } => Category::Threat,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            ShimcacheAnomaly::SystemBinaryRelocated { .. } => "SHIMCACHE-SYSTEM-BINARY-RELOCATED",
            ShimcacheAnomaly::SuspiciousPath { .. } => "SHIMCACHE-SUSPICIOUS-PATH",
        }
    }

    fn note(&self) -> String {
        match self {
            ShimcacheAnomaly::SystemBinaryRelocated { name, path } => format!(
                "{name} is a Windows system binary, but AppCompatCache recorded it at {path} \
                 — consistent with masquerading."
            ),
            ShimcacheAnomaly::SuspiciousPath {
                executable,
                path,
                executed,
            } => {
                let ran = match executed {
                    Some(true) => " (execution flag set)",
                    Some(false) => " (no execution flag)",
                    None => "",
                };
                format!(
                    "{executable} at {path} sits in a directory commonly used to stage malware\
                     {ran} — consistent with suspicious execution."
                )
            }
        }
    }

    fn mitre(&self) -> &'static [&'static str] {
        match self {
            ShimcacheAnomaly::SystemBinaryRelocated { .. } => &["T1036.005"],
            ShimcacheAnomaly::SuspiciousPath { .. } => &["T1204"],
        }
    }

    fn subjects(&self) -> Vec<SubjectRef> {
        let (name, path) = match self {
            ShimcacheAnomaly::SystemBinaryRelocated { name, path } => (name, path),
            ShimcacheAnomaly::SuspiciousPath {
                executable, path, ..
            } => (executable, path),
        };
        vec![SubjectRef {
            scheme: "filesystem".to_string(),
            kind: "executable".to_string(),
            id: path.clone(),
            label: Some(name.clone()),
        }]
    }
}

/// Convenience: produce a [`Finding`] for an anomaly under the given scope.
#[must_use]
pub fn to_finding(anomaly: &ShimcacheAnomaly, scope: impl Into<String>) -> Finding {
    anomaly.to_finding(Source {
        analyzer: "shimcache-forensic".to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    })
}

#[cfg(test)]
mod tests;
