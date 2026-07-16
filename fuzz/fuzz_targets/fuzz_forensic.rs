//! Fuzz target: run the analyzer over arbitrary AppCompatCache value bytes.
//! Invariant: `analyze_blob` never panics; findings are derived without unwrap.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = shimcache_forensic::analyze_blob(data, "fuzz");
});
