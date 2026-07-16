//! Fuzz target: feed arbitrary bytes as an AppCompatCache value blob to the decoder.
//! Invariant: `parse`/`detect_format` never panic — a malformed blob yields an error or a
//! skipped entry, never an out-of-bounds index or arithmetic panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = shimcache_core::detect_format(data);
    let _ = shimcache_core::parse(data);
});
