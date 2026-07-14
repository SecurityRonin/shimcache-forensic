//! Unit tests: spec-faithful synthetic blobs for each format variant, error paths, and
//! panic-free robustness. The Windows 7 64-bit path is additionally validated Tier-1 against a
//! real CFReDS SYSTEM-hive blob in `tests/win7_real.rs`.

use super::*;

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Build a Windows 7 32-bit blob from `(path, filetime, executed)` entries, spec-faithful:
/// 128-byte header, 32-byte fixed records, then a path region the records point into.
fn build_win7_32(entries: &[(&str, u64, bool)]) -> Vec<u8> {
    let n = entries.len();
    let mut header = vec![0u8; 128];
    header[0..4].copy_from_slice(&signature::WIN7.to_le_bytes());
    header[4..8].copy_from_slice(&(n as u32).to_le_bytes());
    let records_start = 128;
    let paths_start = records_start + n * 32;
    let mut records = vec![0u8; n * 32];
    let mut paths = Vec::new();
    for (i, (path, ft, exec)) in entries.iter().enumerate() {
        let pbytes = utf16(path);
        let path_offset = (paths_start + paths.len()) as u32;
        let r = &mut records[i * 32..i * 32 + 32];
        r[0..2].copy_from_slice(&(pbytes.len() as u16).to_le_bytes()); // path_size
        r[2..4].copy_from_slice(&(pbytes.len() as u16).to_le_bytes()); // max_path_size
        r[4..8].copy_from_slice(&path_offset.to_le_bytes());
        r[8..16].copy_from_slice(&ft.to_le_bytes());
        r[16..20].copy_from_slice(&(if *exec { 2u32 } else { 0 }).to_le_bytes());
        paths.extend_from_slice(&pbytes);
    }
    [header, records, paths].concat()
}

/// Build a Windows 8.0/8.1 or Windows 10 blob (self-delimiting inline-path entries).
fn build_modern(
    sig: u32,
    entry_sig: [u8; 4],
    entries: &[(&str, u64, Option<bool>)],
    v8_1: bool,
    v10: bool,
) -> Vec<u8> {
    let header_size = if v10 { sig as usize } else { 128 };
    let mut out = vec![0u8; header_size];
    out[0..4].copy_from_slice(&sig.to_le_bytes());
    for (path, ft, exec) in entries {
        let pbytes = utf16(path);
        let mut body = Vec::new();
        body.extend_from_slice(&(pbytes.len() as u16).to_le_bytes()); // path_size
        body.extend_from_slice(&pbytes); // inline path
        if v10 {
            body.extend_from_slice(&ft.to_le_bytes()); // last_mod
            body.extend_from_slice(&0u32.to_le_bytes()); // data_size
        } else {
            let flags = if exec.unwrap_or(false) { 2u32 } else { 0 };
            body.extend_from_slice(&flags.to_le_bytes()); // insertion_flags
            body.extend_from_slice(&0u32.to_le_bytes()); // shim_flags
            if v8_1 {
                body.extend_from_slice(&0u16.to_le_bytes()); // unknown1
            }
            body.extend_from_slice(&ft.to_le_bytes()); // last_mod
            body.extend_from_slice(&0u32.to_le_bytes()); // data_size
        }
        out.extend_from_slice(&entry_sig);
        out.extend_from_slice(&0u32.to_le_bytes()); // unknown1
        out.extend_from_slice(&(body.len() as u32).to_le_bytes()); // cached_entry_data_size
        out.extend_from_slice(&body);
    }
    out
}

#[test]
fn win7_32bit_roundtrip() {
    let blob = build_win7_32(&[
        (
            "\\??\\C:\\Windows\\system32\\evil.exe",
            131_000_000_000_000_000,
            true,
        ),
        ("C:\\tool.dll", 130_000_000_000_000_000, false),
    ]);
    assert_eq!(detect_format(&blob), Some(ShimcacheFormat::Win7_32));
    let e = parse(&blob).unwrap();
    assert_eq!(e.len(), 2);
    assert_eq!(e[0].path, "C:\\Windows\\system32\\evil.exe"); // \??\ stripped
    assert_eq!(e[0].last_modified_filetime, 131_000_000_000_000_000);
    assert_eq!(e[0].executed, Some(true));
    assert_eq!(e[1].path, "C:\\tool.dll");
    assert_eq!(e[1].executed, Some(false));
}

#[test]
fn win8_0_inline_entries() {
    let blob = build_modern(
        signature::WIN8,
        *ENTRY_SIG_8_0,
        &[("C:\\a.exe", 42, Some(true))],
        false,
        false,
    );
    assert_eq!(detect_format(&blob), Some(ShimcacheFormat::Win8_0));
    let e = parse(&blob).unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].path, "C:\\a.exe");
    assert_eq!(e[0].last_modified_filetime, 42);
    assert_eq!(e[0].executed, Some(true));
}

#[test]
fn win8_1_has_the_extra_unknown_field() {
    let blob = build_modern(
        signature::WIN8,
        *ENTRY_SIG_8_1,
        &[("C:\\b.exe", 99, Some(false))],
        true,
        false,
    );
    assert_eq!(detect_format(&blob), Some(ShimcacheFormat::Win8_1));
    let e = parse(&blob).unwrap();
    assert_eq!(e[0].path, "C:\\b.exe");
    assert_eq!(e[0].last_modified_filetime, 99);
    assert_eq!(e[0].executed, Some(false));
}

#[test]
fn win10_has_no_exec_flag() {
    let blob = build_modern(
        signature::WIN10_CREATORS,
        *ENTRY_SIG_8_1,
        &[("C:\\c.exe", 7, None)],
        false,
        true,
    );
    assert_eq!(detect_format(&blob), Some(ShimcacheFormat::Win10));
    let e = parse(&blob).unwrap();
    assert_eq!(e[0].path, "C:\\c.exe");
    assert_eq!(e[0].last_modified_filetime, 7);
    assert_eq!(e[0].executed, None); // Windows 10 dropped the flag
}

#[test]
fn win10_pre_creators_0x30_header() {
    let blob = build_modern(
        signature::WIN10,
        *ENTRY_SIG_8_1,
        &[("C:\\d.exe", 5, None)],
        false,
        true,
    );
    assert_eq!(detect_format(&blob), Some(ShimcacheFormat::Win10));
    assert_eq!(parse(&blob).unwrap()[0].path, "C:\\d.exe");
}

#[test]
fn unknown_signature_names_the_value() {
    let blob = 0x1234_5678u32.to_le_bytes().to_vec();
    match parse(&blob) {
        Err(ShimcacheError::UnknownSignature { signature }) => assert_eq!(signature, 0x1234_5678),
        other => panic!("expected UnknownSignature, got {other:?}"),
    }
    // detect_format returns None for a recognized-length but unknown signature.
    assert_eq!(detect_format(&blob), None);
}

/// Build a Windows XP blob: 400-byte header + fixed 552-byte entries with a 528-byte inline path.
fn build_xp(entries: &[(&str, u64)]) -> Vec<u8> {
    let mut blob = vec![0u8; 400];
    blob[0..4].copy_from_slice(&signature::WINXP.to_le_bytes());
    blob[4..8].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    for (path, ft) in entries {
        let mut entry = vec![0u8; 552];
        let p = utf16(path);
        entry[..p.len()].copy_from_slice(&p);
        entry[528..536].copy_from_slice(&ft.to_le_bytes());
        blob.extend_from_slice(&entry);
    }
    blob
}

/// Build a Windows 2003 32-bit blob: 8-byte header + 24-byte records + a trailing path region.
fn build_2003_32(entries: &[(&str, u64)]) -> Vec<u8> {
    let n = entries.len();
    let mut header = vec![0u8; 8];
    header[0..4].copy_from_slice(&signature::WIN2003_VISTA.to_le_bytes());
    header[4..8].copy_from_slice(&(n as u32).to_le_bytes());
    let paths_start = 8 + n * 24;
    let mut records = vec![0u8; n * 24];
    let mut paths = Vec::new();
    for (i, (path, ft)) in entries.iter().enumerate() {
        let p = utf16(path);
        let off = (paths_start + paths.len()) as u32;
        let r = &mut records[i * 24..i * 24 + 24];
        r[0..2].copy_from_slice(&(p.len() as u16).to_le_bytes());
        r[2..4].copy_from_slice(&(p.len() as u16).to_le_bytes());
        r[4..8].copy_from_slice(&off.to_le_bytes());
        r[8..16].copy_from_slice(&ft.to_le_bytes());
        paths.extend_from_slice(&p);
    }
    [header, records, paths].concat()
}

#[test]
fn winxp_inline_path_entries() {
    let blob = build_xp(&[(r"\??\C:\WINDOWS\system32\evil.exe", 131_000_000_000_000_000)]);
    assert_eq!(detect_format(&blob), Some(ShimcacheFormat::WinXp));
    let e = parse(&blob).unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].path, r"C:\WINDOWS\system32\evil.exe"); // \??\ + trailing NULs stripped
    assert_eq!(e[0].last_modified_filetime, 131_000_000_000_000_000);
    assert_eq!(e[0].executed, None); // XP records no execution flag
}

#[test]
fn win2003_32bit_path_offset_entries() {
    let blob = build_2003_32(&[(r"C:\a.exe", 42), (r"C:\b.dll", 99)]);
    assert_eq!(detect_format(&blob), Some(ShimcacheFormat::Win2003_32));
    let e = parse(&blob).unwrap();
    assert_eq!(e.len(), 2);
    assert_eq!(e[0].path, r"C:\a.exe");
    assert_eq!(e[0].last_modified_filetime, 42);
    assert_eq!(e[1].path, r"C:\b.dll");
    assert_eq!(e[0].executed, None);
}

/// Build a Windows 2003 64-bit blob: 8-byte header + 32-byte records + a trailing path region.
fn build_2003_64(entries: &[(&str, u64)]) -> Vec<u8> {
    let n = entries.len();
    let mut header = vec![0u8; 8];
    header[0..4].copy_from_slice(&signature::WIN2003_VISTA.to_le_bytes());
    header[4..8].copy_from_slice(&(n as u32).to_le_bytes());
    let paths_start = 8 + n * 32;
    let mut records = vec![0u8; n * 32];
    let mut paths = Vec::new();
    for (i, (path, ft)) in entries.iter().enumerate() {
        let p = utf16(path);
        let off = (paths_start + paths.len()) as u64;
        let r = &mut records[i * 32..i * 32 + 32];
        r[0..2].copy_from_slice(&(p.len() as u16).to_le_bytes());
        r[2..4].copy_from_slice(&(p.len() as u16).to_le_bytes());
        r[8..16].copy_from_slice(&off.to_le_bytes());
        r[16..24].copy_from_slice(&ft.to_le_bytes());
        paths.extend_from_slice(&p);
    }
    [header, records, paths].concat()
}

#[test]
fn win2003_64bit_entries() {
    let blob = build_2003_64(&[(r"C:\x.exe", 7)]);
    assert_eq!(detect_format(&blob), Some(ShimcacheFormat::Win2003_64));
    let e = parse(&blob).unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].path, r"C:\x.exe");
    assert_eq!(e[0].last_modified_filetime, 7);
    assert_eq!(e[0].executed, None);
}

#[test]
fn xp_truncated_and_empty_entries_skip_cleanly() {
    // Header claims 3 entries but no room for any → break, no panic.
    let mut blob = vec![0u8; 402];
    blob[0..4].copy_from_slice(&signature::WINXP.to_le_bytes());
    blob[4..8].copy_from_slice(&3u32.to_le_bytes());
    assert!(parse(&blob).unwrap().is_empty());
    // An all-NUL (empty-path) entry is skipped.
    assert!(parse(&build_xp(&[("", 1)])).unwrap().is_empty());
}

#[test]
fn win2003_truncated_entries_skip_cleanly() {
    // Header claims 5 entries but the records are truncated → the missing fields → break/skip.
    let mut blob = vec![0u8; 10];
    blob[0..4].copy_from_slice(&signature::WIN2003_VISTA.to_le_bytes());
    blob[4..8].copy_from_slice(&5u32.to_le_bytes());
    assert!(parse(&blob).unwrap().is_empty());
    // A record whose path_offset points out of bounds is skipped.
    let mut b = vec![0u8; 8 + 24];
    b[0..4].copy_from_slice(&signature::WIN2003_VISTA.to_le_bytes());
    b[4..8].copy_from_slice(&1u32.to_le_bytes());
    b[8..10].copy_from_slice(&10u16.to_le_bytes()); // path_size
    b[12..16].copy_from_slice(&99_999u32.to_le_bytes()); // path_offset out of bounds
    assert!(parse(&b).unwrap().is_empty());
}

/// Build a valid Windows 7 64-bit blob (128-byte header, 48-byte records + path region).
fn build_win7_64(entries: &[(&str, u64, bool)]) -> Vec<u8> {
    let n = entries.len();
    let mut header = vec![0u8; 128];
    header[0..4].copy_from_slice(&signature::WIN7.to_le_bytes());
    header[4..8].copy_from_slice(&(n as u32).to_le_bytes());
    let paths_start = 128 + n * 48;
    let mut records = vec![0u8; n * 48];
    let mut paths = Vec::new();
    for (i, (path, ft, exec)) in entries.iter().enumerate() {
        let p = utf16(path);
        let off = (paths_start + paths.len()) as u64;
        let r = &mut records[i * 48..i * 48 + 48];
        r[0..2].copy_from_slice(&(p.len() as u16).to_le_bytes());
        r[2..4].copy_from_slice(&(p.len() as u16).to_le_bytes());
        r[8..16].copy_from_slice(&off.to_le_bytes());
        r[16..24].copy_from_slice(&ft.to_le_bytes());
        r[24..28].copy_from_slice(&(if *exec { 2u32 } else { 0 }).to_le_bytes());
        paths.extend_from_slice(&p);
    }
    [header, records, paths].concat()
}

#[test]
fn win7_64bit_roundtrip() {
    let blob = build_win7_64(&[(
        r"C:\Windows\System32\svchost.exe",
        130_000_000_000_000_000,
        true,
    )]);
    assert_eq!(detect_format(&blob), Some(ShimcacheFormat::Win7_64));
    let e = parse(&blob).unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].path, r"C:\Windows\System32\svchost.exe");
    assert_eq!(e[0].last_modified_filetime, 130_000_000_000_000_000);
    assert_eq!(e[0].executed, Some(true));
}

#[test]
fn too_short_blob_errors() {
    assert_eq!(parse(&[0u8; 2]), Err(ShimcacheError::TooShort { len: 2 }));
    assert_eq!(detect_format(&[0u8; 3]), None);
}

#[test]
fn truncated_entry_is_skipped_never_panics() {
    // A Win7 header claiming 5 entries but a blob with room for none — must not panic.
    let mut blob = vec![0u8; 130];
    blob[0..4].copy_from_slice(&signature::WIN7.to_le_bytes());
    blob[4..8].copy_from_slice(&5u32.to_le_bytes());
    let _ = parse(&blob); // no panic; returns whatever it can (likely empty)
}

#[test]
fn win8_stops_at_a_bad_entry_signature() {
    // Header ok, but the bytes at 128 are not 00ts/10ts → no entries, and detect_format None.
    let mut blob = vec![0u8; 200];
    blob[0..4].copy_from_slice(&signature::WIN8.to_le_bytes());
    blob[128..132].copy_from_slice(b"junk");
    assert_eq!(detect_format(&blob), None);
    assert!(matches!(
        parse(&blob),
        Err(ShimcacheError::UnknownSignature { .. })
    ));
}

#[test]
fn empty_utf16_and_non_ascii_paths_decode() {
    let blob = build_win7_32(&[("C:\\Ünïcödé\\日本語.exe", 1, true)]);
    let e = parse(&blob).unwrap();
    assert_eq!(e[0].path, "C:\\Ünïcödé\\日本語.exe");
}

/// Build a Windows 7 64-bit blob with one entry whose `path_offset` is set explicitly (used to
/// exercise the out-of-bounds path skip).
fn build_win7_64_one(path_size: u16, path_offset: u64) -> Vec<u8> {
    let mut blob = vec![0u8; 128 + 48];
    blob[0..4].copy_from_slice(&signature::WIN7.to_le_bytes());
    blob[4..8].copy_from_slice(&1u32.to_le_bytes());
    let r = &mut blob[128..176];
    r[0..2].copy_from_slice(&path_size.to_le_bytes());
    r[8..16].copy_from_slice(&path_offset.to_le_bytes());
    blob
}

#[test]
fn win7_entry_with_out_of_bounds_path_offset_is_skipped() {
    // path_offset points past the end of the blob → the entry is skipped, not a panic.
    let blob = build_win7_64_one(10, 9_999_999);
    assert_eq!(detect_format(&blob), Some(ShimcacheFormat::Win7_64));
    assert!(parse(&blob).unwrap().is_empty());
}

#[test]
fn win8_truncations_break_cleanly() {
    let mut base = vec![0u8; 132];
    base[0..4].copy_from_slice(&signature::WIN8.to_le_bytes());
    base[128..132].copy_from_slice(ENTRY_SIG_8_0);
    // (a) entry sig present but no cached_entry_data_size → break, zero entries.
    assert!(parse(&base).unwrap().is_empty());
    // (b) header + data_size but no path_size.
    let mut b = base.clone();
    b.extend_from_slice(&[0u8; 8]); // unknown1(4)+data_size(4)
    assert!(parse(&b).unwrap().is_empty());
    // (c) path_size claims more bytes than remain → path read fails, break.
    let mut c = base.clone();
    c.extend_from_slice(&0u32.to_le_bytes()); // unknown1
    c.extend_from_slice(&99u32.to_le_bytes()); // data_size
    c.extend_from_slice(&200u16.to_le_bytes()); // path_size=200 but nothing follows
    assert!(parse(&c).unwrap().is_empty());
}

#[test]
fn win10_truncations_break_cleanly() {
    let mut base = vec![0u8; signature::WIN10_CREATORS as usize];
    base[0..4].copy_from_slice(&signature::WIN10_CREATORS.to_le_bytes());
    base.extend_from_slice(ENTRY_SIG_8_1); // entry sig, then nothing → break at data_size
    assert!(parse(&base).unwrap().is_empty());
    // + data_size but no path_size
    let mut b = base.clone();
    b.extend_from_slice(&[0u8; 8]);
    assert!(parse(&b).unwrap().is_empty());
    // + path_size too large
    let mut c = base.clone();
    c.extend_from_slice(&0u32.to_le_bytes());
    c.extend_from_slice(&99u32.to_le_bytes());
    c.extend_from_slice(&200u16.to_le_bytes());
    assert!(parse(&c).unwrap().is_empty());
}

#[test]
fn error_display_messages_show_the_offending_value() {
    assert!(ShimcacheError::TooShort { len: 3 }
        .to_string()
        .contains('3'));
    assert!(ShimcacheError::UnknownSignature {
        signature: 0xabad_1dea
    }
    .to_string()
    .contains("abad1dea"));
}

#[test]
fn win8_entry_variant_none_on_short_blob() {
    // A WIN8 signature but a blob too short to hold the entry signature at 128.
    let mut blob = signature::WIN8.to_le_bytes().to_vec();
    blob.resize(100, 0);
    assert_eq!(detect_format(&blob), None);
}
