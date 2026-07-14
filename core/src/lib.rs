//! Pure-Rust read-only decoder for the Windows **AppCompatCache** (ShimCache) registry value
//! blob — the `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`
//! `AppCompatCache` value. It decodes the versioned binary blob (Windows 7, 8.0, 8.1, 10)
//! into typed [`ShimcacheEntry`]s: the executable **path**, the file's **last-modification
//! FILETIME**, and — where the format records it — an **execution flag**.
//!
//! This crate is a *decoder primitive*: it takes the raw value bytes and never touches the
//! registry (the [`shimcache-forensic`] crate reads the blob out of a hive with `winreg-core`).
//! Like the fleet's other format decoders it is `#![forbid(unsafe_code)]` and **panic-free**:
//! every field read is bounds-checked, a malformed blob yields an error or a skipped entry,
//! never a panic.
//!
//! Format structures follow libyal's authoritative dtfabric specification
//! (`winreg-kb/winregrc/appcompatcache.yaml`). The ShimCache "last modification time" is the
//! file's own last-modified `FILETIME` — **not** an execution time; on Windows 7 the execution
//! bit (`insertion_flags & 0x2`) is the execution witness, absent from the Windows 10 format.
//!
//! [`shimcache-forensic`]: https://crates.io/crates/shimcache-forensic

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::fmt;

/// AppCompatCache header signatures (value at offset 0). For Windows 8/10 the signature value
/// is also the header size (offset to the first cached entry).
mod signature {
    pub const WINXP: u32 = 0xdead_beef;
    pub const WIN2003_VISTA: u32 = 0xbadc_0ffe;
    pub const WIN7: u32 = 0xbadc_0fee;
    pub const WIN8: u32 = 0x80;
    pub const WIN10: u32 = 0x30;
    pub const WIN10_CREATORS: u32 = 0x34;
}

/// Windows 8/10 per-entry record signature (`10ts` / `00ts`), little-endian at the entry start.
const ENTRY_SIG_8_1: &[u8; 4] = b"10ts";
const ENTRY_SIG_8_0: &[u8; 4] = b"00ts";

/// The detected AppCompatCache format variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimcacheFormat {
    /// Windows XP 32-bit (fixed 552-byte entries with an inline 528-byte path).
    WinXp,
    /// Windows Server 2003 / Vista / 2008 (`0xbadc0ffe`), 32-bit cached entries.
    Win2003_32,
    /// Windows Server 2003 / Vista / 2008 (`0xbadc0ffe`), 64-bit cached entries.
    Win2003_64,
    /// Windows 7 / Server 2008 R2, 32-bit cached entries.
    Win7_32,
    /// Windows 7 / Server 2008 R2, 64-bit cached entries.
    Win7_64,
    /// Windows 8.0 / Server 2012.
    Win8_0,
    /// Windows 8.1 / Server 2012 R2.
    Win8_1,
    /// Windows 10 / 11 (both the pre-Creators `0x30` and Creators `0x34` header sizes).
    Win10,
}

/// One decoded AppCompatCache entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimcacheEntry {
    /// The executable path, with a leading `\??\` device prefix stripped.
    pub path: String,
    /// The file's last-modification time as a raw Windows `FILETIME` (100 ns ticks since
    /// 1601-01-01 UTC). `0` when the entry carries no timestamp.
    pub last_modified_filetime: u64,
    /// Whether the entry's execution flag is set. `Some(true)`/`Some(false)` on Windows 7/8
    /// (the `insertion_flags & 0x2` bit); `None` on Windows 10, whose format dropped the flag.
    pub executed: Option<bool>,
}

/// A decode failure. Legacy formats and unknown signatures name the offending value so an
/// examiner can identify the blob (never a bare "unsupported").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShimcacheError {
    /// The blob is shorter than the smallest possible header.
    TooShort {
        /// Actual blob length.
        len: usize,
    },
    /// The header signature is not a recognized AppCompatCache format.
    UnknownSignature {
        /// The 4-byte signature that was found (little-endian u32).
        signature: u32,
    },
}

impl fmt::Display for ShimcacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { len } => {
                write!(f, "AppCompatCache blob too short: {len} bytes")
            }
            Self::UnknownSignature { signature } => {
                write!(f, "unknown AppCompatCache signature 0x{signature:08x}")
            }
        }
    }
}

impl std::error::Error for ShimcacheError {}

/// Detect the AppCompatCache format from the blob header. `None` when the blob is too short or
/// the signature is unrecognized.
#[must_use]
pub fn detect_format(blob: &[u8]) -> Option<ShimcacheFormat> {
    let sig = read_u32(blob, 0)?;
    match sig {
        signature::WINXP => Some(ShimcacheFormat::WinXp),
        signature::WIN2003_VISTA => Some(detect_2003_bitness(blob)),
        signature::WIN7 => Some(detect_win7_bitness(blob)),
        signature::WIN8 => win8_entry_variant(blob).map(|is_8_1| {
            if is_8_1 {
                ShimcacheFormat::Win8_1
            } else {
                ShimcacheFormat::Win8_0
            }
        }),
        signature::WIN10 | signature::WIN10_CREATORS => Some(ShimcacheFormat::Win10),
        _ => None,
    }
}

/// For a Windows 8 header, read the first cached-entry signature at offset 128 and report which
/// variant it is: `Some(true)` for 8.1 (`10ts`), `Some(false)` for 8.0 (`00ts`), `None` otherwise.
fn win8_entry_variant(blob: &[u8]) -> Option<bool> {
    match blob.get(128..132) {
        Some(s) if s == ENTRY_SIG_8_1.as_slice() => Some(true),
        Some(s) if s == ENTRY_SIG_8_0.as_slice() => Some(false),
        _ => None,
    }
}

/// Parse an AppCompatCache value blob into its entries.
///
/// # Errors
/// Returns [`ShimcacheError`] for a too-short blob, an unknown signature, or a recognized but
/// undecoded legacy (XP/2003/Vista) format. Individual malformed entries are skipped, not fatal.
pub fn parse(blob: &[u8]) -> Result<Vec<ShimcacheEntry>, ShimcacheError> {
    let sig = read_u32(blob, 0).ok_or(ShimcacheError::TooShort { len: blob.len() })?;
    match sig {
        signature::WINXP => Ok(parse_xp(blob)),
        signature::WIN2003_VISTA => Ok(parse_2003(blob, detect_2003_bitness(blob))),
        signature::WIN7 => Ok(parse_win7(blob, detect_win7_bitness(blob))),
        signature::WIN8 => match win8_entry_variant(blob) {
            Some(is_8_1) => Ok(parse_win8(blob, 128, is_8_1)),
            None => Err(ShimcacheError::UnknownSignature { signature: sig }),
        },
        signature::WIN10 | signature::WIN10_CREATORS => Ok(parse_win10(blob, sig as usize)),
        _ => Err(ShimcacheError::UnknownSignature { signature: sig }),
    }
}

/// Windows XP header is 400 bytes (signature, entry count, LRU table); each cached entry is a
/// fixed 552 bytes — a 528-byte inline UTF-16LE path (`MAX_PATH`, NUL-padded) followed by the
/// last-modification `FILETIME`, file size, and last-update time. XP records no execution flag.
const XP_HEADER: usize = 400;
const XP_ENTRY: usize = 552;
const XP_PATH_BYTES: usize = 528;

fn parse_xp(blob: &[u8]) -> Vec<ShimcacheEntry> {
    let _ = blob; // RED stub
    Vec::new()
}

/// Windows 2003/Vista/2008 (`0xbadc0ffe`): an 8-byte header (signature, count) then fixed-size
/// records whose path lives at an absolute `path_offset`. The 32-bit record is 24 bytes, the
/// 64-bit 32 bytes; the path (`path_size`@0, `path_offset`@4/@8) and last-modification time are at
/// the same offsets in both, so path + time decode unambiguously (the trailing field — file size
/// on 2003, flags on Vista — is not needed and no execution flag is surfaced).
const WIN2003_HEADER: usize = 8;
const WIN2003_ENTRY_32: usize = 24;
const WIN2003_ENTRY_64: usize = 32;

fn detect_2003_bitness(blob: &[u8]) -> ShimcacheFormat {
    // Default to 32-bit; pick 64-bit only when its first path_offset (a u64 at entry offset 8)
    // lands past the 64-bit records region and inside the blob — a structural check.
    let n = read_u32(blob, 4).unwrap_or(0) as usize;
    let po64 = read_u64(blob, WIN2003_HEADER + 8);
    let end64 = (WIN2003_HEADER + n.saturating_mul(WIN2003_ENTRY_64)) as u64;
    let len = blob.len() as u64;
    if po64.is_some_and(|p| p >= end64 && p < len && p % 2 == 0) {
        ShimcacheFormat::Win2003_64
    } else {
        ShimcacheFormat::Win2003_32
    }
}

fn parse_2003(blob: &[u8], fmt: ShimcacheFormat) -> Vec<ShimcacheEntry> {
    let _ = (blob, fmt); // RED stub
    Vec::new()
}

/// Windows 7 header is 128 bytes; the fixed-size entry records begin there and the path strings
/// live in a region after all the records (each entry points to its path by absolute offset).
/// 32-bit records are 32 bytes, 64-bit are 48 — derive which from where the first path points:
/// the region after `n` records of each size, and pick the layout whose first `path_offset`
/// lands at or beyond its own records region and inside the blob.
const WIN7_HEADER: usize = 128;
const WIN7_ENTRY_32: usize = 32;
const WIN7_ENTRY_64: usize = 48;

fn detect_win7_bitness(blob: &[u8]) -> ShimcacheFormat {
    let n = read_u32(blob, 4).unwrap_or(0) as usize;
    // 32-bit: path_offset is a u32 at entry offset 4; 64-bit: a u64 at entry offset 8.
    let po32 = read_u32(blob, WIN7_HEADER + 4).map(u64::from);
    let po64 = read_u64(blob, WIN7_HEADER + 8);
    let end32 = WIN7_HEADER + n.saturating_mul(WIN7_ENTRY_32);
    let end64 = WIN7_HEADER + n.saturating_mul(WIN7_ENTRY_64);
    let len = blob.len() as u64;
    let ok =
        |po: Option<u64>, end: usize| po.is_some_and(|p| p >= end as u64 && p < len && p % 2 == 0);
    // Prefer 64-bit (the dominant modern case) when both look plausible; only pick 32-bit when
    // it is the one that validates. This is structural, not a guess at a padding byte.
    if ok(po64, end64) {
        ShimcacheFormat::Win7_64
    } else if ok(po32, end32) {
        ShimcacheFormat::Win7_32
    } else {
        ShimcacheFormat::Win7_64
    }
}

fn parse_win7(blob: &[u8], fmt: ShimcacheFormat) -> Vec<ShimcacheEntry> {
    let n = read_u32(blob, 4).unwrap_or(0) as usize;
    let entry_size = if fmt == ShimcacheFormat::Win7_32 {
        WIN7_ENTRY_32
    } else {
        WIN7_ENTRY_64
    };
    let mut out = Vec::new();
    for i in 0..n {
        let base = WIN7_HEADER + i * entry_size;
        let Some(path_size) = read_u16(blob, base) else {
            break;
        };
        let (path_offset, last_mod, ins_flags) = if fmt == ShimcacheFormat::Win7_32 {
            let po = read_u32(blob, base + 4).map(u64::from);
            (po, read_u64(blob, base + 8), read_u32(blob, base + 16))
        } else {
            (
                read_u64(blob, base + 8),
                read_u64(blob, base + 16),
                read_u32(blob, base + 24),
            )
        };
        let (Some(po), Some(lm), Some(flags)) = (path_offset, last_mod, ins_flags) else {
            continue;
        };
        let Some(path) = read_utf16_path(blob, po as usize, path_size as usize) else {
            continue;
        };
        out.push(ShimcacheEntry {
            path,
            last_modified_filetime: lm,
            executed: Some(flags & 0x2 != 0),
        });
    }
    out
}

/// Windows 8.0/8.1 entries are self-delimiting: each begins with a `00ts`/`10ts` signature and a
/// `cached_entry_data_size`, and the path is stored inline. Walk from `start` (offset 128).
fn parse_win8(blob: &[u8], start: usize, is_8_1: bool) -> Vec<ShimcacheEntry> {
    let mut out = Vec::new();
    let mut off = start;
    let sig = if is_8_1 { ENTRY_SIG_8_1 } else { ENTRY_SIG_8_0 };
    loop {
        if blob.get(off..off + 4) != Some(sig.as_slice()) {
            break;
        }
        // header: signature(4) + unknown1(4) + cached_entry_data_size(4)
        let Some(data_size) = read_u32(blob, off + 8) else {
            break;
        };
        let body = off + 12;
        let Some(path_size) = read_u16(blob, body) else {
            break;
        };
        let path_start = body + 2;
        let Some(path) = read_utf16_inline(blob, path_start, path_size as usize) else {
            break;
        };
        // after the inline path: insertion_flags(4) + shim_flags(4) [+ unknown1(2) on 8.1] + last_mod(8)
        let after_path = path_start + path_size as usize;
        let lm_off = if is_8_1 {
            after_path + 4 + 4 + 2
        } else {
            after_path + 4 + 4
        };
        let ins_flags = read_u32(blob, after_path).unwrap_or(0);
        let last_mod = read_u64(blob, lm_off).unwrap_or(0);
        out.push(ShimcacheEntry {
            path,
            last_modified_filetime: last_mod,
            executed: Some(ins_flags & 0x2 != 0),
        });
        // advance by the whole record: 12-byte header + cached_entry_data_size body
        off = body + data_size as usize;
    }
    out
}

/// Windows 10 entries: `10ts` signature, inline path, last-modification `FILETIME`, no exec flag.
/// The header size (and thus first-entry offset) is the signature value (0x30 or 0x34).
fn parse_win10(blob: &[u8], header_size: usize) -> Vec<ShimcacheEntry> {
    let mut out = Vec::new();
    let mut off = header_size;
    loop {
        if blob.get(off..off + 4) != Some(ENTRY_SIG_8_1.as_slice()) {
            break;
        }
        // signature(4) + unknown1(4) + cached_entry_data_size(4)
        let Some(data_size) = read_u32(blob, off + 8) else {
            break;
        };
        let body = off + 12;
        let Some(path_size) = read_u16(blob, body) else {
            break;
        };
        let path_start = body + 2;
        let Some(path) = read_utf16_inline(blob, path_start, path_size as usize) else {
            break;
        };
        // after the inline path: last_modification_time(8) + data_size(4)
        let last_mod = read_u64(blob, path_start + path_size as usize).unwrap_or(0);
        out.push(ShimcacheEntry {
            path,
            last_modified_filetime: last_mod,
            executed: None,
        });
        off = body + data_size as usize;
    }
    out
}

// ── bounds-checked little-endian readers (panic-free) ───────────────────────────────────────

fn read_u16(blob: &[u8], off: usize) -> Option<u16> {
    blob.get(off..off + 2)?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}
fn read_u32(blob: &[u8], off: usize) -> Option<u32> {
    blob.get(off..off + 4)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}
fn read_u64(blob: &[u8], off: usize) -> Option<u64> {
    blob.get(off..off + 8)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

/// Read a UTF-16LE path of `size` bytes located at absolute `offset` (Windows 7 layout), and
/// strip a leading `\??\` device prefix. `None` if the region is out of bounds.
fn read_utf16_path(blob: &[u8], offset: usize, size: usize) -> Option<String> {
    read_utf16_inline(blob, offset, size)
}

/// Decode `size` bytes of UTF-16LE at `offset`, lossily, stripping a leading `\??\`.
fn read_utf16_inline(blob: &[u8], offset: usize, size: usize) -> Option<String> {
    let bytes = blob.get(offset..offset.checked_add(size)?)?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16_lossy(&units);
    Some(s.strip_prefix("\\??\\").unwrap_or(&s).to_string())
}

#[cfg(test)]
mod tests;
