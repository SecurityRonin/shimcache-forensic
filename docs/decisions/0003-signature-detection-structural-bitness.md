# 3. Signature-based format detection with structural 32/64-bit disambiguation

Date: 2026-07-24
Status: Accepted

## Context

AppCompatCache has ~eight on-disk layouts across Windows versions (XP, Server
2003 / Vista / 2008, 7, 8.0, 8.1, 10/11), each with different header sizes, entry
strides, path storage (inline vs. offset-referenced), and endianness quirks. The
header's leading 4 bytes disambiguate most versions, but the 2003/Vista and
Windows 7 formats do **not** encode their pointer width — a 32-bit and a 64-bit
image share the same signature and differ only in record stride and field
offsets. Naively guessing a padding byte would be a fragile special case; the
global "No Special Cases — Solve the General Problem" discipline requires deriving
the layout from the data's structure.

## Decision

1. **Detect the version from the header signature** (`detect_format` /
   `parse` in `core/src/lib.rs`): `0xdeadbeef`→XP, `0xbadc0ffe`→2003/Vista,
   `0xbadc0fee`→Win7, `0x80`→Win8 (8.0 vs 8.1 resolved by the first cached-entry
   signature `00ts`/`10ts` at offset 128), `0x30`/`0x34`→Win10 (the signature
   value is also the header size / first-entry offset). All multi-byte fields are
   **little-endian** — the platform-native encoding of the Windows registry —
   read via the `read_u16/u32/u64` helpers.
2. **Disambiguate 32- vs 64-bit structurally, not by a magic byte.**
   `detect_2003_bitness` / `detect_win7_bitness` compute where the first entry's
   `path_offset` *would* point under each candidate stride and pick the layout
   whose offset lands at/after its own records region, inside the blob, and on an
   even (UTF-16-aligned) boundary. When both look plausible, prefer 64-bit (the
   dominant modern case). This is a validation of the format's own invariant, not
   a guess.
3. **Skip, don't crash, on malformed entries.** A per-entry decode that fails its
   bounds/consistency checks `break`s or `continue`s; the blob-level errors are
   limited to `TooShort` and `UnknownSignature`, and the latter names the
   offending 4-byte value (`ShimcacheError::UnknownSignature { signature }`) so an
   examiner can identify an unrecognized blob — per the fleet "Show the
   unrecognized value" rule.

## Consequences

- Every shipped AppCompatCache version decodes from one code path with no
  input-specific branches; a new member of a known layout class decodes by
  construction.
- Bitness detection is robust to the padding/reserved-byte variation that a
  hardcoded offset guess would break on.
- The offset/stride constants (`XP_ENTRY = 552`, `WIN7_HEADER = 128`,
  `WIN7_ENTRY_64 = 48`, …) are documented against libyal's dtfabric
  `appcompatcache.yaml` in the module comments and `docs/validation.md`; they are
  format facts, not tuned-to-a-fixture literals.
