//! Go build ID extraction.
//!
//! Every Go binary contains a build ID: a string derived from SHA256 hashes of the
//! compilation inputs and outputs. For executables, the format is:
//!
//! ```text
//! actionID/actionID/contentID/contentID
//! ```
//!
//! where each part is 20 characters of URL-safe base64 (alphabet:
//! `A-Za-z0-9-_`, encoding the first 120 bits of a SHA256 hash).
//!
//! ## Embedding Formats
//!
//! The build ID is stored differently depending on the binary format:
//!
//! ### ELF: PT_NOTE segment
//!
//! ```text
//! Section: .note.go.buildid
//! Note name:  "Go\x00\x00"  (4 bytes)
//! Note tag:   4              (ELF_NOTE_GOBUILDID_TAG)
//! Note desc:  <build ID string bytes>
//! ```
//!
//! Additional ELF note tags defined in `src/cmd/link/internal/ld/elf.go:965-973`:
//! - Tag 1: `GOPKGLIST` (package list)
//! - Tag 2: `GOABIHASH` (ABI hash)
//! - Tag 3: `GODEPS` (dependencies)
//! - Tag 4: `GOBUILDID` (build ID)
//!
//! ### Mach-O / PE / Plan9: Raw text-segment marker
//!
//! ```text
//! \xff Go build ID: "<build_id_string>"\n \xff
//! ```
//!
//! Placed at the very beginning of the text segment as symbol `go:buildid`.
//!
//! Source: `src/cmd/internal/buildid/buildid.go:241-242` (marker constants),
//! `src/cmd/link/internal/ld/data.go:2590-2607` (linker embedding).

use crate::{
    detection::find_bytes,
    formats::{BinaryContext, BinaryFormat},
};

/// Raw build ID prefix in non-ELF binaries.
///
/// Byte sequence: `ff 20 47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22`
///
/// Source: `src/cmd/internal/buildid/buildid.go:241`
const BUILD_ID_PREFIX: &[u8] = b"\xff Go build ID: \"";

/// Raw build ID suffix in non-ELF binaries.
///
/// Byte sequence: `22 0a 20 ff`
///
/// Source: `src/cmd/internal/buildid/buildid.go:242`
const BUILD_ID_SUFFIX: &[u8] = b"\"\n \xff";

/// ELF note name for Go notes: `"Go\x00\x00"` (4 bytes, null-padded).
///
/// Source: `src/cmd/internal/buildid/note.go:73`
const ELF_GO_NOTE_NAME: &[u8] = b"Go\x00\x00";

/// ELF note tag value for the Go build ID.
///
/// Source: `src/cmd/link/internal/ld/elf.go:970`
const ELF_NOTE_GOBUILDID_TAG: u32 = 4;

/// Maximum number of bytes to scan for the raw build ID marker.
///
/// The linker places `go:buildid` at the very start of the text segment, so 64KB
/// is more than enough to cover the initial headers + text start on any format.
const RAW_SEARCH_LIMIT: usize = 65536;

/// Extract the Go build ID from a binary.
///
/// For ELF binaries, first tries the structured `PT_NOTE` path (faster, more
/// reliable), then falls back to raw marker scanning.
/// For Mach-O and PE, uses raw marker scanning only.
pub fn extract(ctx: &BinaryContext<'_>) -> Option<String> {
    match ctx.format() {
        BinaryFormat::Elf => extract_elf_note(ctx).or_else(|| extract_raw_marker(ctx.data())),
        _ => extract_raw_marker(ctx.data()),
    }
}

/// Scan for the raw text-segment marker: `\xff Go build ID: "..."\n \xff`.
///
/// The build ID string between the quotes is extracted verbatim. It may contain
/// Go string escape sequences (the Go toolchain uses `strconv.Quote`), but in
/// practice build IDs are pure ASCII base64 characters.
fn extract_raw_marker(data: &[u8]) -> Option<String> {
    let search_end = data.len().min(RAW_SEARCH_LIMIT);
    let prefix_pos = find_bytes(&data[..search_end], BUILD_ID_PREFIX)?;
    let id_start = prefix_pos + BUILD_ID_PREFIX.len();

    // Look for the suffix within 1KB of the prefix (build IDs are ~83 chars)
    let search_window = &data[id_start..data.len().min(id_start + 1024)];
    let suffix_pos = find_bytes(search_window, BUILD_ID_SUFFIX)?;

    String::from_utf8(data[id_start..id_start + suffix_pos].to_vec()).ok()
}

/// Extract build ID from ELF `PT_NOTE` segments.
///
/// Uses pre-parsed note segment ranges from [`BinaryContext`] rather than
/// re-parsing the ELF.
///
/// ## ELF Note Layout (per note entry)
///
/// ```text
/// Offset  Size  Field
/// 0       4     namesz  (name length including null padding)
/// 4       4     descsz  (descriptor/value length)
/// 8       4     type    (note tag)
/// 12      N     name    (null-padded to 4-byte alignment)
/// 12+N    M     desc    (null-padded to 4-byte alignment)
/// ```
fn extract_elf_note(ctx: &BinaryContext<'_>) -> Option<String> {
    for note_data in ctx.elf_note_segments() {
        if let Some(id) = parse_go_note(note_data) {
            return Some(id);
        }
    }
    None
}

/// Walk an ELF note segment looking for the Go build ID note.
fn parse_go_note(data: &[u8]) -> Option<String> {
    let mut pos = 0;
    while pos + 12 <= data.len() {
        let namesz = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
        let descsz = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().ok()?) as usize;
        let note_type = u32::from_le_bytes(data[pos + 8..pos + 12].try_into().ok()?);

        let name_start = pos + 12;
        let name_padded = align4(namesz);
        let desc_start = name_start + name_padded;
        let desc_padded = align4(descsz);

        if desc_start + descsz > data.len() {
            break;
        }

        if namesz == 4
            && note_type == ELF_NOTE_GOBUILDID_TAG
            && &data[name_start..name_start + 4] == ELF_GO_NOTE_NAME
        {
            return String::from_utf8(data[desc_start..desc_start + descsz].to_vec()).ok();
        }

        pos = desc_start + desc_padded;
    }
    None
}

/// Round `n` up to the nearest multiple of 4 (ELF note alignment).
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_raw_marker() {
        let mut data = vec![0u8; 0x1000];
        let marker = b"\xff Go build ID: \"abc123/def456\"\n \xff";
        data[0..marker.len()].copy_from_slice(marker);

        let id = extract_raw_marker(&data).unwrap();
        assert_eq!(id, "abc123/def456");
    }

    #[test]
    fn test_raw_marker_not_found() {
        let data = vec![0u8; 0x1000];
        assert!(extract_raw_marker(&data).is_none());
    }
}
