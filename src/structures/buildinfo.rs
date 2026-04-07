//! Go build info extraction (version, module path, dependencies, build settings).
//!
//! The build info blob is a structured header embedded in every Go binary since Go 1.13.
//! It contains the Go toolchain version, the main module path, all dependency module
//! versions, and build settings (GOOS, GOARCH, VCS info, compiler flags, etc.).
//!
//! ## Binary Layout
//!
//! The blob lives in a dedicated section (`.go.buildinfo` on ELF, `__go_buildinfo`
//! on Mach-O, first writable PE section). It starts with a 32-byte header:
//!
//! ```text
//! Offset  Size   Field
//! 0       14     Magic: "\xff Go buildinf:" (literal bytes)
//! 14      1      ptrSize: pointer size (4 or 8)
//! 15      1      flags:
//!                  bit 0: endianness (0=little, 1=big)
//!                  bit 1: version format (0=pointer-based, 1=inline varint)
//! 16      16     Padding (zeros, to reach 32-byte total)
//! 32      var    Inline strings (Go 1.18+): varint-length-prefixed version,
//!                then varint-length-prefixed modinfo
//! ```
//!
//! The header requires 16-byte alignment in the binary.
//!
//! ## Module Info Format
//!
//! The modinfo string is framed by 16-byte binary sentinels:
//!
//! ```text
//! Start sentinel: 30 77 af 0c 92 74 08 02 41 e1 c1 07 e6 d6 18 e6
//! End sentinel:   f9 32 43 31 86 18 20 72 00 82 42 10 41 16 d8 f2
//! ```
//!
//! Between sentinels, a tab-delimited text block:
//! ```text
//! path\t<main_package_path>
//! mod\t<module_name>\t<version>
//! dep\t<dep_path>\t<version>\t<hash>
//! build\t<key>=<value>
//! ```
//!
//! ## Source References
//!
//! - Header format: `src/debug/buildinfo/buildinfo.go:58-203`
//! - Sentinel bytes: `src/cmd/go/internal/modload/build.go:29-30`
//! - Linker creation: `src/cmd/link/internal/ld/data.go:2609-2656`
//! - Modinfo parsing: `src/runtime/debug/mod.go:40-95`

use crate::{detection::find_bytes, formats::BinaryContext, metadata::BuildInfo};

/// Build info magic prefix: `"\xff Go buildinf:"` (14 bytes).
///
/// Source: `src/debug/buildinfo/buildinfo.go:58`
const BUILDINFO_MAGIC: &[u8] = b"\xff Go buildinf:";

/// The header must be placed at a 16-byte aligned address.
///
/// Source: `src/debug/buildinfo/buildinfo.go:61`
const BUILDINFO_ALIGN: usize = 16;

/// Total size of the build info header (magic + ptrSize + flags + padding).
///
/// Source: `src/debug/buildinfo/buildinfo.go:62`
const BUILDINFO_HEADER_SIZE: usize = 32;

/// Module info start sentinel (16 bytes).
///
/// Source: `src/cmd/go/internal/modload/build.go:29`
const MOD_INFO_START: &[u8] = &[
    0x30, 0x77, 0xaf, 0x0c, 0x92, 0x74, 0x08, 0x02, 0x41, 0xe1, 0xc1, 0x07, 0xe6, 0xd6, 0x18, 0xe6,
];

/// Module info end sentinel (16 bytes).
///
/// Source: `src/cmd/go/internal/modload/build.go:30`
const MOD_INFO_END: &[u8] = &[
    0xf9, 0x32, 0x43, 0x31, 0x86, 0x18, 0x20, 0x72, 0x00, 0x82, 0x42, 0x10, 0x41, 0x16, 0xd8, 0xf2,
];

/// Flags byte, bit 0: endianness (`0` = little-endian, `1` = big-endian).
const FLAG_ENDIAN: u8 = 0x01;

/// Flags byte, bit 1: string format (`0` = pointer-based pre-1.18, `1` = inline varint 1.18+).
///
/// Source: `src/debug/buildinfo/buildinfo.go:196-203`
const FLAG_VERSION_INL: u8 = 0x02;

/// Extract build info from binary data.
///
/// If the build info section location is known (from [`GoSections`](crate::formats::GoSections)), it's used
/// directly; otherwise the function falls back to scanning the entire binary for
/// the magic header.
///
/// For the inline format (Go 1.18+), the version and modinfo strings are decoded
/// from varint-length-prefixed data immediately after the 32-byte header.
/// For the pointer format (Go < 1.18), only a version string scan is attempted.
pub fn extract(ctx: &BinaryContext<'_>) -> Option<BuildInfo> {
    let data = ctx.data();
    let sections = ctx.sections();

    let search_data = if let Some(ref range) = sections.go_buildinfo {
        let end = (range.offset + range.size).min(data.len());
        &data[range.offset..end]
    } else {
        data
    };

    let magic_pos = find_aligned_magic(search_data)?;
    let header_start = if let Some(ref range) = sections.go_buildinfo {
        range.offset + magic_pos
    } else {
        magic_pos
    };

    if header_start + BUILDINFO_HEADER_SIZE > data.len() {
        return None;
    }

    let header = &data[header_start..header_start + BUILDINFO_HEADER_SIZE];
    let ptr_size = header[14] as usize;
    let flags = header[15];
    let _is_big_endian = (flags & FLAG_ENDIAN) != 0;
    let is_inline = (flags & FLAG_VERSION_INL) != 0;

    if ptr_size != 4 && ptr_size != 8 {
        return None;
    }

    let mut info = BuildInfo::default();

    if is_inline {
        // Go 1.18+: varint-length-prefixed strings after the 32-byte header
        let payload = &data[header_start + BUILDINFO_HEADER_SIZE..];
        let (version, rest) = read_varint_string(payload)?;
        info.go_version = Some(version);

        // The modinfo blob contains binary sentinel bytes (not valid UTF-8)
        let (modinfo_bytes, _) = read_varint_bytes(rest)?;
        if let Some(text) = extract_modinfo_text(modinfo_bytes) {
            parse_modinfo(text, &mut info);
        }
    } else {
        // Pre-1.18: version stored via pointers (base address unknown in static analysis)
        info.go_version = find_version_string(data);
    }

    Some(info)
}

/// Find the magic header at 16-byte alignment within `data`.
///
/// The Go linker aligns the build info to 16 bytes (macOS requirement).
/// We first scan with alignment checking, then fall back to an unaligned scan
/// in case the section offset shifted the alignment.
fn find_aligned_magic(data: &[u8]) -> Option<usize> {
    let mut pos = 0;
    while pos + BUILDINFO_HEADER_SIZE <= data.len() {
        if data[pos..].starts_with(BUILDINFO_MAGIC) && (pos % BUILDINFO_ALIGN == 0 || pos == 0) {
            return Some(pos);
        }
        pos += 1;
    }
    find_bytes(data, BUILDINFO_MAGIC)
}

/// Read a varint-length-prefixed UTF-8 string, returning the string and remaining data.
fn read_varint_string(data: &[u8]) -> Option<(String, &[u8])> {
    let (len, consumed) = read_uvarint(data)?;
    let len = len as usize;
    if consumed + len > data.len() {
        return None;
    }
    let s = String::from_utf8(data[consumed..consumed + len].to_vec()).ok()?;
    Some((s, &data[consumed + len..]))
}

/// Read a varint-length-prefixed byte slice (may contain non-UTF-8 sentinel bytes).
fn read_varint_bytes(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, consumed) = read_uvarint(data)?;
    let len = len as usize;
    if consumed + len > data.len() {
        return None;
    }
    Some((&data[consumed..consumed + len], &data[consumed + len..]))
}

/// Strip the 16-byte sentinels and return the UTF-8 text between them.
fn extract_modinfo_text(data: &[u8]) -> Option<&str> {
    let start = if data.len() >= 16 && data[..16] == *MOD_INFO_START {
        16
    } else {
        0
    };
    let end = if data.len() >= 16 && data[data.len() - 16..] == *MOD_INFO_END {
        data.len() - 16
    } else {
        data.len()
    };
    if start >= end {
        return None;
    }
    std::str::from_utf8(&data[start..end]).ok()
}

/// Decode an unsigned LEB128 / base-128 varint.
///
/// Each byte contributes 7 data bits (low 7) and 1 continuation bit (high bit).
/// If the high bit is set, more bytes follow. Maximum 10 bytes (for u64).
///
/// This is the same encoding used by Protocol Buffers and Go's `binary.Uvarint`.
fn read_uvarint(data: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return None;
        }
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

/// Parse the tab-delimited modinfo text into [`BuildInfo`] fields.
///
/// ## Line Formats
///
/// ```text
/// path\t<import_path>
/// mod\t<module>\t<version>
/// dep\t<module>\t<version>\t<hash>
/// build\t<key>=<value>
/// ```
///
/// Known build setting keys (from `src/runtime/debug/mod.go:69-95`):
/// `-buildmode`, `-compiler`, `CGO_ENABLED`, `GOARCH`, `GOOS`, `GOAMD64`,
/// `GOARM`, `GO386`, `GOFIPS140`, `vcs`, `vcs.revision`, `vcs.time`, `vcs.modified`
fn parse_modinfo(text: &str, info: &mut BuildInfo) {
    for line in text.lines() {
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        match parts.first() {
            Some(&"path") if parts.len() >= 2 => {
                info.main_path = Some(parts[1].to_string());
            }
            Some(&"mod") if parts.len() >= 2 => {
                info.main_module = Some(parts[1].to_string());
                if parts.len() >= 3 {
                    info.main_version = Some(parts[2].to_string());
                }
            }
            Some(&"dep") if parts.len() >= 2 => {
                let dep = parts[1].to_string();
                let version = parts.get(2).map(|v| v.to_string());
                info.deps.push((dep, version));
            }
            Some(&"build") if parts.len() >= 2 => {
                let setting = parts[1].to_string();
                if let Some((key, value)) = setting.split_once('=') {
                    info.build_settings
                        .push((key.to_string(), value.to_string()));
                } else {
                    info.build_settings.push((setting, String::new()));
                }
            }
            _ => {}
        }
    }
}

/// Scan binary data for a Go version string matching `"go1.XX"` or `"go1.XX.X"`.
///
/// Used as a fallback when the structured build info is unavailable (pre-1.18 binaries
/// or when the header is corrupted). Finds the first plausible match.
pub fn find_version_string(data: &[u8]) -> Option<String> {
    let pattern = b"go1.";
    let mut pos = 0;
    while pos + 8 < data.len() {
        if let Some(found) = find_bytes(&data[pos..], pattern) {
            let start = pos + found;
            let mut end = start + 4;
            while end < data.len() && end < start + 20 {
                let ch = data[end];
                if ch.is_ascii_digit() || ch == b'.' {
                    end += 1;
                } else {
                    break;
                }
            }
            if let Ok(s) = std::str::from_utf8(&data[start..end]) {
                if s.len() >= 5 && s[4..].starts_with(|c: char| c.is_ascii_digit()) {
                    return Some(s.to_string());
                }
            }
            pos = start + 4;
        } else {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_uvarint_single_byte() {
        assert_eq!(read_uvarint(&[0x08]), Some((8, 1)));
    }

    #[test]
    fn test_read_uvarint_multi_byte() {
        assert_eq!(read_uvarint(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(read_uvarint(&[0xac, 0x02]), Some((300, 2)));
    }

    #[test]
    fn test_read_varint_string() {
        let data = [0x05, b'h', b'e', b'l', b'l', b'o', 0x00];
        let (s, rest) = read_varint_string(&data).unwrap();
        assert_eq!(s, "hello");
        assert_eq!(rest.len(), 1);
    }

    #[test]
    fn test_find_version_string() {
        let mut data = vec![0u8; 100];
        data[50..58].copy_from_slice(b"go1.26.1");
        data[58] = 0;
        assert_eq!(find_version_string(&data).as_deref(), Some("go1.26.1"));
    }

    #[test]
    fn test_parse_modinfo() {
        let text = "path\texample.com/app\nmod\texample.com/app\t(devel)\ndep\texample.com/dep\tv1.0.0\nbuild\t-compiler=gc\nbuild\tGOOS=linux\n";
        let mut info = BuildInfo::default();
        parse_modinfo(text, &mut info);
        assert_eq!(info.main_path.as_deref(), Some("example.com/app"));
        assert_eq!(info.main_module.as_deref(), Some("example.com/app"));
        assert_eq!(info.deps.len(), 1);
        assert_eq!(info.deps[0].0, "example.com/dep");
        assert_eq!(info.build_settings.len(), 2);
    }
}
