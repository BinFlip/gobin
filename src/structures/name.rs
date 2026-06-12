//! Go encoded name decoder.
//!
//! Go type names are stored in a compact encoding defined in
//! `src/internal/abi/type.go:589-613`. Each name starts with a flags byte,
//! followed by the length, then the UTF-8 name bytes.
//!
//! ```text
//! Byte 0:    flags (bit 0=exported, 1=hasTag, 2=hasPkgPath, 3=embedded)
//! Bytes 1+:  name length
//! Following: name bytes (UTF-8)
//! Optional:  tag length + tag bytes (if bit 1 set)
//! Optional:  4-byte NameOff to package path (if bit 2 set)
//! ```
//!
//! The length encoding changed in Go 1.17: Go ≤1.16 stores it as a **2-byte
//! big-endian `uint16`** (name data at byte 3), while Go 1.17+ uses a varint.
//! The `legacy` parameter selects the pre-1.17 form.

/// Flag bit set on names that are exported (start with an uppercase letter).
pub const NAME_FLAG_EXPORTED: u8 = 1 << 0;
/// Flag bit set when the name is followed by a struct tag.
pub const NAME_FLAG_HAS_TAG: u8 = 1 << 1;
/// Flag bit set when the name is followed by a `NameOff` package path.
pub const NAME_FLAG_HAS_PKG_PATH: u8 = 1 << 2;
/// Flag bit set on struct fields that are embedded (anonymous) in their parent.
pub const NAME_FLAG_EMBEDDED: u8 = 1 << 3;

/// Decode a Go encoded name from raw bytes.
///
/// `legacy` selects the pre-1.17 (2-byte big-endian length) form; pass `false`
/// for Go 1.17+ (varint). Returns the name string, or `None` if malformed.
pub fn decode_name(data: &[u8], legacy: bool) -> Option<&str> {
    decode_name_with_flags(data, legacy).map(|(name, _)| name)
}

/// Decode a Go encoded name and return `(name, flags_byte)`.
///
/// Use the `NAME_FLAG_*` constants to interpret the flags. Bit 0 marks
/// exported, bit 1 has-tag, bit 2 has-pkg-path, bit 3 embedded (struct fields).
/// `legacy` selects the pre-1.17 length encoding (see module docs).
pub fn decode_name_with_flags(data: &[u8], legacy: bool) -> Option<(&str, u8)> {
    let flags = *data.first()?;

    let (pos, name_len) = if legacy {
        // Go ≤1.16: 2-byte big-endian length at bytes 1-2, data at byte 3.
        let hi = *data.get(1)? as usize;
        let lo = *data.get(2)? as usize;
        (3usize, (hi << 8) | lo)
    } else {
        // Go 1.17+: varint length after the flags byte.
        let mut name_len: usize = 0;
        let mut shift: u32 = 0;
        let mut pos: usize = 1;
        loop {
            let b = *data.get(pos)?;
            name_len |= ((b & 0x7f) as usize).checked_shl(shift)?;
            pos = pos.checked_add(1)?;
            if b & 0x80 == 0 {
                break;
            }
            shift = shift.checked_add(7)?;
            if shift > 35 {
                return None;
            }
        }
        (pos, name_len)
    };

    let end = pos.checked_add(name_len)?;
    let bytes = data.get(pos..end)?;
    let name = std::str::from_utf8(bytes).ok()?;
    Some((name, flags))
}

/// Decode a Go encoded name and, when present, its trailing struct tag.
///
/// Returns `(name, flags, tag)`. The tag (e.g. `json:"id" db:"id"`) follows the
/// name when the `NAME_FLAG_HAS_TAG` bit is set, encoded with the same
/// length scheme. `tag` is `None` when the name carries no tag.
pub fn decode_name_and_tag(data: &[u8], legacy: bool) -> Option<(&str, u8, Option<&str>)> {
    let flags = *data.first()?;

    let read_len = |start: usize| -> Option<(usize, usize)> {
        // Returns (data_start, len).
        if legacy {
            let hi = *data.get(start)? as usize;
            let lo = *data.get(start.checked_add(1)?)? as usize;
            Some((start.checked_add(2)?, (hi << 8) | lo))
        } else {
            let mut len: usize = 0;
            let mut shift: u32 = 0;
            let mut pos = start;
            loop {
                let b = *data.get(pos)?;
                len |= ((b & 0x7f) as usize).checked_shl(shift)?;
                pos = pos.checked_add(1)?;
                if b & 0x80 == 0 {
                    break;
                }
                shift = shift.checked_add(7)?;
                if shift > 35 {
                    return None;
                }
            }
            Some((pos, len))
        }
    };

    let (name_start, name_len) = read_len(1)?;
    let name_end = name_start.checked_add(name_len)?;
    let name = std::str::from_utf8(data.get(name_start..name_end)?).ok()?;

    let tag = if flags & NAME_FLAG_HAS_TAG != 0 {
        let (tag_start, tag_len) = read_len(name_end)?;
        let tag_end = tag_start.checked_add(tag_len)?;
        std::str::from_utf8(data.get(tag_start..tag_end)?).ok()
    } else {
        None
    };

    Some((name, flags, tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_simple_name() {
        // flags=0x01 (exported), len=5, "Hello"
        let data = [0x01, 0x05, b'H', b'e', b'l', b'l', b'o'];
        assert_eq!(decode_name(&data, false), Some("Hello"));
    }

    #[test]
    fn decode_empty_name() {
        // flags=0, len=0
        let data = [0x00, 0x00];
        assert_eq!(decode_name(&data, false), Some(""));
    }

    #[test]
    fn decode_varint_length() {
        // flags=0, len=128 (varint: 0x80 0x01), then 128 'x' bytes
        let mut data = vec![0x00, 0x80, 0x01];
        data.extend(std::iter::repeat_n(b'x', 128));
        assert_eq!(decode_name(&data, false), Some(&"x".repeat(128)[..]));
    }

    #[test]
    fn decode_legacy_big_endian_length() {
        // Go ≤1.16: flags=0x01, len=0x0005 big-endian, data at byte 3.
        let data = [0x01, 0x00, 0x05, b'H', b'e', b'l', b'l', b'o'];
        assert_eq!(decode_name(&data, true), Some("Hello"));
        // len 300 (0x012C) exercises the high byte.
        let mut big = vec![0x00, 0x01, 0x2c];
        big.extend(std::iter::repeat_n(b'z', 300));
        assert_eq!(decode_name(&big, true), Some(&"z".repeat(300)[..]));
    }

    #[test]
    fn decode_tag_varint() {
        // flags=0x06 (has-tag | has-pkg-path… only has-tag matters here),
        // name "ID" (len 2), tag `json:"id"` (len 9).
        let tag = b"json:\"id\"";
        let mut data = vec![NAME_FLAG_HAS_TAG, 0x02, b'I', b'D', 0x09];
        data.extend_from_slice(tag);
        let (name, _flags, decoded_tag) = decode_name_and_tag(&data, false).unwrap();
        assert_eq!(name, "ID");
        assert_eq!(decoded_tag, Some("json:\"id\""));
    }

    #[test]
    fn decode_no_tag_when_flag_unset() {
        let data = [0x01, 0x02, b'I', b'D'];
        let (name, _f, tag) = decode_name_and_tag(&data, false).unwrap();
        assert_eq!(name, "ID");
        assert_eq!(tag, None);
    }

    #[test]
    fn decode_tag_legacy() {
        // Go ≤1.16: 2-byte big-endian lengths.
        let mut data = vec![NAME_FLAG_HAS_TAG, 0x00, 0x02, b'I', b'D', 0x00, 0x04];
        data.extend_from_slice(b"db:x");
        let (name, _f, tag) = decode_name_and_tag(&data, true).unwrap();
        assert_eq!(name, "ID");
        assert_eq!(tag, Some("db:x"));
    }

    #[test]
    fn decode_empty_data() {
        assert_eq!(decode_name(&[], false), None);
    }

    #[test]
    fn decode_truncated() {
        // flags=0, len=10, but only 5 bytes of name
        let data = [0x00, 0x0A, b'H', b'e', b'l', b'l', b'o'];
        assert_eq!(decode_name(&data, false), None);
    }

    #[test]
    fn decode_invalid_utf8() {
        let data = [0x00, 0x02, 0xFF, 0xFE];
        assert_eq!(decode_name(&data, false), None);
    }
}
