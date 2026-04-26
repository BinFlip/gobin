//! Go encoded name decoder.
//!
//! Go type names are stored in a compact encoding defined in
//! `src/internal/abi/type.go:589-613`. Each name starts with a flags byte,
//! followed by a varint-encoded length, then the UTF-8 name bytes.
//!
//! ```text
//! Byte 0:    flags (bit 0=exported, 1=hasTag, 2=hasPkgPath, 3=embedded)
//! Bytes 1+:  varint-encoded name length
//! Following: name bytes (UTF-8)
//! Optional:  varint tag length + tag bytes (if bit 1 set)
//! Optional:  4-byte NameOff to package path (if bit 2 set)
//! ```

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
/// Returns the name string, or `None` if the data is malformed.
pub fn decode_name(data: &[u8]) -> Option<&str> {
    decode_name_with_flags(data).map(|(name, _)| name)
}

/// Decode a Go encoded name and return `(name, flags_byte)`.
///
/// Use the `NAME_FLAG_*` constants to interpret the flags. Bit 0 marks
/// exported, bit 1 has-tag, bit 2 has-pkg-path, bit 3 embedded (struct fields).
pub fn decode_name_with_flags(data: &[u8]) -> Option<(&str, u8)> {
    let flags = *data.first()?;

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

    let end = pos.checked_add(name_len)?;
    let bytes = data.get(pos..end)?;
    let name = std::str::from_utf8(bytes).ok()?;
    Some((name, flags))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_simple_name() {
        // flags=0x01 (exported), len=5, "Hello"
        let data = [0x01, 0x05, b'H', b'e', b'l', b'l', b'o'];
        assert_eq!(decode_name(&data), Some("Hello"));
    }

    #[test]
    fn decode_empty_name() {
        // flags=0, len=0
        let data = [0x00, 0x00];
        assert_eq!(decode_name(&data), Some(""));
    }

    #[test]
    fn decode_varint_length() {
        // flags=0, len=128 (varint: 0x80 0x01), then 128 'x' bytes
        let mut data = vec![0x00, 0x80, 0x01];
        data.extend(std::iter::repeat_n(b'x', 128));
        assert_eq!(decode_name(&data), Some(&"x".repeat(128)[..]));
    }

    #[test]
    fn decode_empty_data() {
        assert_eq!(decode_name(&[]), None);
    }

    #[test]
    fn decode_truncated() {
        // flags=0, len=10, but only 5 bytes of name
        let data = [0x00, 0x0A, b'H', b'e', b'l', b'l', b'o'];
        assert_eq!(decode_name(&data), None);
    }

    #[test]
    fn decode_invalid_utf8() {
        let data = [0x00, 0x02, 0xFF, 0xFE];
        assert_eq!(decode_name(&data), None);
    }
}
