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

/// Decode a Go encoded name from raw bytes.
///
/// Returns the name string, or `None` if the data is malformed.
pub fn decode_name(data: &[u8]) -> Option<&str> {
    if data.is_empty() {
        return None;
    }
    let _flags = data[0];

    let mut name_len: usize = 0;
    let mut shift = 0;
    let mut pos = 1;
    loop {
        if pos >= data.len() {
            return None;
        }
        let b = data[pos];
        name_len |= ((b & 0x7f) as usize) << shift;
        pos += 1;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 35 {
            return None;
        }
    }

    if pos + name_len > data.len() {
        return None;
    }

    std::str::from_utf8(&data[pos..pos + name_len]).ok()
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
        data.extend(std::iter::repeat(b'x').take(128));
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
