//! Go string header (`reflect.StringHeader`) as stored in compiled binaries.
//!
//! A Go string is `(ptr, len)`, each `uintptr`-sized. Unlike slices,
//! strings have no capacity field.
//!
//! Source: `src/runtime/string.go`, `src/reflect/value.go:2573-2576`

use crate::structures::util::read_uintptr;

/// A Go string header: `(ptr, len)`, each pointer-sized.
#[derive(Debug, Clone, Copy, Default)]
pub struct GoString {
    /// Virtual address of the string data.
    pub ptr: u64,
    /// Byte length.
    pub len: u64,
}

impl GoString {
    /// Binary size: 2 * pointer_size.
    pub fn size(ps: u8) -> usize {
        2 * ps as usize
    }

    /// Parse from raw bytes.
    pub fn parse(data: &[u8], offset: usize, ps: u8) -> Option<Self> {
        let p = ps as usize;
        Some(Self {
            ptr: read_uintptr(data, offset, ps)?,
            len: read_uintptr(data, offset + p, ps)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_64bit() {
        let mut data = vec![0u8; 16];
        data[0..8].copy_from_slice(&0x4000u64.to_le_bytes());
        data[8..16].copy_from_slice(&12u64.to_le_bytes());
        let s = GoString::parse(&data, 0, 8).unwrap();
        assert_eq!(s.ptr, 0x4000);
        assert_eq!(s.len, 12);
    }

    #[test]
    fn parse_32bit() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&0x5000u32.to_le_bytes());
        data[4..8].copy_from_slice(&8u32.to_le_bytes());
        let s = GoString::parse(&data, 0, 4).unwrap();
        assert_eq!(s.ptr, 0x5000);
        assert_eq!(s.len, 8);
    }

    #[test]
    fn parse_too_short() {
        let data = vec![0u8; 12];
        assert!(GoString::parse(&data, 0, 8).is_none());
    }

    #[test]
    fn size_calculations() {
        assert_eq!(GoString::size(4), 8);
        assert_eq!(GoString::size(8), 16);
    }
}
