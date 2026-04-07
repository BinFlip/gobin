//! Low-level byte reading helpers for parsing Go binary structures.
//!
//! These functions read little-endian integers at arbitrary offsets within
//! a byte slice, returning `None` for out-of-bounds access. They form
//! the foundation for all Go struct parsers in this crate.

/// Read a little-endian `uintptr` (4 or 8 bytes depending on `ps`).
pub(crate) fn read_uintptr(data: &[u8], offset: usize, ps: u8) -> Option<u64> {
    match ps {
        4 => {
            let b = data.get(offset..offset + 4)?;
            Some(u32::from_le_bytes(b.try_into().ok()?) as u64)
        }
        8 => {
            let b = data.get(offset..offset + 8)?;
            Some(u64::from_le_bytes(b.try_into().ok()?))
        }
        _ => None,
    }
}

/// Read a little-endian `u32`.
pub(crate) fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let b = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(b.try_into().ok()?))
}

/// Read a little-endian `i32`.
pub(crate) fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    let b = data.get(offset..offset + 4)?;
    Some(i32::from_le_bytes(b.try_into().ok()?))
}

/// Read a little-endian `u16`.
pub(crate) fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let b = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes(b.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_uintptr_32bit() {
        let data = 42u32.to_le_bytes();
        assert_eq!(read_uintptr(&data, 0, 4), Some(42));
    }

    #[test]
    fn read_uintptr_64bit() {
        let data = 0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes();
        assert_eq!(read_uintptr(&data, 0, 8), Some(0xDEAD_BEEF_CAFE_BABE));
    }

    #[test]
    fn read_uintptr_out_of_bounds() {
        let data = [0u8; 4];
        assert_eq!(read_uintptr(&data, 2, 4), None);
    }

    #[test]
    fn read_uintptr_invalid_ps() {
        let data = [0u8; 8];
        assert_eq!(read_uintptr(&data, 0, 3), None);
    }

    #[test]
    fn read_u32_basic() {
        let data = 0x12345678u32.to_le_bytes();
        assert_eq!(read_u32(&data, 0), Some(0x12345678));
    }

    #[test]
    fn read_u32_out_of_bounds() {
        let data = [0u8; 3];
        assert_eq!(read_u32(&data, 0), None);
    }

    #[test]
    fn read_i32_negative() {
        let data = (-100i32).to_le_bytes();
        assert_eq!(read_i32(&data, 0), Some(-100));
    }

    #[test]
    fn read_u16_basic() {
        let data = 0xABCDu16.to_le_bytes();
        assert_eq!(read_u16(&data, 0), Some(0xABCD));
    }

    #[test]
    fn read_at_offset() {
        let mut data = vec![0u8; 16];
        data[8..12].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(read_u32(&data, 8), Some(99));
    }
}
