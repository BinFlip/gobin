//! Go map type extra fields (`abi.SwissMapType`).
//!
//! The `MapType` follows the embedded `abi.Type` in the binary layout
//! for types of kind `Map`. This is the largest concrete type extra,
//! carrying ten pointer-sized fields and a `u32` flags word.
//!
//! Binary layout:
//! - 10 * pointer_size + 4 bytes of flags
//! - Plus 4 bytes of alignment padding when ps == 8
//! - Total: 10*ps + 4 + (4 if ps==8) = 44 (ps=4) or 88 (ps=8)
//!
//! Fields (all uintptr unless noted):
//! - `Key`        -- pointer to the key type descriptor
//! - `Elem`       -- pointer to the element type descriptor
//! - `Group`      -- pointer to the group type descriptor
//! - `Hasher`     -- pointer to the hash function
//! - `GroupSize`  -- size of a map group in bytes
//! - `KeysOff`    -- offset of keys within a group
//! - `KeyStride`  -- stride between consecutive keys
//! - `ElemsOff`   -- offset of elements within a group
//! - `ElemStride` -- stride between consecutive elements
//! - `ElemOff`    -- offset from key to its corresponding element
//! - `Flags`      (u32) -- map type flags
//!
//! Source: `src/internal/abi/type.go:379-420`

use crate::structures::util::{read_u32, read_uintptr};

/// Parsed extra fields for a map type descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct MapTypeExtra {
    /// Virtual address of the key type descriptor.
    pub key: u64,
    /// Virtual address of the element type descriptor.
    pub elem: u64,
    /// Virtual address of the group type descriptor.
    pub group: u64,
    /// Virtual address of the hash function.
    pub hasher: u64,
    /// Size of a map group in bytes.
    pub group_size: u64,
    /// Offset of keys within a group.
    pub keys_off: u64,
    /// Stride between consecutive keys.
    pub key_stride: u64,
    /// Offset of elements within a group.
    pub elems_off: u64,
    /// Stride between consecutive elements.
    pub elem_stride: u64,
    /// Offset from key to its corresponding element.
    pub elem_off: u64,
    /// Map type flags.
    pub flags: u32,
}

impl MapTypeExtra {
    /// Binary size for the given pointer size.
    ///
    /// Layout: 10*ps + 4 + padding.
    /// - ps=4: 10*4 + 4 = 44 bytes (no padding needed)
    /// - ps=8: 10*8 + 4 + 4 = 88 bytes (4 bytes padding for alignment)
    pub fn size(ps: u8) -> usize {
        let base = (ps as usize).saturating_mul(10).saturating_add(4);
        if ps == 8 {
            base.saturating_add(4) // alignment padding
        } else {
            base
        }
    }

    /// Parse from `data`. Data must start at the map type extra fields.
    ///
    /// Returns `None` if the buffer is too small.
    pub fn parse(data: &[u8], ps: u8) -> Option<Self> {
        let p = ps as usize;
        if data.len() < Self::size(ps) {
            return None;
        }

        let mut off: usize = 0;

        let key = read_uintptr(data, off, ps)?;
        off = off.checked_add(p)?;
        let elem = read_uintptr(data, off, ps)?;
        off = off.checked_add(p)?;
        let group = read_uintptr(data, off, ps)?;
        off = off.checked_add(p)?;
        let hasher = read_uintptr(data, off, ps)?;
        off = off.checked_add(p)?;
        let group_size = read_uintptr(data, off, ps)?;
        off = off.checked_add(p)?;
        let keys_off = read_uintptr(data, off, ps)?;
        off = off.checked_add(p)?;
        let key_stride = read_uintptr(data, off, ps)?;
        off = off.checked_add(p)?;
        let elems_off = read_uintptr(data, off, ps)?;
        off = off.checked_add(p)?;
        let elem_stride = read_uintptr(data, off, ps)?;
        off = off.checked_add(p)?;
        let elem_off = read_uintptr(data, off, ps)?;
        off = off.checked_add(p)?;
        let flags = read_u32(data, off)?;

        Some(Self {
            key,
            elem,
            group,
            hasher,
            group_size,
            keys_off,
            key_stride,
            elems_off,
            elem_stride,
            elem_off,
            flags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_64bit() {
        let mut buf = vec![0u8; 88];
        let ps: u8 = 8;
        let p = ps as usize;

        // Fill each uintptr field with a recognizable value
        for i in 0..10u64 {
            let val = (i + 1) * 0x1000;
            let off = i as usize * p;
            buf[off..off + p].copy_from_slice(&val.to_le_bytes());
        }
        // flags at offset 80
        buf[80..84].copy_from_slice(&0xABCDu32.to_le_bytes());

        let m = MapTypeExtra::parse(&buf, 8).unwrap();
        assert_eq!(m.key, 0x1000);
        assert_eq!(m.elem, 0x2000);
        assert_eq!(m.group, 0x3000);
        assert_eq!(m.hasher, 0x4000);
        assert_eq!(m.group_size, 0x5000);
        assert_eq!(m.keys_off, 0x6000);
        assert_eq!(m.key_stride, 0x7000);
        assert_eq!(m.elems_off, 0x8000);
        assert_eq!(m.elem_stride, 0x9000);
        assert_eq!(m.elem_off, 0xA000);
        assert_eq!(m.flags, 0xABCD);
    }

    #[test]
    fn size_ps4() {
        assert_eq!(MapTypeExtra::size(4), 44);
    }

    #[test]
    fn size_ps8() {
        assert_eq!(MapTypeExtra::size(8), 88);
    }

    #[test]
    fn too_short_returns_none() {
        let buf = vec![0u8; 80];
        assert!(MapTypeExtra::parse(&buf, 8).is_none());
    }

    #[test]
    fn parse_32bit() {
        let mut buf = vec![0u8; 44];
        let ps: u8 = 4;
        let p = ps as usize;

        for i in 0..10u32 {
            let val = (i + 1) * 0x100;
            let off = i as usize * p;
            buf[off..off + p].copy_from_slice(&val.to_le_bytes());
        }
        // flags at offset 40
        buf[40..44].copy_from_slice(&0x0001u32.to_le_bytes());

        let m = MapTypeExtra::parse(&buf, 4).unwrap();
        assert_eq!(m.key, 0x100);
        assert_eq!(m.elem, 0x200);
        assert_eq!(m.elem_off, 0xA00);
        assert_eq!(m.flags, 1);
    }
}
