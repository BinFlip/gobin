//! `itablink` decoder — recovers `(interface, concrete type)` pairs.
//!
//! When the Go linker proves that a concrete type implements an interface, it
//! emits an `itab` record carrying both type-descriptor pointers plus a hash
//! used at runtime for type-switch dispatch. The set of all generated itabs
//! is enumerated in the `itablinks` slice (or, on ELF, the `.itablink`
//! section), which is an array of `*itab` pointers.
//!
//! ## `itab` Layout (Go 1.16+)
//!
//! ```text
//! Offset  Size       Field    Description
//! 0       ptrSize    inter    *interfacetype  (VA of interface type descriptor)
//! ptrSize ptrSize    _type    *_type          (VA of concrete type descriptor)
//! 2*ptr   4          hash     u32             (copy of _type.hash, for type assertion)
//! 2*ptr+4 4          _pad     [4]byte         (reserved)
//! 2*ptr+8 var        fun[N]   uintptr[]       (method func VAs; N inferred from interfacetype)
//! ```
//!
//! Source: `src/runtime/runtime2.go:982-991`
//!
//! ## Why It Matters
//!
//! Itab pairs let an analyst answer questions like "what implements
//! `io.Reader` in this binary?" — extremely useful when chasing exfiltration
//! paths in malware analysis.

use crate::{
    formats::BinaryContext,
    structures::{goslice::GoSlice, util::read_uintptr},
};

/// One `(interface, concrete type)` pair recorded by the linker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItabPair {
    /// Virtual address of the interface type descriptor.
    pub iface_type_va: u64,
    /// Virtual address of the concrete type descriptor.
    pub concrete_type_va: u64,
    /// Type hash (copy of `_type.hash` for runtime type assertions).
    pub hash: u32,
    /// Virtual address of the itab itself.
    pub itab_va: u64,
}

/// Streaming iterator over [`ItabPair`]s in a binary.
///
/// Each [`Iterator::next`] reads one pointer from the underlying itab-array
/// (either the `.itablink` section or `moduledata.itablinks`), dereferences
/// it through VA→file translation, and parses the [`ItabPair`]. Skips entries
/// that fail to dereference / parse — adversarial input cannot panic the walk.
pub struct ItabIter<'ctx, 'a> {
    ctx: &'ctx BinaryContext<'a>,
    ps: usize,
    array: &'a [u8],
    pos: usize,
}

impl<'ctx, 'a> ItabIter<'ctx, 'a> {
    fn empty(ctx: &'ctx BinaryContext<'a>) -> Self {
        Self {
            ctx,
            ps: 0,
            array: &[],
            pos: 0,
        }
    }
}

impl Iterator for ItabIter<'_, '_> {
    type Item = ItabPair;

    fn next(&mut self) -> Option<ItabPair> {
        let ps = self.ps;
        if ps == 0 {
            return None;
        }
        let ps_u8 = u8::try_from(ps).ok()?;
        loop {
            let end = self.pos.checked_add(ps)?;
            if end > self.array.len() {
                return None;
            }
            let v = match ps {
                4 => self
                    .array
                    .get(self.pos..end)
                    .and_then(|s| s.try_into().ok())
                    .map(|b: [u8; 4]| u32::from_le_bytes(b) as u64),
                8 => self
                    .array
                    .get(self.pos..end)
                    .and_then(|s| s.try_into().ok())
                    .map(u64::from_le_bytes),
                _ => return None,
            };
            self.pos = end;
            let itab_va = match v {
                Some(v) if v != 0 => v,
                _ => continue,
            };
            if let Some(pair) = parse_itab(self.ctx, itab_va, ps, ps_u8) {
                return Some(pair);
            }
            // parse failed; skip and try next entry
        }
    }
}

/// Construct a streaming iterator over the binary's itab pairs.
///
/// Source-of-truth selection:
/// 1. `.itablink` / `__itablink` section (ELF / Mach-O).
/// 2. `moduledata.itablinks` slice (PE / older Go).
/// 3. Empty iterator otherwise.
pub fn extract_iter<'ctx, 'a>(
    ctx: &'ctx BinaryContext<'a>,
    ptr_size: u8,
    moduledata_itablinks: Option<&GoSlice>,
) -> ItabIter<'ctx, 'a> {
    let ps = ptr_size as usize;
    if ps == 0 {
        return ItabIter::empty(ctx);
    }
    let sections = ctx.sections();

    if let Some(ref range) = sections.itablink {
        if let Some(bytes) = ctx.section_data(range) {
            return ItabIter {
                ctx,
                ps,
                array: bytes,
                pos: 0,
            };
        }
    }

    if let Some(slice) = moduledata_itablinks {
        let data = ctx.data();
        if let Some(file_off) = ctx.va_to_file(slice.ptr) {
            if let Some(byte_len) = (slice.len as usize).checked_mul(ps) {
                if let Some(end) = file_off.checked_add(byte_len) {
                    if let Some(s) = data.get(file_off..end) {
                        return ItabIter {
                            ctx,
                            ps,
                            array: s,
                            pos: 0,
                        };
                    }
                }
            }
        }
    }

    ItabIter::empty(ctx)
}

/// Parse a single `itab` at `itab_va`.
fn parse_itab(ctx: &BinaryContext<'_>, itab_va: u64, ps: usize, ps_u8: u8) -> Option<ItabPair> {
    let file_off = ctx.va_to_file(itab_va)?;
    let data = ctx.data();
    let hash_off = ps.checked_mul(2)?;
    let needed = hash_off.checked_add(4)?;
    let buf = data.get(file_off..)?;
    if buf.len() < needed {
        return None;
    }
    let iface_type_va = read_uintptr(buf, 0, ps_u8)?;
    let concrete_type_va = read_uintptr(buf, ps, ps_u8)?;
    let hash_end = hash_off.checked_add(4)?;
    let hash_bytes: [u8; 4] = buf.get(hash_off..hash_end)?.try_into().ok()?;
    let hash = u32::from_le_bytes(hash_bytes);
    Some(ItabPair {
        iface_type_va,
        concrete_type_va,
        hash,
        itab_va,
    })
}
