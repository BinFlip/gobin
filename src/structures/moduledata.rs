//! Go `moduledata` structure parser with version-aware layout.
//!
//! The `moduledata` is the linker-generated master record that ties together all
//! runtime metadata in a Go binary. Its layout has changed across Go versions,
//! requiring version-specific parsing.
//!
//! ## Version History
//!
//! | Variant | Go Versions | Key Differences                                    |
//! |---------|-------------|----------------------------------------------------|
//! | V2      | 1.16-1.17   | No rodata/gofunc, covctrs, inittasks, epclntab     |
//! | V3      | 1.18-1.25   | +rodata/gofunc; +covctrs (1.20+); +inittasks (1.21+)|
//! | V4      | 1.26        | +epclntab                                          |
//! | V5      | 1.27+       | -typelinks, -itablinks, +typedesclen, +itaboffset  |
//!
//! Source: `src/runtime/symtab.go:402-450`

use crate::structures::{
    PclntabVersion,
    goslice::{GoSlice, GoStr},
    util::{advance, align_up, read_uintptr},
};

/// A `[start, end)` virtual-address range for a moduledata memory region.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VaRange {
    /// Start virtual address (inclusive).
    pub start: u64,
    /// End virtual address (exclusive).
    pub end: u64,
}

impl VaRange {
    /// Size of the range in bytes (`end - start`, saturating).
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether the range is empty (`end <= start`).
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

/// One entry of `moduledata.textsectmap` (`runtime.textsect`): a sub-range of
/// the text segment. Present (length > 1) only when the linker split code
/// across multiple text sections in a large binary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TextSect {
    /// Virtual address of the section start.
    pub vaddr: u64,
    /// Virtual address one past the section end.
    pub end: u64,
    /// Base address the section was relocated to.
    pub baseaddr: u64,
}

impl TextSect {
    /// Binary size: 3 * pointer_size.
    pub fn size(ps: u8) -> usize {
        (ps as usize).saturating_mul(3)
    }

    /// Parse from raw bytes at `offset`.
    pub fn parse(data: &[u8], offset: usize, ps: u8) -> Option<Self> {
        let p = ps as usize;
        Some(Self {
            vaddr: read_uintptr(data, offset, ps)?,
            end: read_uintptr(data, offset.checked_add(p)?, ps)?,
            baseaddr: read_uintptr(data, offset.checked_add(p.checked_mul(2)?)?, ps)?,
        })
    }
}

/// One entry of `moduledata.ptab` (`runtime.ptabEntry`) — an exported symbol of
/// a Go plugin. Both fields are offsets relative to `moduledata.types`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtabEntry<'a> {
    /// Exported symbol name, resolved from the names table.
    pub name: Option<&'a str>,
    /// `TypeOff` of the symbol's type descriptor (relative to
    /// `moduledata.types`).
    pub type_offset: i32,
}

/// One entry of `moduledata.pkghashes` / `modulehashes` (`runtime.modulehash`)
/// — a per-package ABI hash used to verify plugin / shared-object
/// compatibility at load time. Populated only for plugin / shared builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleHash<'a> {
    /// Imported module / package path.
    pub module_name: Option<&'a str>,
    /// Link-time ABI hash (the value compared against the dependency's
    /// run-time hash). This is the package-level "abi hash".
    pub linktime_hash: Option<&'a str>,
}

/// A Go `bitvector` (`runtime.bitvector`): `{ n int32; bytedata *byte }` — a
/// bit count plus a pointer to the packed bit data. In moduledata these
/// describe the GC pointer maps for the data and bss segments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bitvector {
    /// Number of bits.
    pub n: i32,
    /// Virtual address of the packed bit data (`bytedata`).
    pub bytedata: u64,
}

impl Bitvector {
    /// Binary size: `int32` + (pointer-aligned) `*byte` = `2 * ptr_size`.
    pub fn size(ps: u8) -> usize {
        (ps as usize).saturating_mul(2)
    }

    /// Parse from raw bytes at `offset` (the `*byte` sits one pointer in).
    pub fn parse(data: &[u8], offset: usize, ps: u8) -> Option<Self> {
        Some(Self {
            n: crate::structures::util::read_i32(data, offset)?,
            bytedata: read_uintptr(data, offset.checked_add(ps as usize)?, ps)?,
        })
    }
}

/// Version-specific moduledata layout.
///
/// Contains the parsed fields common to all versions plus version-specific
/// optional fields like `typelinks` and `itablinks`.
#[derive(Debug, Clone)]
pub struct Moduledata {
    /// VA of the pcHeader.
    pub pc_header: u64,
    /// funcnametab slice.
    pub funcnametab: GoSlice,
    /// cutab slice.
    pub cutab: GoSlice,
    /// filetab slice.
    pub filetab: GoSlice,
    /// pctab slice.
    pub pctab: GoSlice,
    /// pclntable slice (points to the functab section).
    pub pclntable: GoSlice,
    /// ftab slice.
    pub ftab: GoSlice,
    /// findfunctab pointer.
    pub findfunctab: u64,
    /// Minimum PC value.
    pub minpc: u64,
    /// Maximum PC value.
    pub maxpc: u64,
    /// Start of text (code) section.
    pub text: u64,
    /// End of text section.
    pub etext: u64,
    /// `[noptrdata, enoptrdata)` — non-pointer initialized data (`.noptrdata`).
    pub noptrdata: VaRange,
    /// `[data, edata)` — pointer-containing initialized data (`.data`).
    pub data: VaRange,
    /// `[bss, ebss)` — zero-initialized pointer-containing data (`.bss`).
    pub bss: VaRange,
    /// `[noptrbss, enoptrbss)` — zero-initialized non-pointer data (`.noptrbss`).
    pub noptrbss: VaRange,
    /// End VA of the whole module image.
    pub end: u64,
    /// VA of the GC data bitmap (`gcdata`).
    pub gcdata: u64,
    /// VA of the GC bss bitmap (`gcbss`).
    pub gcbss: u64,
    /// `[covctrs, ecovctrs)` coverage-counter region. `Some` and non-empty
    /// only for coverage-instrumented builds (Go 1.20+); `None` pre-1.20.
    pub covctrs: Option<VaRange>,
    /// VA of the types region start.
    pub types: u64,
    /// Length of the type-descriptor region (`typedesclen`, Go 1.27+ / V5).
    /// `None` pre-1.27.
    pub typedesclen: Option<u64>,
    /// VA of the types region end.
    pub etypes: u64,
    /// VA of the start of `.rodata` (Go 1.18+ / V3 / V4 / V5). `None` for V2.
    pub rodata: Option<u64>,
    /// VA used as the base for resolving `funcdata[]` offsets — every value
    /// returned by [`crate::structures::pclntab::ParsedPclntab::funcdata_at`]
    /// is added to this base to get the funcdata blob's VA. Go 1.18+ / V3 /
    /// V4 / V5; `None` for V2 binaries (where funcdata used a different
    /// addressing scheme).
    pub gofunc: Option<u64>,
    /// typelinks slice (present in Go 1.16-1.26, absent in future).
    pub typelinks: Option<GoSlice>,
    /// itablinks slice (present in Go 1.16-1.26, absent in future).
    pub itablinks: Option<GoSlice>,
    /// VA of the itab array (Go 1.27+ / V5 only). In V5 the `itablinks`
    /// slice was removed; itabs are stored contiguously at
    /// `[itaboffset .. itaboffset + itabsize]`. `None` for V2-V4.
    pub itaboffset: Option<u64>,
    /// Byte length of the itab array (Go 1.27+ / V5 only). `None` for V2-V4.
    pub itabsize: Option<u64>,
    /// VA of `epclntab` — one past the end of the pclntab (Go 1.26+ / V4+).
    /// `None` pre-1.26.
    pub epclntab: Option<u64>,
    /// inittasks slice: `[]*initTask`, the linker-built list of package
    /// init tasks (Go 1.21+). `None` for pre-1.21 binaries.
    pub inittasks: Option<GoSlice>,
    /// `textsectmap` slice (one `textsect` per text section). Length > 1 only
    /// for large binaries the linker split across multiple text sections.
    pub textsectmap: GoSlice,
    /// `ptab` slice (`[]ptabEntry`) — exported plugin symbols. Non-empty only
    /// for `-buildmode=plugin`.
    pub ptab: GoSlice,
    /// `pluginpath` string header. Non-empty only for `-buildmode=plugin`.
    pub pluginpath: GoStr,
    /// `pkghashes` slice (`[]modulehash`) — per-package ABI hashes used to
    /// verify plugin/shared compatibility. Non-empty only for plugin/shared.
    pub pkghashes: GoSlice,
    /// `modulename` string header. Set for plugins / shared libraries; empty
    /// for an ordinary executable.
    pub modulename: GoStr,
    /// `modulehashes` slice (`[]modulehash`) — dependency ABI hashes for
    /// plugin/shared compatibility checks.
    pub modulehashes: GoSlice,
    /// `hasmain` flag — this module contains the program's `main` (true for
    /// the main executable, false for plugins / shared libraries). Best-effort
    /// tail read; `false` if the tail was truncated.
    pub has_main: bool,
    /// `bad` flag — the runtime marks a module that failed to load and should
    /// be ignored. Best-effort tail read.
    pub bad: bool,
    /// `gcdatamask` bitvector — GC pointer map for the data segment.
    pub gcdatamask: Bitvector,
    /// `gcbssmask` bitvector — GC pointer map for the bss segment.
    pub gcbssmask: Bitvector,
    /// VA of the runtime `typemap` (`map[typeOff]*_type`) — cross-module type
    /// deduplication map, populated at load time. `0` if absent.
    pub typemap: u64,
    /// VA of the `next` moduledata in the linked list, or `0` for the last
    /// (the only entry in a normal statically-linked executable). Follow it to
    /// enumerate additional modules (plugins / shared libraries).
    pub next: u64,
    /// The moduledata version that was used to parse.
    pub version: ModuledataVersion,
}

/// Which moduledata layout was detected. Boundaries are field-accurate
/// against `runtime/symtab.go` across releases (note: `epclntab` was added in
/// Go 1.26, not 1.24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuledataVersion {
    /// Go 1.16-1.17: no `rodata`/`gofunc`, no `covctrs`, no `inittasks`.
    V2,
    /// Go 1.18-1.25: `+rodata`/`gofunc`; `+covctrs` (1.20+); `+inittasks`
    /// (1.21+); no `epclntab`.
    V3,
    /// Go 1.26: `+epclntab`.
    V4,
    /// Go 1.27+: no `typelinks`/`itablinks`; `+typedesclen`,
    /// `+itaboffset`/`itabsize`.
    V5,
}

impl Moduledata {
    /// Parse a moduledata from raw bytes with version detection.
    ///
    /// Field presence is determined per-field:
    /// 1. pclntab magic Go120 -> has `covctrs`/`rodata`/`gofunc` (Go 1.20+)
    /// 2. Go minor version -> `inittasks` (1.21+), `epclntab` (1.26+)
    /// 3. absent `.typelink` section (+ minor >= 27 when known) -> V5 layout
    pub fn parse(
        data: &[u8],
        ps: u8,
        pclntab_version: PclntabVersion,
        has_typelink_section: bool,
        go_version_minor: Option<u32>,
    ) -> Option<Self> {
        let p = ps as usize;
        let slice_sz = GoSlice::size(ps);
        // A Go `string` header is (ptr, len) = 2 pointers.
        let string_sz = p.saturating_mul(2);
        let mut off: usize = 0;

        let pc_header = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;

        let funcnametab = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;
        let cutab = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;
        let filetab = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;
        let pctab = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;
        let pclntable = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;
        let ftab = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;

        let findfunctab = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let minpc = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let maxpc = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;

        let text = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let etext = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;

        // Data-segment boundaries: four `(start, end)` VA pairs.
        let read_range = |off: &mut usize| -> Option<VaRange> {
            let start = read_uintptr(data, *off, ps)?;
            *off = advance(*off, p)?;
            let end = read_uintptr(data, *off, ps)?;
            *off = advance(*off, p)?;
            Some(VaRange { start, end })
        };
        let noptrdata = read_range(&mut off)?;
        let data_seg = read_range(&mut off)?;
        let bss = read_range(&mut off)?;
        let noptrbss = read_range(&mut off)?;

        // The middle/tail layout is determined per-field from the pclntab
        // magic and the Go minor version, verified against runtime/symtab.go
        // across releases:
        //   - rodata / gofunc           : Go 1.18+ (magic Go118 or Go120)
        //   - covctrs                   : Go 1.20+ (magic Go120)
        //   - inittasks                 : Go 1.21+
        //   - epclntab                  : Go 1.26+ (absent in 1.24 / 1.25!)
        //   - V5 (typedesclen + itaboffset/itabsize, no typelinks/itablinks):
        //                                 Go 1.27+
        if pclntab_version == PclntabVersion::Go12 {
            return None;
        }
        // `covctrs` sits *before* `types`, so its presence shifts every later
        // field; `rodata`/`gofunc` sit *after* `etypes`. They were added in
        // different releases (1.20 vs 1.18), so they must be gated separately.
        let has_covctrs = matches!(pclntab_version, PclntabVersion::Go120);
        let has_rodata_gofunc = matches!(
            pclntab_version,
            PclntabVersion::Go118 | PclntabVersion::Go120
        );
        // V5 dropped the `.typelink` section, so its absence is a reliable
        // structural signal; the version string disambiguates when present.
        let v5 = has_covctrs && !has_typelink_section && go_version_minor.is_none_or(|m| m >= 27);
        let has_inittasks = v5 || go_version_minor.is_none_or(|m| m >= 21);

        // covctrs, ecovctrs (Go 1.20+)
        let covctrs = if has_covctrs {
            Some(read_range(&mut off)?)
        } else {
            None
        };
        // end, gcdata, gcbss
        let end = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let gcdata = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let gcbss = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;

        let types = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let typedesclen = if v5 {
            let n = read_uintptr(data, off, ps)?;
            off = advance(off, p)?;
            Some(n)
        } else {
            None
        };
        let etypes = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;

        // itaboffset / itabsize (V5 only): itabs live inline at
        // [types + itaboffset .. + itabsize].
        let (itaboffset, itabsize) = if v5 {
            let io = read_uintptr(data, off, ps)?;
            off = advance(off, p)?;
            let is = read_uintptr(data, off, ps)?;
            off = advance(off, p)?;
            (Some(io), Some(is))
        } else {
            (None, None)
        };

        // rodata, gofunc (Go 1.18+)
        let (rodata, gofunc) = if has_rodata_gofunc {
            let r = read_uintptr(data, off, ps)?;
            off = advance(off, p)?;
            let g = read_uintptr(data, off, ps)?;
            off = advance(off, p)?;
            (Some(r), Some(g))
        } else {
            (None, None)
        };

        // epclntab (Go 1.26+, and always present in V5). When the minor
        // version is unknown, probe structurally: the field here is either the
        // `textsectmap` slice (no epclntab) or a lone `epclntab` pointer.
        let has_epclntab = if v5 {
            true
        } else if has_covctrs {
            match go_version_minor {
                Some(m) => m >= 26,
                None => !looks_like_slice_header(data, off, ps),
            }
        } else {
            false
        };
        let epclntab = if has_epclntab {
            let e = read_uintptr(data, off, ps)?;
            off = advance(off, p)?;
            Some(e)
        } else {
            None
        };

        // textsectmap (slice)
        let textsectmap = GoSlice::parse(data, off, ps).unwrap_or_default();
        off = advance(off, slice_sz)?;

        // typelinks, itablinks (slices) — removed in V5.
        let (typelinks, itablinks) = if v5 {
            (None, None)
        } else {
            let tl = GoSlice::parse(data, off, ps)?;
            off = advance(off, slice_sz)?;
            let il = GoSlice::parse(data, off, ps)?;
            off = advance(off, slice_sz)?;
            (Some(tl), Some(il))
        };

        // ptab (slice), pluginpath (string), pkghashes (slice)
        let ptab = GoSlice::parse(data, off, ps).unwrap_or_default();
        off = advance(off, slice_sz)?;
        let pluginpath = GoStr::parse(data, off, ps).unwrap_or_default();
        off = advance(off, string_sz)?;
        let pkghashes = GoSlice::parse(data, off, ps).unwrap_or_default();
        off = advance(off, slice_sz)?;

        // inittasks []*initTask (Go 1.21+) — best-effort tail read; a malformed
        // tail collapses to `None` rather than failing the whole parse.
        let inittasks = if has_inittasks {
            let it = GoSlice::parse(data, off, ps);
            off = off.saturating_add(slice_sz);
            it
        } else {
            None
        };

        // Tail (all best-effort — a truncated moduledata must not fail the
        // whole parse, since the parser needs nothing past this point):
        //   modulename (string), modulehashes (slice), hasmain (uint8), then a
        //   version-divergent block. In Go 1.24+ `bad` moved to right after
        //   `hasmain`; before 1.24 it sat between `typemap` and `next`:
        //     <1.24:  hasmain, gcdatamask, gcbssmask, typemap, bad, next
        //     >=1.24: hasmain, bad, gcdatamask, gcbssmask, typemap, next
        let bv_sz = Bitvector::size(ps);
        let modulename = GoStr::parse(data, off, ps).unwrap_or_default();
        off = off.saturating_add(string_sz);
        let modulehashes = GoSlice::parse(data, off, ps).unwrap_or_default();
        off = off.saturating_add(slice_sz);
        let has_main = data.get(off).is_some_and(|&b| b != 0);
        off = off.saturating_add(1);

        let bad_after_hasmain = go_version_minor.is_none_or(|m| m >= 24);
        let (bad, gcdatamask, gcbssmask, typemap, next) = if bad_after_hasmain {
            let bad = data.get(off).is_some_and(|&b| b != 0);
            // Align to the pointer boundary the bitvector struct sits on.
            let mut o = align_up(off.saturating_add(1), p).unwrap_or(off);
            let gcdatamask = Bitvector::parse(data, o, ps).unwrap_or_default();
            o = o.saturating_add(bv_sz);
            let gcbssmask = Bitvector::parse(data, o, ps).unwrap_or_default();
            o = o.saturating_add(bv_sz);
            let typemap = read_uintptr(data, o, ps).unwrap_or(0);
            o = o.saturating_add(p);
            let next = read_uintptr(data, o, ps).unwrap_or(0);
            (bad, gcdatamask, gcbssmask, typemap, next)
        } else {
            let mut o = align_up(off, p).unwrap_or(off);
            let gcdatamask = Bitvector::parse(data, o, ps).unwrap_or_default();
            o = o.saturating_add(bv_sz);
            let gcbssmask = Bitvector::parse(data, o, ps).unwrap_or_default();
            o = o.saturating_add(bv_sz);
            let typemap = read_uintptr(data, o, ps).unwrap_or(0);
            o = o.saturating_add(p);
            let bad = data.get(o).is_some_and(|&b| b != 0);
            let o2 = align_up(o.saturating_add(1), p).unwrap_or(o);
            let next = read_uintptr(data, o2, ps).unwrap_or(0);
            (bad, gcdatamask, gcbssmask, typemap, next)
        };

        let version = if v5 {
            ModuledataVersion::V5
        } else if has_epclntab {
            ModuledataVersion::V4
        } else if has_rodata_gofunc {
            ModuledataVersion::V3
        } else {
            ModuledataVersion::V2
        };

        Some(Moduledata {
            pc_header,
            funcnametab,
            cutab,
            filetab,
            pctab,
            pclntable,
            ftab,
            findfunctab,
            minpc,
            maxpc,
            text,
            etext,
            noptrdata,
            data: data_seg,
            bss,
            noptrbss,
            end,
            gcdata,
            gcbss,
            covctrs,
            types,
            typedesclen,
            etypes,
            rodata,
            gofunc,
            epclntab,
            typelinks,
            itablinks,
            itaboffset,
            itabsize,
            inittasks,
            textsectmap,
            ptab,
            pluginpath,
            pkghashes,
            modulename,
            modulehashes,
            has_main,
            bad,
            gcdatamask,
            gcbssmask,
            typemap,
            next,
            version,
        })
    }
}

/// Heuristic: do the three pointer-sized words at `off` look like a Go slice
/// header `(ptr, len, cap)` with `len == cap` and a small length?
///
/// Used to distinguish the Go 1.24/1.25 moduledata (no `epclntab`, so
/// `textsectmap` sits here) from Go 1.26+ (a lone `epclntab` pointer first)
/// when no Go version string is available. `textsectmap` has one entry per
/// text section, so its length is tiny.
fn looks_like_slice_header(data: &[u8], off: usize, ps: u8) -> bool {
    let p = ps as usize;
    let (Some(len_off), Some(cap_off)) = (off.checked_add(p), off.checked_add(p.saturating_mul(2)))
    else {
        return false;
    };
    let (Some(len), Some(cap)) = (
        read_uintptr(data, len_off, ps),
        read_uintptr(data, cap_off, ps),
    ) else {
        return false;
    };
    len == cap && (1..4096).contains(&len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_detection_go116() {
        // V2 moduledata needs enough space for the full prefix + version-specific section
        // Prefix: 1 ptr + 6 slices + 4 ptrs + 8 skipped ptrs = 1*8 + 6*24 + 4*8 + 8*8 = 248
        // V2 tail: 3 ptrs + 2 ptrs + 1 slice + 2 slices = 3*8 + 2*8 + 24 + 2*24 = 112
        let data = vec![0u8; 400];
        let md = Moduledata::parse(&data, 8, PclntabVersion::Go116, false, None);
        assert!(md.is_some());
        assert_eq!(md.unwrap().version, ModuledataVersion::V2);
    }

    #[test]
    fn version_detection_go118_is_v3_with_rodata() {
        // Go 1.18-1.19 (Go118 magic): rodata/gofunc present (V3), but no
        // covctrs. Distinct from the V2 (Go116) layout.
        let data = vec![0u8; 500];
        let md = Moduledata::parse(&data, 8, PclntabVersion::Go118, false, Some(19))
            .expect("Go118 moduledata should parse");
        assert_eq!(md.version, ModuledataVersion::V3);
        assert!(md.rodata.is_some(), "Go 1.18+ has rodata");
        assert!(md.gofunc.is_some(), "Go 1.18+ has gofunc");
    }

    #[test]
    fn version_detection_go116_is_v2_no_rodata() {
        let data = vec![0u8; 500];
        let md = Moduledata::parse(&data, 8, PclntabVersion::Go116, false, Some(16))
            .expect("Go116 moduledata should parse");
        assert_eq!(md.version, ModuledataVersion::V2);
        assert!(md.rodata.is_none(), "Go 1.16-1.17 has no rodata");
    }

    #[test]
    fn version_detection_go120_minor_22() {
        let data = vec![0u8; 500];
        let md = Moduledata::parse(&data, 8, PclntabVersion::Go120, false, Some(22));
        assert!(md.is_some());
        assert_eq!(md.unwrap().version, ModuledataVersion::V3);
    }

    #[test]
    fn version_detection_go120_minor_25_is_v3_no_epclntab() {
        // Go 1.24 / 1.25 have NO epclntab field -> V3 layout, not V4.
        let data = vec![0u8; 500];
        let md = Moduledata::parse(&data, 8, PclntabVersion::Go120, false, Some(25));
        assert!(md.is_some());
        assert_eq!(md.unwrap().version, ModuledataVersion::V3);
    }

    #[test]
    fn version_detection_go120_minor_26_is_v4() {
        // epclntab was added in Go 1.26 -> V4.
        let data = vec![0u8; 500];
        let md = Moduledata::parse(&data, 8, PclntabVersion::Go120, false, Some(26));
        assert!(md.is_some());
        assert_eq!(md.unwrap().version, ModuledataVersion::V4);
    }

    #[test]
    fn version_detection_go120_minor_27_v5() {
        // minor > 26 and no typelink section -> V5 (Go 1.27+).
        let mut data = vec![0u8; 600];
        // itaboffset lands at byte 320 in the 64-bit V5 walk (see the V5
        // branch comment for the field sequence). Plant a recognizable
        // value to prove the new fields are actually read.
        data[320..328].copy_from_slice(&0xdead_beefu64.to_le_bytes());
        data[328..336].copy_from_slice(&0x40u64.to_le_bytes());
        let md = Moduledata::parse(&data, 8, PclntabVersion::Go120, false, Some(27))
            .expect("V5 moduledata should parse");
        assert_eq!(md.version, ModuledataVersion::V5);
        assert_eq!(md.itaboffset, Some(0xdead_beef));
        assert_eq!(md.itabsize, Some(0x40));
        assert!(md.typelinks.is_none());
        assert!(md.itablinks.is_none());
        // rodata/gofunc are still present in V5 (regression guard against
        // the old speculative branch that hardcoded them to None).
        assert!(md.rodata.is_some());
        assert!(md.gofunc.is_some());
    }

    #[test]
    fn v4_falls_back_to_typelinks_not_v5() {
        // minor 27 but a typelink section is present -> stay on V4 layout.
        let data = vec![0u8; 600];
        let md = Moduledata::parse(&data, 8, PclntabVersion::Go120, true, Some(27))
            .expect("should parse");
        assert_eq!(md.version, ModuledataVersion::V4);
    }

    #[test]
    fn go12_unsupported() {
        let data = vec![0u8; 500];
        assert!(Moduledata::parse(&data, 8, PclntabVersion::Go12, false, None).is_none());
    }

    #[test]
    fn too_short_returns_none() {
        let data = vec![0u8; 10];
        assert!(Moduledata::parse(&data, 8, PclntabVersion::Go120, false, Some(25)).is_none());
    }
}
