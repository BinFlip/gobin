//! Go `moduledata` structure parser with version-aware layout.
//!
//! The `moduledata` is the linker-generated master record that ties together all
//! runtime metadata in a Go binary. Its layout has changed across Go versions,
//! requiring version-specific parsing.
//!
//! ## Version History
//!
//! | Variant | Go Versions  | Key Differences                                   |
//! |---------|-------------|---------------------------------------------------|
//! | V2      | 1.16-1.19   | No covctrs, rodata, gofunc, inittasks, epclntab   |
//! | V3      | 1.20-1.23   | +covctrs, +rodata, +gofunc                        |
//! | V4      | 1.24-1.26   | +inittasks, +epclntab, bad field moved             |
//! | V5      | future      | -typelinks, -itablinks, +typedesclen, +itaboffset  |
//!
//! Source: `src/runtime/symtab.go:402-450`

use crate::structures::{PclntabVersion, goslice::GoSlice, util::read_uintptr};

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
    /// VA of the types region start.
    pub types: u64,
    /// VA of the types region end.
    pub etypes: u64,
    /// typelinks slice (present in Go 1.16-1.26, absent in future).
    pub typelinks: Option<GoSlice>,
    /// itablinks slice (present in Go 1.16-1.26, absent in future).
    pub itablinks: Option<GoSlice>,
    /// The moduledata version that was used to parse.
    pub version: ModuledataVersion,
}

/// Which moduledata layout was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuledataVersion {
    /// Go 1.16-1.19 (pclntab V2: no covctrs, no rodata/gofunc)
    V2,
    /// Go 1.20-1.23 (pclntab V4: +covctrs, +rodata, +gofunc)
    V3,
    /// Go 1.24-1.26 (+inittasks, +epclntab, bad field moved)
    V4,
    /// Future Go (no typelinks, +typedesclen)
    V5,
}

impl Moduledata {
    /// Parse a moduledata from raw bytes with version detection.
    ///
    /// The version is determined by:
    /// 1. pclntab magic -> narrows to V2/V3/V4/V5
    /// 2. Presence of typelinks section -> V2/V3/V4 vs V5
    /// 3. Go version string -> V3 vs V4 (boundary at go1.24)
    pub fn parse(
        data: &[u8],
        ps: u8,
        pclntab_version: PclntabVersion,
        has_typelink_section: bool,
        go_version_minor: Option<u32>,
    ) -> Option<Self> {
        let p = ps as usize;
        let slice_sz = GoSlice::size(ps);
        let mut off = 0;

        let pc_header = read_uintptr(data, off, ps)?;
        off += p;

        let funcnametab = GoSlice::parse(data, off, ps)?;
        off += slice_sz;
        let cutab = GoSlice::parse(data, off, ps)?;
        off += slice_sz;
        let filetab = GoSlice::parse(data, off, ps)?;
        off += slice_sz;
        let pctab = GoSlice::parse(data, off, ps)?;
        off += slice_sz;
        let pclntable = GoSlice::parse(data, off, ps)?;
        off += slice_sz;
        let ftab = GoSlice::parse(data, off, ps)?;
        off += slice_sz;

        let findfunctab = read_uintptr(data, off, ps)?;
        off += p;
        let minpc = read_uintptr(data, off, ps)?;
        off += p;
        let maxpc = read_uintptr(data, off, ps)?;
        off += p;

        let text = read_uintptr(data, off, ps)?;
        off += p;
        let etext = read_uintptr(data, off, ps)?;
        off += p;

        // noptrdata, enoptrdata, data, edata, bss, ebss, noptrbss, enoptrbss
        off += 8 * p;

        let version = match pclntab_version {
            PclntabVersion::Go12 => return None,
            PclntabVersion::Go116 | PclntabVersion::Go118 => ModuledataVersion::V2,
            PclntabVersion::Go120 => {
                if let Some(minor) = go_version_minor {
                    match minor {
                        20..=23 => ModuledataVersion::V3,
                        24..=26 => ModuledataVersion::V4,
                        _ if minor > 26 && !has_typelink_section => ModuledataVersion::V5,
                        _ => ModuledataVersion::V4,
                    }
                } else {
                    ModuledataVersion::V4
                }
            }
        };

        match version {
            ModuledataVersion::V2 => {
                // end, gcdata, gcbss (3 uintptrs)
                off += 3 * p;
                let types = read_uintptr(data, off, ps)?;
                off += p;
                let etypes = read_uintptr(data, off, ps)?;
                off += p;
                // textsectmap (slice)
                off += slice_sz;
                let typelinks = GoSlice::parse(data, off, ps)?;
                off += slice_sz;
                let itablinks = GoSlice::parse(data, off, ps)?;

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
                    types,
                    etypes,
                    typelinks: Some(typelinks),
                    itablinks: Some(itablinks),
                    version,
                })
            }
            ModuledataVersion::V3 => {
                // covctrs, ecovctrs (2 uintptrs)
                off += 2 * p;
                // end, gcdata, gcbss (3 uintptrs)
                off += 3 * p;
                let types = read_uintptr(data, off, ps)?;
                off += p;
                let etypes = read_uintptr(data, off, ps)?;
                off += p;
                // rodata, gofunc (2 uintptrs)
                off += 2 * p;
                // textsectmap (slice)
                off += slice_sz;
                let typelinks = GoSlice::parse(data, off, ps)?;
                off += slice_sz;
                let itablinks = GoSlice::parse(data, off, ps)?;

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
                    types,
                    etypes,
                    typelinks: Some(typelinks),
                    itablinks: Some(itablinks),
                    version,
                })
            }
            ModuledataVersion::V4 => {
                // covctrs, ecovctrs (2 uintptrs)
                off += 2 * p;
                // end, gcdata, gcbss (3 uintptrs)
                off += 3 * p;
                let types = read_uintptr(data, off, ps)?;
                off += p;
                let etypes = read_uintptr(data, off, ps)?;
                off += p;
                // rodata, gofunc, epclntab (3 uintptrs)
                off += 3 * p;
                // textsectmap (slice)
                off += slice_sz;
                let typelinks = GoSlice::parse(data, off, ps)?;
                off += slice_sz;
                let itablinks = GoSlice::parse(data, off, ps)?;

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
                    types,
                    etypes,
                    typelinks: Some(typelinks),
                    itablinks: Some(itablinks),
                    version,
                })
            }
            ModuledataVersion::V5 => {
                // covctrs, ecovctrs (2 uintptrs)
                off += 2 * p;
                // end, gcdata, gcbss (3 uintptrs)
                off += 3 * p;
                let types = read_uintptr(data, off, ps)?;
                off += p;
                let _typedesclen = read_uintptr(data, off, ps)?;
                off += p;
                let etypes = read_uintptr(data, off, ps)?;

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
                    types,
                    etypes,
                    typelinks: None,
                    itablinks: None,
                    version,
                })
            }
        }
    }
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
    fn version_detection_go120_minor_22() {
        let data = vec![0u8; 500];
        let md = Moduledata::parse(&data, 8, PclntabVersion::Go120, false, Some(22));
        assert!(md.is_some());
        assert_eq!(md.unwrap().version, ModuledataVersion::V3);
    }

    #[test]
    fn version_detection_go120_minor_25() {
        let data = vec![0u8; 500];
        let md = Moduledata::parse(&data, 8, PclntabVersion::Go120, false, Some(25));
        assert!(md.is_some());
        assert_eq!(md.unwrap().version, ModuledataVersion::V4);
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
