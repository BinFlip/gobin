//! Binary format detection and Go-specific section discovery.
//!
//! Go binaries can be ELF (Linux, FreeBSD, etc.), Mach-O (macOS, iOS), or PE (Windows).
//! Each format stores Go metadata in differently-named sections:
//!
//! | Structure   | ELF Section          | Mach-O Section      | PE Section    |
//! |-------------|----------------------|---------------------|---------------|
//! | pclntab     | `.gopclntab`         | `__gopclntab`       | (in `.rdata`) |
//! | Build info  | `.go.buildinfo`      | `__go_buildinfo`    | (in `.data`)  |
//! | Module data | `.go.module`         | `__go_module`       | (in `.data`)  |
//! | Build ID    | `.note.go.buildid`   | (raw marker)        | (raw marker)  |
//! | Type links  | `.typelink`          | (in `__rodata`)     | (in `.rdata`) |
//! | Itab links  | `.itablink`          | (in `__rodata`)     | (in `.rdata`) |
//!
//! For PE binaries, Go does not create dedicated section names. Instead, the pclntab
//! lives inside `.rdata` and the build info lives inside `.data`. Detection falls back
//! to magic-byte scanning for these.
//!
//! ## API Layers
//!
//! - **Low-level**: [`BinaryContext`] parses the executable format once (via `goblin`)
//!   and provides zero-copy section slicing, VA translation, and ELF note access.
//! - **High-level**: [`crate::GoBinary`] wraps `BinaryContext` and performs the full
//!   Go metadata extraction pipeline.
//!
//! ## Source References
//!
//! - Section creation: `src/cmd/link/internal/ld/elf.go`, `macho.go`, `pe.go`
//! - Symbol kinds: `src/cmd/link/internal/sym/symkind.go`
//! - Section name mapping: `go:buildinfo` symbol -> `.go.buildinfo` section
//!   (`src/cmd/link/internal/ld/data.go:1831-1832`)

use goblin::elf::program_header::{PT_LOAD, PT_NOTE};

use crate::{
    detection::find_bytes,
    structures::wasm::{build_linear_memory_image, walk as walk_wasm_sections},
};

/// The executable format of the binary being analyzed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    /// ELF (Executable and Linkable Format) -- Linux, FreeBSD, etc.
    /// Magic: `\x7fELF` (`7f 45 4c 46`)
    Elf,
    /// Mach-O -- macOS, iOS.
    /// Magic: `\xcf\xfa\xed\xfe` (64-bit LE), `\xce\xfa\xed\xfe` (32-bit LE),
    /// or their big-endian counterparts.
    MachO,
    /// PE (Portable Executable) -- Windows.
    /// Magic: `MZ` (`4d 5a`) DOS header.
    Pe,
    /// WebAssembly module (`.wasm`) — produced by `GOOS=js GOARCH=wasm` (or
    /// `wasip1` since Go 1.21).
    /// Magic: `\0asm` + version `01 00 00 00`.
    ///
    /// Wasm has no ELF/Mach-O/PE-style virtual-address space; instead the
    /// runtime addresses static data via *linear-memory offsets*. Two
    /// translations make wasm look the same as the other formats to
    /// downstream parsers:
    ///
    /// - `image_base` is `0` — linear-memory addresses are absolute.
    /// - The Data section's many segments are reassembled into one
    ///   contiguous linear-memory image (with zero-fill gaps), and that
    ///   image becomes the address space [`BinaryContext::va_to_file`]
    ///   resolves through. Several Go runtime structures (the pcHeader,
    ///   moduledata, type descriptors, …) span multiple disjoint segments
    ///   in linear memory; the image presents them contiguously.
    ///
    /// The Go linker does not emit format-specific sections (`.gopclntab`
    /// etc.) for wasm — only three custom sections: `go:buildid`,
    /// `producers`, `name`. pclntab and buildinfo bytes live inside the
    /// Data-section linear-memory payload alongside the rest of the
    /// runtime's static data. `text_va` and `etext_va` here are runtime
    /// "PC" boundaries — not byte offsets into the Code section — since
    /// wasm encodes a Go PC as `(function_index << 16) | bytecode_offset`.
    Wasm,
    /// Unrecognized format. Magic-byte scanning can still find Go structures.
    Unknown,
}

/// Locations of Go-specific sections within the binary.
///
/// Populated during [`BinaryContext::new`] using the `goblin` crate's format-specific
/// section iterators. When a section is found, its file offset and size are recorded
/// so that downstream parsers can slice directly into the binary data.
pub struct GoSections {
    /// Whether a `.gopclntab` / `__gopclntab` section was found.
    pub has_gopclntab: bool,
    /// Whether a `.go.buildinfo` / `__go_buildinfo` section was found.
    pub has_go_buildinfo: bool,
    /// Whether a `.note.go.buildid` ELF note section was found.
    pub has_go_buildid_note: bool,

    /// File byte range of the pclntab section.
    pub gopclntab: Option<SectionRange>,
    /// File byte range of the build info section.
    pub go_buildinfo: Option<SectionRange>,
    /// File byte range of the moduledata section.
    pub go_module: Option<SectionRange>,
    /// File byte range of the typelink section (ELF only).
    pub typelink: Option<SectionRange>,
    /// File byte range of the itablink section (ELF only).
    pub itablink: Option<SectionRange>,
}

/// A contiguous byte range within the binary file, with its virtual address.
#[derive(Debug, Clone, Copy)]
pub struct SectionRange {
    /// Byte offset from the start of the file.
    pub offset: usize,
    /// Size in bytes.
    pub size: usize,
    /// Virtual address of the section in the loaded image.
    pub va: u64,
}

/// Central context for a parsed binary.
///
/// Parses the executable format **once** (via `goblin`) during construction and
/// provides zero-copy section slicing, VA-to-file-offset translation, and ELF
/// note segment access. This is the low-level entry point — all Go metadata
/// parsers (pclntab, buildinfo, types, etc.) receive a `&BinaryContext` rather
/// than re-parsing the binary independently.
///
/// Always succeeds construction (returns empty/default sections if `goblin`
/// cannot parse the binary). Higher-level confidence/detection logic lives in
/// [`crate::GoBinary`].
pub struct BinaryContext<'a> {
    /// The raw binary data this context borrows from.
    data: &'a [u8],
    /// Detected binary format (ELF / Mach-O / PE / Wasm / Unknown).
    format: BinaryFormat,
    /// Go-specific section locations.
    sections: GoSections,
    /// VA-to-file-offset mapping: `(segment_va, file_offset, size)` tuples.
    /// Built from ELF `PT_LOAD` headers, Mach-O segments, or PE sections.
    segments: Vec<(u64, u64, u64)>,
    /// ELF `PT_NOTE` segment ranges: `(file_offset, file_size)`.
    /// Empty for non-ELF binaries. Used by build ID extraction to walk
    /// note entries without re-parsing the ELF.
    elf_note_segments: Vec<(usize, usize)>,
    /// Image base virtual address.
    ///
    /// For PE binaries this is the `OptionalHeader.ImageBase` field — RVAs in
    /// the PE address space are relative to it. For ELF and Mach-O the field
    /// is `0`, since their addresses are already absolute VAs and "RVA"
    /// effectively coincides with VA. `Unknown` formats also report `0`.
    image_base: u64,
    /// Reconstructed wasm linear-memory image, when `format == Wasm`.
    ///
    /// Wasm splits the runtime's static data across many independently-placed
    /// data segments separated by zero-fill gaps in linear memory. Several
    /// Go runtime structures (the pclntab and moduledata in particular) span
    /// multiple segments. We materialize a single linear-memory image at
    /// parse time so downstream parsers can address bytes by their VA the
    /// same way they do for ELF/Mach-O/PE.
    ///
    /// Owned by [`BinaryContext`] (no leak). Borrows handed out via
    /// [`Self::structure_search_data`] are tied to `&self` and live as long
    /// as the context does — all parsers that build structures borrowing
    /// from the LM image (`ParsedPclntab`, `GoType`, etc.) borrow with the
    /// same `&self` lifetime.
    wasm_lm: Option<Box<[u8]>>,
}

impl<'a> BinaryContext<'a> {
    /// Parse a binary, extracting format info, Go sections, VA mappings, and ELF notes
    /// in a single `goblin` pass.
    ///
    /// Always succeeds — returns a context with empty sections/segments if `goblin`
    /// cannot parse the data.
    pub fn new(data: &'a [u8]) -> Self {
        let format = detect_format(data);
        let mut sections = GoSections {
            has_gopclntab: false,
            has_go_buildinfo: false,
            has_go_buildid_note: false,
            gopclntab: None,
            go_buildinfo: None,
            go_module: None,
            typelink: None,
            itablink: None,
        };
        let mut segments = Vec::new();
        let mut elf_note_segments = Vec::new();
        let mut image_base: u64 = 0;

        if let Ok(obj) = goblin::Object::parse(data) {
            match obj {
                goblin::Object::Elf(elf) => {
                    // Sections → GoSections
                    for sh in &elf.section_headers {
                        let name = match elf.shdr_strtab.get_at(sh.sh_name) {
                            Some(n) => n,
                            None => continue,
                        };
                        let range = if sh.sh_type != goblin::elf::section_header::SHT_NOBITS
                            && sh.sh_size > 0
                        {
                            Some(SectionRange {
                                offset: sh.sh_offset as usize,
                                size: sh.sh_size as usize,
                                va: sh.sh_addr,
                            })
                        } else {
                            None
                        };
                        classify_section(name, range, &mut sections);
                    }

                    // Program headers → VA segments + PT_NOTE ranges
                    for phdr in &elf.program_headers {
                        if phdr.p_type == PT_LOAD && phdr.p_filesz > 0 {
                            segments.push((phdr.p_vaddr, phdr.p_offset, phdr.p_filesz));
                        }
                        if phdr.p_type == PT_NOTE && phdr.p_filesz > 0 {
                            let offset = phdr.p_offset as usize;
                            let size = phdr.p_filesz as usize;
                            if offset.checked_add(size).is_some_and(|e| e <= data.len()) {
                                elf_note_segments.push((offset, size));
                            }
                        }
                    }
                }
                goblin::Object::Mach(goblin::mach::Mach::Binary(ref macho)) => {
                    for seg in &macho.segments {
                        // VA mapping
                        if seg.filesize > 0 {
                            segments.push((seg.vmaddr, seg.fileoff, seg.filesize));
                        }
                        // Sections → GoSections
                        for (section, _data) in seg.sections().unwrap_or_default() {
                            let sectname = section.name().unwrap_or("");
                            let range = if section.size > 0 {
                                Some(SectionRange {
                                    offset: section.offset as usize,
                                    size: section.size as usize,
                                    va: section.addr,
                                })
                            } else {
                                None
                            };
                            classify_section(sectname, range, &mut sections);
                        }
                    }
                }
                goblin::Object::PE(pe) => {
                    image_base = pe.image_base;
                    for section in &pe.sections {
                        let va = image_base.saturating_add(section.virtual_address as u64);
                        let file_off = section.pointer_to_raw_data as u64;
                        let size = section.size_of_raw_data as u64;
                        if size > 0 {
                            segments.push((va, file_off, size));
                        }
                        let name = match section.name() {
                            Ok(n) => n,
                            Err(_) => continue,
                        };
                        let range = if section.size_of_raw_data > 0 {
                            Some(SectionRange {
                                offset: section.pointer_to_raw_data as usize,
                                size: section.size_of_raw_data as usize,
                                va,
                            })
                        } else {
                            None
                        };
                        classify_section(name, range, &mut sections);
                    }
                }
                _ => {}
            }
        }

        // ELF fallback: check PT_NOTE segments for the Go note identifier
        if format == BinaryFormat::Elf && !sections.has_go_buildid_note {
            sections.has_go_buildid_note = check_elf_go_note(data);
        }

        // WASM: walk custom sections for the Go-emitted markers, register
        // each data segment as a VA segment so `va_to_file` translates
        // linear-memory addresses to file offsets, and reconstruct the
        // linear-memory image so downstream parsers can address pclntab /
        // moduledata bytes by VA.
        let mut wasm_lm: Option<Box<[u8]>> = None;
        if format == BinaryFormat::Wasm {
            for sec in walk_wasm_sections(data) {
                if sec.id == 0 && sec.name == Some("go:buildid") {
                    // Presence is a hard signal that the Go linker produced
                    // this binary. Reuse the existing flag — buildid extract
                    // falls through to the raw-marker scan and finds the
                    // payload bytes inside the section.
                    sections.has_go_buildid_note = true;
                }
            }
            // Reconstruct the linear-memory image. Cap at 256 MB so an
            // adversarial wasm with absurd offsets can't blow our memory.
            const MAX_LM_BYTES: usize = 256 * 1024 * 1024;
            if let Some(image) = build_linear_memory_image(data, MAX_LM_BYTES) {
                // Register the linear-memory image as a single VA mapping.
                // This makes `va_to_file(va) == va`, so every code path that
                // does `structure_search_data()[va_to_file(va)..]` reads
                // contiguous bytes across wasm data-segment boundaries —
                // gaps are zero-fill in the reconstructed image.
                let lm_len = image.len() as u64;
                segments.push((0u64, 0u64, lm_len));
                wasm_lm = Some(image.into_boxed_slice());
            }
        }

        Self {
            data,
            format,
            sections,
            segments,
            elf_note_segments,
            image_base,
            wasm_lm,
        }
    }

    /// The raw binary data this context was built from.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The detected executable format.
    pub fn format(&self) -> BinaryFormat {
        self.format
    }

    /// Go-specific section locations discovered during construction.
    pub fn sections(&self) -> &GoSections {
        &self.sections
    }

    /// The image base virtual address.
    ///
    /// For PE binaries this is `OptionalHeader.ImageBase`; subtract it from a
    /// VA to obtain a PE-style RVA in the disassembler's address space. For
    /// ELF and Mach-O this is `0`, since their VAs are already image-base
    /// relative.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Whether VA-to-file-offset translation is available.
    pub fn has_va_mapping(&self) -> bool {
        !self.segments.is_empty()
    }

    /// Translate a virtual address to a file byte offset.
    pub fn va_to_file(&self, va: u64) -> Option<usize> {
        for &(seg_va, seg_off, seg_size) in &self.segments {
            let seg_end = seg_va.checked_add(seg_size)?;
            if va >= seg_va && va < seg_end {
                let delta = va.checked_sub(seg_va)?;
                let file = seg_off.checked_add(delta)?;
                return usize::try_from(file).ok();
            }
        }
        None
    }

    /// Translate a file byte offset to a virtual address.
    pub fn file_to_va(&self, file_off: usize) -> Option<u64> {
        let file_off = file_off as u64;
        for &(seg_va, seg_off, seg_size) in &self.segments {
            let seg_end = seg_off.checked_add(seg_size)?;
            if file_off >= seg_off && file_off < seg_end {
                let delta = file_off.checked_sub(seg_off)?;
                return seg_va.checked_add(delta);
            }
        }
        None
    }

    /// Bytes used by the pclntab/moduledata parsers as their address space.
    ///
    /// For wasm this is the reconstructed linear-memory image (covering all
    /// data segments laid out at their target offsets, with zero-fill in
    /// between). For every other format this is the file bytes — wasm is the
    /// only one where Go runtime structures span multiple disjoint regions.
    ///
    /// Offsets returned by [`Self::va_to_file`] index into this slice for
    /// every format. The returned borrow is tied to `&self`; consumers that
    /// need to construct longer-lived structures (e.g. caching parsed state
    /// across method calls) should store scalar metadata and re-derive
    /// borrowing structs on demand.
    pub fn structure_search_data(&self) -> &[u8] {
        match self.wasm_lm.as_deref() {
            Some(lm) => lm,
            None => self.data,
        }
    }

    /// Borrow a slice starting at the byte at virtual address `va`.
    ///
    /// Format-aware: for wasm, indexes into the reconstructed linear-memory
    /// image (so the slice spans wasm data-segment boundaries seamlessly).
    /// For ELF/Mach-O/PE, equivalent to `va_to_file(va).map(|off|
    /// data.get(off..))`.
    ///
    /// Used by Go-runtime structure parsers (types, moduledata, itab, inline
    /// tree, strings) which need to read multi-byte structures starting at
    /// a given VA without worrying about whether the bytes happen to live
    /// in one file region or several.
    pub fn slice_at_va(&self, va: u64) -> Option<&[u8]> {
        let off = self.va_to_file(va)?;
        self.structure_search_data().get(off..)
    }

    /// Return the raw bytes for a given [`SectionRange`], bounds-checked.
    pub fn section_data(&self, range: &SectionRange) -> Option<&'a [u8]> {
        let end = range.offset.checked_add(range.size)?;
        self.data.get(range.offset..end)
    }

    /// Iterate over ELF `PT_NOTE` segment byte slices.
    ///
    /// Empty for non-ELF binaries. Each slice contains one or more ELF note
    /// entries that can be walked with the standard `(namesz, descsz, type)`
    /// header format.
    pub fn elf_note_segments(&self) -> impl Iterator<Item = &'a [u8]> {
        let data = self.data;
        self.elf_note_segments
            .iter()
            .filter_map(move |&(offset, size)| {
                let end = offset.checked_add(size)?;
                data.get(offset..end)
            })
    }
}

/// Detect the binary format from the first 4 bytes (magic number).
///
/// # Format Magic Bytes
///
/// | Format | Magic Bytes | Notes |
/// |--------|-------------|-------|
/// | ELF    | `7f 45 4c 46` | `\x7fELF` |
/// | Mach-O | `cf fa ed fe` | 64-bit little-endian (`MH_CIGAM_64`) |
/// | Mach-O | `ce fa ed fe` | 32-bit little-endian (`MH_CIGAM`) |
/// | Mach-O | `fe ed fa cf` | 64-bit big-endian (`MH_MAGIC_64`) |
/// | Mach-O | `fe ed fa ce` | 32-bit big-endian (`MH_MAGIC`) |
/// | PE     | `4d 5a`       | `MZ` DOS stub header |
///
/// Source: `src/cmd/internal/buildid/buildid.go:246-251`
pub fn detect_format(data: &[u8]) -> BinaryFormat {
    let head: &[u8; 4] = match data.get(..4).and_then(|s| s.try_into().ok()) {
        Some(h) => h,
        None => return BinaryFormat::Unknown,
    };
    match head {
        [0x7f, b'E', b'L', b'F'] => BinaryFormat::Elf,
        [0xcf, 0xfa, 0xed, 0xfe] | [0xce, 0xfa, 0xed, 0xfe] => BinaryFormat::MachO,
        [0xfe, 0xed, 0xfa, 0xcf] | [0xfe, 0xed, 0xfa, 0xce] => BinaryFormat::MachO,
        [b'M', b'Z', ..] => BinaryFormat::Pe,
        // Wasm magic `\0asm` + version `01 00 00 00`. The full version is in
        // the next 4 bytes; we validate it explicitly below.
        [0x00, b'a', b's', b'm']
            if data
                .get(4..8)
                .is_some_and(|v| v == [0x01, 0x00, 0x00, 0x00]) =>
        {
            BinaryFormat::Wasm
        }
        _ => BinaryFormat::Unknown,
    }
}

/// Classify a section by name and record it into the appropriate GoSections field.
fn classify_section(name: &str, range: Option<SectionRange>, result: &mut GoSections) {
    match name {
        ".gopclntab" | "__gopclntab" => {
            result.has_gopclntab = true;
            result.gopclntab = range;
        }
        ".go.buildinfo" | "__go_buildinfo" => {
            result.has_go_buildinfo = true;
            result.go_buildinfo = range;
        }
        ".note.go.buildid" => {
            result.has_go_buildid_note = true;
        }
        ".go.module" | "__go_module" => {
            result.go_module = range;
        }
        ".typelink" | "__typelink" => {
            result.typelink = range;
        }
        ".itablink" | "__itablink" => {
            result.itablink = range;
        }
        _ => {}
    }
}

/// Quick scan for the `"Go\x00\x00"` note identifier in the first 32KB.
///
/// This catches cases where the `.note.go.buildid` section header was stripped
/// but the `PT_NOTE` program header (and its payload) remain intact.
fn check_elf_go_note(data: &[u8]) -> bool {
    const GO_NOTE_NAME: &[u8] = b"Go\x00\x00";
    let search_end = data.len().min(32768);
    match data.get(..search_end) {
        Some(slice) => find_bytes(slice, GO_NOTE_NAME).is_some(),
        None => false,
    }
}
