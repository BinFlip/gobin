//! PC/line table (pclntab) parser -- the crown jewel of Go binary analysis.
//!
//! The pclntab is the single most important structure for Go reverse engineering.
//! It is **required** by the Go runtime for stack traces, garbage collection, and
//! goroutine preemption, so it **cannot be removed** without breaking the binary.
//! Even stripped or obfuscated Go binaries retain full function names, source file
//! paths, and line number mappings in this structure.
//!
//! ## Section Names
//!
//! | Format | Section Name    |
//! |--------|-----------------|
//! | ELF    | `.gopclntab`    |
//! | Mach-O | `__gopclntab`   |
//! | PE     | (inside `.rdata`, found by magic scan) |
//!
//! ## Internal Layout (Go 1.16+)
//!
//! The pclntab section is one contiguous blob with these sub-tables:
//!
//! ```text
//! runtime.pclntab (carrier symbol)
//! +-- runtime.pcheader      pcHeader struct (magic, counts, offsets)
//! +-- runtime.funcnametab   null-terminated function name strings
//! +-- runtime.cutab         compilation unit -> file index mapping
//! +-- runtime.filetab       null-terminated source file path strings
//! +-- runtime.pctab         delta-encoded PC-value tables
//! +-- runtime.functab       function table entries + _func structs
//! +-- runtime.findfunctab   fast PC -> function lookup buckets
//! ```
//!
//! Source: `src/cmd/link/internal/ld/pcln.go:930-967`
//!
//! ## pcHeader Structure (Go 1.16+)
//!
//! ```text
//! Offset      Size(bytes) Field            Description
//! 0           4           magic            Version magic (see PclntabVersion)
//! 4           1           pad1             Always 0
//! 5           1           pad2             Always 0
//! 6           1           minLC            Min instruction size (1/2/4)
//! 7           1           ptrSize          Pointer size (4/8)
//! 8           ptrSize     nfunc            Number of functions
//! 8+1*ps      ptrSize     nfiles           Number of source files
//! 8+2*ps      ptrSize     (unused)         Formerly textStart (Go 1.18+)
//! 8+3*ps      ptrSize     funcnameOffset   Offset to funcnametab
//! 8+4*ps      ptrSize     cuOffset         Offset to cutab
//! 8+5*ps      ptrSize     filetabOffset    Offset to filetab
//! 8+6*ps      ptrSize     pctabOffset      Offset to pctab
//! 8+7*ps      ptrSize     pclnOffset       Offset to functab
//! ```
//!
//! Total: 8 + 8*ptrSize bytes (40 bytes on 32-bit, 72 bytes on 64-bit).
//!
//! Source: `src/runtime/symtab.go:376-395`
//!
//! ## _func Structure (Per-Function Metadata)
//!
//! Each function has a 44-byte fixed-size record followed by variable-length arrays:
//!
//! ```text
//! Offset  Size  Type    Field         Description
//! 0       4     u32     entryOff      PC offset from moduledata.text
//! 4       4     i32     nameOff       Index into funcnametab
//! 8       4     i32     args          Argument size in bytes
//! 12      4     u32     deferreturn   Offset to deferreturn call
//! 16      4     u32     pcsp          Offset into pctab (SP delta table)
//! 20      4     u32     pcfile        Offset into pctab (file table)
//! 24      4     u32     pcln          Offset into pctab (line table)
//! 28      4     u32     npcdata       Number of PCDATA entries
//! 32      4     u32     cuOffset      Compilation unit offset in cutab
//! 36      4     i32     startLine     Line number of func keyword
//! 40      1     u8      funcID        Special function ID (see FuncID enum)
//! 41      1     u8      flag          Function flags
//! 42      1     u8      _pad          Padding
//! 43      1     u8      nfuncdata     Number of FUNCDATA entries (MUST BE LAST)
//! [44]    var   [u32]   pcdata[npcdata]     Offsets into pctab
//! [44+4*n]var   [u32]   funcdata[nfuncdata] Offsets into funcdata section
//! ```
//!
//! Source: `src/runtime/runtime2.go:1074-1099`
//!
//! ## functab Entry Format (Go 1.18+)
//!
//! Each entry is 8 bytes: `(entryoff: u32, funcoff: u32)`.
//! - `entryoff`: PC offset from `runtime.text`
//! - `funcoff`: offset within the functab section to the `_func` struct
//!
//! The functab has `nfunc + 1` entries (the last contains only an end-PC sentinel).
//!
//! Source: `src/runtime/symtab.go:579-582`

use crate::{
    formats::{BinaryContext, GoSections},
    structures::{Arch, PclntabVersion},
};

/// All recognized pclntab magic values, in order from newest to oldest.
///
/// We check newest first since modern Go binaries are the most common analysis targets.
const MAGICS: &[([u8; 4], PclntabVersion)] = &[
    ([0xf1, 0xff, 0xff, 0xff], PclntabVersion::Go120),
    ([0xf0, 0xff, 0xff, 0xff], PclntabVersion::Go118),
    ([0xfa, 0xff, 0xff, 0xff], PclntabVersion::Go116),
    ([0xfb, 0xff, 0xff, 0xff], PclntabVersion::Go12),
];

/// A parsed pclntab header with accessors into function and file name tables.
///
/// All offsets are relative to the start of the pclntab section (`self.data[0]`
/// = the `pcHeader` magic bytes). The lifetime `'a` borrows from the original
/// binary data, enabling zero-copy string access.
pub struct ParsedPclntab<'a> {
    /// The entire pclntab section data, starting at the pcHeader.
    pub data: &'a [u8],
    /// Absolute file offset where this pclntab starts in the binary.
    pub offset: usize,
    /// Detected pclntab version (determines struct layouts).
    pub version: PclntabVersion,
    /// Minimum instruction size in bytes (1=x86, 2=s390x, 4=ARM/MIPS/PPC).
    /// Used as the "PC quantum" for delta-encoded PC tables.
    pub min_lc: u8,
    /// Pointer size in bytes (4 for 32-bit, 8 for 64-bit).
    pub ptr_size: u8,
    /// Number of functions in the binary.
    pub nfunc: usize,
    /// Number of source files referenced.
    pub nfiles: usize,
    /// Offset from pcHeader to the start of `funcnametab` (null-terminated names).
    pub funcname_offset: usize,
    /// Offset from pcHeader to the start of `cutab` (compilation unit table).
    pub cu_offset: usize,
    /// Offset from pcHeader to the start of `filetab` (null-terminated file paths).
    pub filetab_offset: usize,
    /// Offset from pcHeader to the start of `pctab` (delta-encoded PC tables).
    pub pctab_offset: usize,
    /// Offset from pcHeader to the start of `functab` (function table + `_func` structs).
    pub functab_offset: usize,
}

impl<'a> ParsedPclntab<'a> {
    /// Infer the target architecture from `minLC` and `ptrSize`.
    ///
    /// See [`Arch`] for the mapping table and caveats.
    pub fn arch(&self) -> Arch {
        match (self.min_lc, self.ptr_size) {
            (1, 4) => Arch::X86,
            (1, 8) => Arch::X86_64,
            (4, 4) => Arch::Arm,
            (4, 8) => Arch::Arm64,
            (2, 8) => Arch::S390x,
            _ => Arch::Unknown,
        }
    }

    /// Look up a function name by its `nameOff` index into `funcnametab`.
    ///
    /// Names are null-terminated UTF-8 strings. Returns `None` if the offset
    /// is out of bounds or the data is not valid UTF-8.
    pub fn func_name(&self, name_off: u32) -> Option<&'a str> {
        let pos = self.funcname_offset + name_off as usize;
        if pos >= self.data.len() {
            return None;
        }
        let remaining = &self.data[pos..];
        let end = remaining.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&remaining[..end]).ok()
    }

    /// Look up a source file path by its offset into `filetab`.
    ///
    /// Paths are null-terminated UTF-8 strings, typically absolute paths
    /// as seen by the compiler.
    pub fn file_name(&self, file_off: u32) -> Option<&'a str> {
        let pos = self.filetab_offset + file_off as usize;
        if pos >= self.data.len() {
            return None;
        }
        let remaining = &self.data[pos..];
        let end = remaining.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&remaining[..end]).ok()
    }

    /// Read a pointer-sized little-endian integer at `offset` within the pclntab.
    #[allow(dead_code)]
    fn read_ptr(&self, offset: usize) -> Option<usize> {
        let ps = self.ptr_size as usize;
        if offset + ps > self.data.len() {
            return None;
        }
        let bytes = &self.data[offset..offset + ps];
        Some(match ps {
            4 => u32::from_le_bytes(bytes.try_into().ok()?) as usize,
            8 => u64::from_le_bytes(bytes.try_into().ok()?) as usize,
            _ => return None,
        })
    }

    /// Iterate over `(entryoff, funcoff)` pairs from the functab.
    ///
    /// Each pair is 8 bytes (two `u32`s). There are `nfunc` entries
    /// (plus one end-sentinel that we skip).
    pub fn func_entries(&self) -> FuncEntryIter<'a> {
        FuncEntryIter {
            data: self.data,
            base: self.functab_offset,
            index: 0,
            count: self.nfunc,
        }
    }

    /// Parse the `_func` struct at the given `funcoff` from a functab entry.
    ///
    /// In Go 1.16+, `funcoff` is relative to the functab section start (not
    /// to the pcHeader). The _func structs are stored within the functab section
    /// after the `(nfunc+1)` entry pairs. Thus the absolute offset within pclntab
    /// data is `functab_offset + funcoff`.
    ///
    /// Source: `src/runtime/runtime2.go:1074-1099`
    pub fn parse_func(&self, func_off: u32) -> Option<FuncData> {
        let off = self.functab_offset + func_off as usize;
        if off + 44 > self.data.len() {
            return None;
        }
        let d = &self.data[off..];

        Some(FuncData {
            entry_off: u32::from_le_bytes(d[0..4].try_into().ok()?),
            name_off: i32::from_le_bytes(d[4..8].try_into().ok()?),
            args: i32::from_le_bytes(d[8..12].try_into().ok()?),
            deferreturn: u32::from_le_bytes(d[12..16].try_into().ok()?),
            pcsp: u32::from_le_bytes(d[16..20].try_into().ok()?),
            pcfile: u32::from_le_bytes(d[20..24].try_into().ok()?),
            pcln: u32::from_le_bytes(d[24..28].try_into().ok()?),
            npcdata: u32::from_le_bytes(d[28..32].try_into().ok()?),
            cu_offset: u32::from_le_bytes(d[32..36].try_into().ok()?),
            start_line: i32::from_le_bytes(d[36..40].try_into().ok()?),
            func_id: d[40],
            flag: d[41],
            nfuncdata: d[43],
        })
    }

    /// Decode a PC-value table from the pctab.
    ///
    /// Go's pctab stores delta-encoded step functions mapping PC ranges to values.
    /// Each entry is a `(value_delta, pc_delta)` pair in unsigned varint encoding:
    /// - `value_delta` uses zigzag encoding (bit 0 = sign, remaining bits = magnitude)
    /// - `pc_delta` is unsigned, multiplied by `minLC` to get the real PC advance
    /// - A `pc_delta` of 0 terminates the table
    ///
    /// Returns `(pc_offset, value)` pairs where `pc_offset` is relative to
    /// the function entry and `value` is the accumulated decoded value.
    ///
    /// Source: `src/runtime/symtab.go:518-571` (`pcvalue`),
    /// `src/cmd/internal/obj/pcln.go:112-137` (encoder)
    pub fn decode_pcvalue(&self, pctab_off: u32) -> Vec<(u32, i32)> {
        let start = self.pctab_offset + pctab_off as usize;
        if start >= self.data.len() {
            return Vec::new();
        }
        let data = &self.data[start..];
        let min_lc = self.min_lc as u32;
        let mut result = Vec::new();
        let mut pc: u32 = 0;
        let mut val: i32 = -1;
        let mut pos = 0;

        while let Some((uvdelta, n1)) = read_uvarint(&data[pos..]) {
            pos += n1;

            // Zigzag decode: if bit 0 is set, negate
            let vdelta = if uvdelta & 1 != 0 {
                -((uvdelta >> 1) as i32) - 1
            } else {
                (uvdelta >> 1) as i32
            };
            val = val.wrapping_add(vdelta);

            let (uvpcdelta, n2) = match read_uvarint(&data[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += n2;

            if uvpcdelta == 0 {
                break;
            }
            pc = pc.wrapping_add((uvpcdelta as u32).wrapping_mul(min_lc));
            result.push((pc, val));
        }

        result
    }

    /// Decode the PC-to-line table for a function, returning `(pc_offset, line_number)` pairs.
    ///
    /// Line numbers are absolute (start_line + accumulated deltas).
    pub fn decode_pcln(&self, func: &FuncData) -> Vec<(u32, i32)> {
        let mut entries = self.decode_pcvalue(func.pcln);
        for entry in &mut entries {
            entry.1 += func.start_line;
        }
        entries
    }

    /// Resolve the source file for a function via its pcfile and cutab entries.
    ///
    /// The pcfile table maps PC ranges to file indices. These indices are looked up
    /// through the compilation unit table (`cutab`) to get offsets into `filetab`.
    ///
    /// Returns the file name for the first (entry-point) file index.
    pub fn resolve_source_file(&self, func: &FuncData) -> Option<&'a str> {
        let entries = self.decode_pcvalue(func.pcfile);
        let file_idx = entries.first().map(|e| e.1)?;
        self.resolve_file_via_cu(func.cu_offset, file_idx as u32)
    }

    /// Resolve a file index through the cutab to get a filetab offset, then
    /// look up the file name string.
    ///
    /// The cutab is an array of u32 entries. For compilation unit `cu`, the file
    /// at local index `file_idx` is at `cutab[cu + file_idx]`, which gives an
    /// offset into filetab.
    ///
    /// Source: `src/runtime/symtab.go:714-726` (`funcfile`)
    fn resolve_file_via_cu(&self, cu_offset: u32, file_idx: u32) -> Option<&'a str> {
        let cu_pos = self.cu_offset + (cu_offset as usize + file_idx as usize) * 4;
        if cu_pos + 4 > self.data.len() {
            return None;
        }
        let file_off = u32::from_le_bytes(self.data[cu_pos..cu_pos + 4].try_into().ok()?);
        self.file_name(file_off)
    }

    /// Get the line number range for a function: `(start_line, end_line)`.
    ///
    /// Decodes the pcln table and returns the min and max line numbers.
    pub fn line_range(&self, func: &FuncData) -> Option<(i32, i32)> {
        let entries = self.decode_pcln(func);
        if entries.is_empty() {
            return None;
        }
        let min = entries.iter().map(|e| e.1).min().unwrap();
        let max = entries.iter().map(|e| e.1).max().unwrap();
        Some((min, max))
    }

    /// Get the maximum stack frame size for a function.
    ///
    /// Decodes the pcsp table and returns the peak SP delta.
    pub fn max_frame_size(&self, func: &FuncData) -> Option<i32> {
        let entries = self.decode_pcvalue(func.pcsp);
        entries.iter().map(|e| e.1).max()
    }

    /// Iterate over all source file paths in the filetab.
    ///
    /// The filetab is a sequence of null-terminated strings. Yields each
    /// non-empty valid UTF-8 entry as a borrowed `&str`.
    pub fn file_names(&self) -> FileNameIter<'a> {
        let start = self.filetab_offset;
        let filetab_data = if start < self.data.len() {
            &self.data[start..]
        } else {
            &[]
        };
        FileNameIter {
            data: filetab_data,
            pos: 0,
            remaining: self.nfiles,
        }
    }
}

/// Streaming iterator over functab `(entryoff, funcoff)` pairs.
pub struct FuncEntryIter<'a> {
    data: &'a [u8],
    base: usize,
    index: usize,
    count: usize,
}

impl Iterator for FuncEntryIter<'_> {
    type Item = (u32, u32);

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        let off = self.base + self.index * 8;
        if off + 8 > self.data.len() {
            return None;
        }
        let entry_off = u32::from_le_bytes(self.data[off..off + 4].try_into().ok()?);
        let func_off = u32::from_le_bytes(self.data[off + 4..off + 8].try_into().ok()?);
        self.index += 1;
        Some((entry_off, func_off))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.count - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for FuncEntryIter<'_> {}

/// Streaming iterator over filetab null-terminated file name strings.
pub struct FileNameIter<'a> {
    data: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> Iterator for FileNameIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining > 0 && self.pos < self.data.len() {
            let rest = &self.data[self.pos..];
            let end = rest.iter().position(|&b| b == 0)?;
            self.remaining -= 1;
            self.pos += end + 1;
            if end > 0 {
                if let Ok(name) = std::str::from_utf8(&rest[..end]) {
                    return Some(name);
                }
            }
        }
        None
    }
}

/// Parsed `_func` structure fields (per-function metadata).
///
/// See the module-level documentation for the full struct layout.
///
/// ## Notable Fields for Reverse Engineering
///
/// - `name_off`: index into `funcnametab` to get the package-qualified function name
/// - `entry_off`: PC offset from `runtime.text`, used to map addresses back to functions
/// - `start_line`: source line where the `func` keyword appears
/// - `func_id`: nonzero for special runtime functions (see FuncID constants below)
///
/// ## FuncID Values (from `src/internal/abi/symtab.go:62-96`)
///
/// | Value | Name                    | Description                    |
/// |-------|-------------------------|--------------------------------|
/// | 0     | `FuncIDNormal`          | Regular user/library function  |
/// | 80    | `FuncID_abort`          | `runtime.abort`                |
/// | 86    | `FuncID_goexit`         | Goroutine exit                 |
/// | 91    | `FuncID_morestack`      | Stack growth                   |
/// | 92    | `FuncID_mstart`         | Machine/thread start           |
/// | 94    | `FuncID_rt0_go`         | Runtime entry point            |
/// | 96    | `FuncID_runtime_main`   | `runtime.main`                 |
/// | 100   | `FuncIDWrapper`         | Auto-generated wrapper         |
#[derive(Debug)]
pub struct FuncData {
    /// PC offset from `moduledata.text` (the start of executable code).
    pub entry_off: u32,
    /// Index into `funcnametab` for this function's name.
    pub name_off: i32,
    /// Total argument size in bytes (input + output parameters).
    pub args: i32,
    /// Offset from function entry to the `deferreturn` call (0 if none).
    pub deferreturn: u32,
    /// Offset into `pctab` for the stack-pointer delta table.
    pub pcsp: u32,
    /// Offset into `pctab` for the file-number table.
    pub pcfile: u32,
    /// Offset into `pctab` for the line-number table.
    pub pcln: u32,
    /// Number of PCDATA entries following this struct.
    pub npcdata: u32,
    /// Compilation unit offset in `cutab`.
    pub cu_offset: u32,
    /// Source line number of the `func` keyword.
    pub start_line: i32,
    /// Special function identifier (0 = normal function).
    pub func_id: u8,
    /// Function flags (`FuncFlagTopFrame`, `FuncFlagSPWrite`, `FuncFlagAsm`).
    pub flag: u8,
    /// Number of FUNCDATA entries following the PCDATA array.
    pub nfuncdata: u8,
}

/// Parse a pclntab from binary data.
///
/// Uses a layered detection strategy, from cheapest/most reliable to most expensive:
///
/// 1. **Known section + magic** — If the binary has a `.gopclntab` section, validate
///    its start against the known magic bytes. This is the fastest and most reliable path.
/// 2. **Full magic scan** — Scan the entire binary at 4-byte aligned offsets for one
///    of the four known magic values, then validate the full header.
/// 3. **Relaxed header scan** — If magic bytes were wiped (common in malware), scan
///    for the pcHeader structural pattern without requiring magic. Validates
///    `pad1==0, pad2==0, minLC∈{1,2,4}, ptrSize∈{4,8}` plus sub-table offset
///    monotonicity and funcname spot-checking. (Strategy A from RESEARCH.md §1.5)
/// 4. **moduledata pointer chain** — Scan data sections for pointer-aligned values
///    that point into the `.gopclntab` section range, then validate the target with
///    relaxed header validation. This mirrors how the Go runtime itself finds the
///    pclntab via `runtime.firstmoduledata.pcHeader`. (Strategy B from RESEARCH.md §1.5)
/// 5. **functab monotonicity** — Scan read-only sections for long arrays of
///    `(u32, u32)` pairs with strictly monotonically increasing first elements.
///    Work backwards to find the pcHeader. (Strategy C from RESEARCH.md §1.5)
pub fn parse<'a>(ctx: &BinaryContext<'a>) -> Option<ParsedPclntab<'a>> {
    let data = ctx.data();
    let sections = ctx.sections();

    // Strategy 0: known section + magic validation (cheapest)
    if let Some(ref range) = sections.gopclntab {
        let end = (range.offset + range.size).min(data.len());
        let section_data = &data[range.offset..end];
        if let Some(parsed) = try_parse_at(section_data, range.offset) {
            return Some(parsed);
        }
    }

    // Strategy 1: full-binary magic scan
    if let Some(parsed) = scan_for_magic(data) {
        return Some(parsed);
    }

    // Strategy A: relaxed header scan (no magic required)
    if let Some(parsed) = scan_relaxed(data, sections) {
        return Some(parsed);
    }

    // Strategy B: moduledata pointer chain
    if let Some(parsed) = scan_via_moduledata(ctx) {
        return Some(parsed);
    }

    // Strategy C: functab monotonicity
    scan_via_functab(data)
}

/// Attempt to parse a pclntab starting at the beginning of `data`, requiring
/// a valid magic match.
fn try_parse_at(data: &[u8], base_offset: usize) -> Option<ParsedPclntab<'_>> {
    if data.len() < 8 {
        return None;
    }

    let magic_bytes: [u8; 4] = data[..4].try_into().ok()?;
    let version = MAGICS
        .iter()
        .find(|(m, _)| *m == magic_bytes)
        .map(|(_, v)| *v)?;

    parse_header(data, base_offset, version)
}

/// Scan the binary for pclntab magic bytes at 4-byte aligned offsets.
fn scan_for_magic(data: &[u8]) -> Option<ParsedPclntab<'_>> {
    for offset in (0..data.len().saturating_sub(72)).step_by(4) {
        let magic: [u8; 4] = data[offset..offset + 4].try_into().ok()?;
        if MAGICS.iter().any(|(m, _)| *m == magic) {
            if let Some(parsed) = try_parse_at(&data[offset..], offset) {
                return Some(parsed);
            }
        }
    }
    None
}

/// Attempt to parse a pclntab at `data` without requiring a magic match.
///
/// Validates structural constraints that cannot be wiped without breaking the
/// binary: pad bytes, minLC/ptrSize ranges, sub-table offset monotonicity,
/// and a funcname spot-check for plausible ASCII strings.
///
/// Source: `src/runtime/symtab.go:623-631` — the runtime's own validation.
fn try_parse_relaxed(data: &[u8], base_offset: usize) -> Option<ParsedPclntab<'_>> {
    if data.len() < 8 {
        return None;
    }

    // Try magic first to get a definite version
    let magic_bytes: [u8; 4] = data[..4].try_into().ok()?;
    let version = MAGICS
        .iter()
        .find(|(m, _)| *m == magic_bytes)
        .map(|(_, v)| *v)
        .unwrap_or(PclntabVersion::Go120); // assume newest if magic is wiped

    // Validate pad bytes (must be zero)
    if data[4] != 0 || data[5] != 0 {
        return None;
    }

    let min_lc = data[6];
    let ptr_size = data[7];
    if !matches!(min_lc, 1 | 2 | 4) || !matches!(ptr_size, 4 | 8) {
        return None;
    }

    let parsed = parse_header(data, base_offset, version)?;

    // Additional validation: sub-table offsets must be monotonically increasing.
    // The linker emits them in order: funcnametab < cutab < filetab < pctab < functab
    // Source: src/cmd/link/internal/ld/pcln.go:981-986
    if !(parsed.funcname_offset < parsed.cu_offset
        && parsed.cu_offset < parsed.filetab_offset
        && parsed.filetab_offset < parsed.pctab_offset
        && parsed.pctab_offset < parsed.functab_offset)
    {
        return None;
    }

    // Spot-check: the first byte of funcnametab should be a null byte (the empty
    // name at index 0), followed by plausible ASCII function name characters.
    if parsed.funcname_offset < data.len() {
        let fndata = &data[parsed.funcname_offset..];
        // funcnametab[0] is always '\0' (the zero-index name is empty)
        if fndata.first() != Some(&0) {
            return None;
        }
        // Check that some bytes after the first null look like ASCII text
        if fndata.len() > 2
            && !fndata[1..fndata.len().min(32)]
                .iter()
                .any(|&b| b.is_ascii_alphanumeric())
        {
            return None;
        }
    }

    Some(parsed)
}

/// Scan the gopclntab section (or the full binary) with relaxed validation.
fn scan_relaxed<'a>(data: &'a [u8], sections: &GoSections) -> Option<ParsedPclntab<'a>> {
    // If we have the section bounds, only scan within them
    if let Some(ref range) = sections.gopclntab {
        let end = (range.offset + range.size).min(data.len());
        let section_data = &data[range.offset..end];
        return try_parse_relaxed(section_data, range.offset);
    }

    // Otherwise scan the whole binary at pointer-aligned offsets.
    // This is more expensive, so step by 8 (common ptrSize alignment).
    for offset in (0..data.len().saturating_sub(72)).step_by(8) {
        if let Some(parsed) = try_parse_relaxed(&data[offset..], offset) {
            return Some(parsed);
        }
    }
    // Retry at 4-byte alignment for 32-bit binaries
    for offset in (4..data.len().saturating_sub(40)).step_by(8) {
        if let Some(parsed) = try_parse_relaxed(&data[offset..], offset) {
            return Some(parsed);
        }
    }
    None
}

/// Scan data sections for a pointer to the pclntab section, mimicking how the
/// Go runtime locates pclntab via `runtime.firstmoduledata.pcHeader`.
///
/// The first field of `moduledata` is a pointer to the pcHeader. If we know the
/// gopclntab section's VA range, we can scan writable data sections for a
/// pointer-aligned value that falls within that range.
///
/// Source: `src/runtime/symtab.go:402` (`pcHeader *pcHeader` is field 0),
/// `src/cmd/link/internal/ld/symtab.go:593-594` (linker writes this pointer).
fn scan_via_moduledata<'a>(ctx: &BinaryContext<'a>) -> Option<ParsedPclntab<'a>> {
    let data = ctx.data();
    let pclntab_range = ctx.sections().gopclntab.as_ref()?;
    let pclntab_va = pclntab_range.va;
    if pclntab_va == 0 || !ctx.has_va_mapping() {
        return None;
    }

    // Determine pointer size from the binary format (try 8 first, then 4)
    for &ptr_size in &[8u8, 4u8] {
        let ps = ptr_size as usize;

        // Scan the entire binary at pointer-aligned offsets looking for values
        // that point into the gopclntab section VA range.
        let pclntab_va_end = pclntab_va + pclntab_range.size as u64;

        for offset in (0..data.len().saturating_sub(ps)).step_by(ps) {
            let candidate_va = match ps {
                4 => u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as u64,
                8 => u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?),
                _ => continue,
            };

            // Must point to the start of the gopclntab section (pcHeader is at the beginning)
            // Allow a small tolerance — the pointer should be within the first 64 bytes
            if candidate_va >= pclntab_va
                && candidate_va < pclntab_va + 64
                && candidate_va < pclntab_va_end
            {
                let target_file_off = ctx.va_to_file(candidate_va)?;
                if target_file_off + 72 <= data.len() {
                    if let Some(parsed) =
                        try_parse_relaxed(&data[target_file_off..], target_file_off)
                    {
                        return Some(parsed);
                    }
                }
            }
        }
    }
    None
}

/// The minimum number of consecutive monotonically-increasing functab entries
/// required to consider a candidate region as a real functab.
const FUNCTAB_MIN_RUN: usize = 100;

/// Scan for functab by finding long runs of monotonically increasing `(u32, u32)` pairs,
/// then work backwards to locate the pcHeader.
///
/// The functab is an array of `(entryoff: u32, funcoff: u32)` where `entryoff` values
/// are strictly monotonically increasing. The runtime enforces this invariant at startup.
///
/// Source: `src/runtime/symtab.go:635-653`
fn scan_via_functab<'a>(data: &'a [u8]) -> Option<ParsedPclntab<'a>> {
    // We need at least FUNCTAB_MIN_RUN * 8 bytes for the functab + 72 for the header
    if data.len() < FUNCTAB_MIN_RUN * 8 + 72 {
        return None;
    }

    // Scan at 4-byte aligned offsets for runs of monotonically increasing u32 pairs
    let mut offset = 0;
    while offset + FUNCTAB_MIN_RUN * 8 <= data.len() {
        let run_len = count_monotonic_run(&data[offset..]);
        if run_len >= FUNCTAB_MIN_RUN {
            // We found a candidate functab at `offset` with `run_len` entries.
            // Try to locate the pcHeader by scanning backwards.
            if let Some(parsed) = recover_header_from_functab(data, offset, run_len) {
                return Some(parsed);
            }
            // Skip past this run
            offset += run_len * 8;
        } else {
            // Advance by 8 bytes (one functab entry) to find the next candidate
            offset += 8;
        }
    }
    None
}

/// Count consecutive monotonically-increasing `(u32, u32)` pairs starting at `data`.
///
/// Returns the number of pairs where `pair[i].entryoff < pair[i+1].entryoff`.
fn count_monotonic_run(data: &[u8]) -> usize {
    let mut count = 0;
    let mut prev_entry: u32 = 0;
    let mut i = 0;

    while i + 8 <= data.len() {
        let entry_off = u32::from_le_bytes(match data[i..i + 4].try_into() {
            Ok(b) => b,
            Err(_) => break,
        });
        // First entry: just record it
        if count == 0 {
            prev_entry = entry_off;
            count = 1;
            i += 8;
            continue;
        }
        // Must be strictly increasing
        if entry_off <= prev_entry {
            break;
        }
        prev_entry = entry_off;
        count += 1;
        i += 8;
    }
    count
}

/// Given a functab location and its entry count, try to find the pcHeader
/// by scanning backwards through candidate offsets.
///
/// The pcHeader stores `pclnOffset` (at `8 + 7*ptrSize`) which is the offset
/// from the pcHeader to the functab. So: `pcHeader_offset = functab_offset - pclnOffset`.
fn recover_header_from_functab<'a>(
    data: &'a [u8],
    functab_file_offset: usize,
    run_len: usize,
) -> Option<ParsedPclntab<'a>> {
    // The pcHeader is always at least 4-byte aligned, so step by 4.
    // We infer the actual ptrSize from each candidate's header byte rather
    // than assuming it, since the distance to the functab may not be
    // ptrSize-aligned in edge cases.
    let max_distance = functab_file_offset.min(16 * 1024 * 1024);

    let mut dist: usize = 4;
    while dist <= max_distance {
        let candidate = functab_file_offset - dist;

        let hdr = &data[candidate..];

        // Quick structural check: pad1==0, pad2==0, minLC valid, ptrSize valid
        if hdr[4] != 0 || hdr[5] != 0 {
            dist += 4;
            continue;
        }
        if !matches!(hdr[6], 1 | 2 | 4) || !matches!(hdr[7], 4 | 8) {
            dist += 4;
            continue;
        }

        let ps = hdr[7] as usize;
        let header_size = 8 + 8 * ps;
        if candidate + header_size > data.len() {
            dist += 4;
            continue;
        }

        // Read the pclnOffset (functab offset) from the header
        let pclnoffset_pos = 8 + 7 * ps;
        if candidate + pclnoffset_pos + ps > data.len() {
            dist += 4;
            continue;
        }
        let pln_offset = read_uint(data, candidate + pclnoffset_pos, ps)?;

        // Check if this header's pclnOffset actually points to our functab
        if pln_offset == dist {
            let nfunc = read_uint(data, candidate + 8, ps)?;

            // nfunc should be close to run_len (run_len may include the +1 sentinel)
            if nfunc > 0 && (nfunc == run_len || nfunc + 1 == run_len || nfunc == run_len + 1) {
                if let Some(parsed) = try_parse_relaxed(&data[candidate..], candidate) {
                    return Some(parsed);
                }
            }
        }

        dist += 4;
    }
    None
}

/// Read a little-endian unsigned integer of `size` bytes (4 or 8) from `data` at `offset`.
fn read_uint(data: &[u8], offset: usize, size: usize) -> Option<usize> {
    if offset + size > data.len() {
        return None;
    }
    Some(match size {
        4 => u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize,
        8 => u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?) as usize,
        _ => return None,
    })
}

/// Decode an unsigned LEB128 / base-128 varint from a byte slice.
///
/// Returns `(value, bytes_consumed)`. Each byte contributes 7 data bits (low 7)
/// and 1 continuation bit (high bit). Maximum 10 bytes (for u64).
///
/// This is the same encoding used by Go's `binary.Uvarint` and the pctab encoder.
///
/// Source: `src/encoding/binary/varint.go:63-82`
fn read_uvarint(data: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return None;
        }
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

/// Parse a pcHeader at the start of `data` with a known version.
///
/// Validates field ranges (nfunc, nfiles, offsets) but does NOT check magic bytes
/// — the caller is responsible for version determination.
fn parse_header(
    data: &[u8],
    base_offset: usize,
    version: PclntabVersion,
) -> Option<ParsedPclntab<'_>> {
    // Validate padding bytes (must be zero)
    if data[4] != 0 || data[5] != 0 {
        return None;
    }

    let min_lc = data[6];
    let ptr_size = data[7];
    if !matches!(min_lc, 1 | 2 | 4) || !matches!(ptr_size, 4 | 8) {
        return None;
    }

    let ps = ptr_size as usize;
    let header_size = 8 + 8 * ps;
    if data.len() < header_size {
        return None;
    }

    let read_ptr = |offset: usize| -> Option<usize> {
        let bytes = &data[offset..offset + ps];
        Some(match ps {
            4 => u32::from_le_bytes(bytes.try_into().ok()?) as usize,
            8 => u64::from_le_bytes(bytes.try_into().ok()?) as usize,
            _ => return None,
        })
    };

    let nfunc = read_ptr(8)?;
    let nfiles = read_ptr(8 + ps)?;
    let funcname_offset = read_ptr(8 + 3 * ps)?;
    let cu_offset = read_ptr(8 + 4 * ps)?;
    let filetab_offset = read_ptr(8 + 5 * ps)?;
    let pctab_offset = read_ptr(8 + 6 * ps)?;
    let functab_offset = read_ptr(8 + 7 * ps)?;

    // Sanity: reject obviously bogus values
    if nfunc > 10_000_000 || nfiles > 10_000_000 {
        return None;
    }
    if funcname_offset > data.len() || filetab_offset > data.len() || functab_offset > data.len() {
        return None;
    }

    Some(ParsedPclntab {
        data,
        offset: base_offset,
        version,
        min_lc,
        ptr_size,
        nfunc,
        nfiles,
        funcname_offset,
        cu_offset,
        filetab_offset,
        pctab_offset,
        functab_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::{GoSections, SectionRange};

    /// Build a synthetic pcHeader (Go 1.20+, 64-bit ARM64) with valid sub-tables.
    /// Returns a data buffer with the header at offset 0 and minimal sub-table stubs.
    fn build_synthetic_pclntab(magic: [u8; 4]) -> Vec<u8> {
        let mut data = vec![0u8; 4096];

        // pcHeader: magic(4) + pad(2) + minLC(1) + ptrSize(1) + 8 ptr fields
        data[0..4].copy_from_slice(&magic);
        data[4] = 0; // pad1
        data[5] = 0; // pad2
        data[6] = 4; // minLC = ARM
        data[7] = 8; // ptrSize = 64-bit

        let nfunc: u64 = 3;
        let nfiles: u64 = 2;
        data[8..16].copy_from_slice(&nfunc.to_le_bytes());
        data[16..24].copy_from_slice(&nfiles.to_le_bytes());
        // unused field at 8+2*8=24
        data[24..32].copy_from_slice(&0u64.to_le_bytes());

        // Sub-table offsets (monotonically increasing):
        //   funcname=100, cutab=200, filetab=300, pctab=400, functab=500
        let offsets: [u64; 5] = [100, 200, 300, 400, 500];
        for (i, &off) in offsets.iter().enumerate() {
            let pos = 8 + (3 + i) * 8;
            data[pos..pos + 8].copy_from_slice(&off.to_le_bytes());
        }

        // funcnametab at offset 100: starts with null byte, then ASCII name
        data[100] = 0; // empty name at index 0
        data[101..111].copy_from_slice(b"runtime.ma");
        data[111] = 0; // null terminator

        // functab at offset 500: 3 entries + sentinel, monotonically increasing
        let functab_base = 500;
        for i in 0..4u32 {
            let entry_off = (i + 1) * 0x100;
            let func_off = i * 44;
            let pos = functab_base + (i as usize) * 8;
            data[pos..pos + 4].copy_from_slice(&entry_off.to_le_bytes());
            data[pos + 4..pos + 8].copy_from_slice(&func_off.to_le_bytes());
        }

        data
    }

    #[test]
    fn test_magic_detection() {
        let magic: [u8; 4] = [0xf1, 0xff, 0xff, 0xff];
        let version = MAGICS.iter().find(|(m, _)| *m == magic).map(|(_, v)| *v);
        assert_eq!(version, Some(PclntabVersion::Go120));
    }

    #[test]
    fn test_arch_detection() {
        let data = build_synthetic_pclntab([0xf1, 0xff, 0xff, 0xff]);
        let ctx = BinaryContext::new(&data);

        let parsed = parse(&ctx).unwrap();
        assert_eq!(parsed.version, PclntabVersion::Go120);
        assert_eq!(parsed.min_lc, 4);
        assert_eq!(parsed.ptr_size, 8);
        assert_eq!(parsed.nfunc, 3);
        assert_eq!(parsed.arch(), Arch::Arm64);
    }

    #[test]
    fn test_strategy_a_relaxed_header_zeroed_magic() {
        // Build a valid pclntab, then zero the magic — relaxed scan should still find it
        let mut data = build_synthetic_pclntab([0xf1, 0xff, 0xff, 0xff]);
        data[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // wipe magic

        let ctx = BinaryContext::new(&data);
        let parsed = parse(&ctx).unwrap();
        assert_eq!(parsed.min_lc, 4);
        assert_eq!(parsed.ptr_size, 8);
        assert_eq!(parsed.nfunc, 3);
        // Version defaults to Go120 when magic is wiped
        assert_eq!(parsed.version, PclntabVersion::Go120);
    }

    #[test]
    fn test_strategy_a_relaxed_rejects_garbage() {
        // Random data should not produce a false positive
        let data = vec![0x42u8; 4096];
        let ctx = BinaryContext::new(&data);
        assert!(parse(&ctx).is_none());
    }

    #[test]
    fn test_strategy_a_relaxed_with_section_hint() {
        // Embed a magic-zeroed pclntab at offset 1024 and tell the parser where it is.
        // Use internal scan_relaxed directly since BinaryContext::new() can't set
        // custom section ranges on synthetic data.
        let mut data = vec![0u8; 8192];
        let pclntab = build_synthetic_pclntab([0x00, 0x00, 0x00, 0x00]); // zeroed magic
        data[1024..1024 + pclntab.len()].copy_from_slice(&pclntab);

        let sections = GoSections {
            has_gopclntab: true,
            has_go_buildinfo: false,
            has_go_buildid_note: false,
            gopclntab: Some(SectionRange {
                offset: 1024,
                size: pclntab.len(),
                va: 0x400000,
            }),
            go_buildinfo: None,
            go_module: None,
            typelink: None,
            itablink: None,
        };

        let parsed = scan_relaxed(&data, &sections).unwrap();
        assert_eq!(parsed.offset, 1024);
        assert_eq!(parsed.nfunc, 3);
    }

    #[test]
    fn test_strategy_c_functab_monotonicity() {
        // Build a buffer with a valid pcHeader at offset 0 and a long functab at offset 500.
        // Zero the magic so strategies 0/1 fail. The relaxed scan (A) should find it first,
        // but let's verify the functab run detection utility works.
        let data = build_synthetic_pclntab([0xf1, 0xff, 0xff, 0xff]);
        let run = count_monotonic_run(&data[500..]);
        // We wrote 4 entries (3 funcs + 1 sentinel) with increasing entryoffs
        assert_eq!(run, 4);
    }

    #[test]
    fn test_monotonic_run_rejects_nonmonotonic() {
        let mut data = vec![0u8; 64];
        // Two entries: first entryoff=0x200, second entryoff=0x100 (decreasing)
        data[0..4].copy_from_slice(&0x200u32.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        data[8..12].copy_from_slice(&0x100u32.to_le_bytes());
        data[12..16].copy_from_slice(&44u32.to_le_bytes());

        let run = count_monotonic_run(&data);
        assert_eq!(run, 1); // only the first entry before the break
    }

    #[test]
    fn test_strategy_c_recover_header() {
        // Build a large buffer with a valid pcHeader + long functab, zero the magic,
        // and ensure recover_header_from_functab can trace back from the functab.
        let mut data = build_synthetic_pclntab([0x00, 0x00, 0x00, 0x00]); // zeroed magic

        // Extend the functab to FUNCTAB_MIN_RUN + 1 entries for the scanner threshold.
        // Update nfunc to match.
        let nfunc = FUNCTAB_MIN_RUN as u64;
        data[8..16].copy_from_slice(&nfunc.to_le_bytes());

        // Ensure data is large enough
        let functab_offset = 500;
        let needed = functab_offset + (FUNCTAB_MIN_RUN + 1) * 8 + 256;
        data.resize(needed, 0);

        // Write FUNCTAB_MIN_RUN + 1 monotonically increasing entries
        for i in 0..=(FUNCTAB_MIN_RUN as u32) {
            let entry_off = (i + 1) * 0x10;
            let func_off = i * 44;
            let pos = functab_offset + (i as usize) * 8;
            data[pos..pos + 4].copy_from_slice(&entry_off.to_le_bytes());
            data[pos + 4..pos + 8].copy_from_slice(&func_off.to_le_bytes());
        }

        let result = recover_header_from_functab(&data, functab_offset, FUNCTAB_MIN_RUN + 1);
        assert!(result.is_some(), "should recover pcHeader from functab");
        let parsed = result.unwrap();
        assert_eq!(parsed.offset, 0);
        assert_eq!(parsed.nfunc, FUNCTAB_MIN_RUN);
    }
}
