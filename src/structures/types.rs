//! Deterministic Go type descriptor extraction.
//!
//! Go embeds full type information in every binary for reflection, interface
//! dispatch, and garbage collection. This module uses structured parsing of
//! `abi.Type` descriptors via proper typed Rust structs (see [`super::abitype`]).
//!
//! ## Extraction Strategies
//!
//! 1. **Typelink path** (ELF `.typelink`, Mach-O `__typelink`): An array of `int32`
//!    offsets from `moduledata.types`. Each offset points to an `abi.Type`.
//!
//! 2. **Descriptor-walking path** (PE, or future Go without typelinks): Walk from
//!    `moduledata.types + PtrSize` to `moduledata.etypes`, advancing by each type's
//!    `DescriptorSize`. Same algorithm as the Go runtime's `moduleTypelinks()`.
//!
//! 3. **PE moduledata discovery**: PE binaries lack Go-specific section names.
//!    We find moduledata by scanning `.data` for a pointer matching the pclntab VA
//!    (the `pcHeader` field is always first in moduledata).
//!
//! ## Source References
//!
//! - Type descriptors: `src/internal/abi/type.go`
//! - Type walking: `src/runtime/type.go:522-545` (`moduleTypelinks`)
//! - Moduledata: `src/runtime/symtab.go:402-450`

use crate::{
    formats::{BinaryContext, BinaryFormat},
    structures::{
        PclntabVersion, abitype::AbiType, arraytype::ArrayTypeExtra, chantype::ChanTypeExtra,
        descriptor, elemtype::ElemTypeExtra, functype::FuncTypeExtra,
        interfacetype::InterfaceTypeExtra, maptype::MapTypeExtra, moduledata::Moduledata,
        name::decode_name, structtype::StructTypeExtra, uncommon::UncommonType,
    },
};

/// A type extracted deterministically from Go type descriptors.
#[derive(Debug, Clone)]
pub struct GoType {
    /// Full type name as stored in the binary (e.g. `"*net/http.Client"`).
    pub name: String,
    /// Type kind (Bool, Int, Struct, Pointer, Slice, etc.).
    pub kind: TypeKind,
    /// Size of the type in bytes.
    pub size: u64,
    /// Alignment of a variable of this type (bytes).
    pub align: u8,
    /// Alignment of a struct field of this type (bytes).
    pub field_align: u8,
    /// Number of bytes in the type that contain pointers (GC metadata).
    pub ptr_bytes: u64,
    /// Hash of the type, used for map key comparison and interface dispatch.
    pub hash: u32,
    /// Whether this type has an UncommonType (methods, package path).
    pub has_uncommon: bool,
    /// Whether this is a named type (has a declared name vs anonymous).
    pub is_named: bool,
    /// Whether the type is exported.
    pub is_exported: bool,
    /// Number of methods (total), from UncommonType. 0 if no uncommon type.
    pub method_count: u16,
    /// Number of exported methods, from UncommonType.
    pub exported_method_count: u16,
    /// Kind-specific type details parsed from the type descriptor's extra fields.
    pub detail: TypeDetail,
}

/// Kind-specific details parsed from Go type descriptors.
///
/// Each composite type kind (array, chan, func, interface, map, struct) carries
/// extra fields after the base `abi.Type`. These are parsed from the binary and
/// surfaced here.
#[derive(Debug, Clone)]
pub enum TypeDetail {
    /// No extra detail (scalar types, pointer, slice, string, unsafe.Pointer).
    None,
    /// Array type: fixed-size `[N]T`.
    Array {
        /// Array length.
        len: u64,
    },
    /// Channel type: `chan T`, `<-chan T`, or `chan<- T`.
    Chan {
        /// Channel direction: 1=recv only, 2=send only, 3=bidirectional.
        dir: u64,
    },
    /// Function type: `func(args...) (returns...)`.
    Func {
        /// Number of input parameters.
        in_count: u16,
        /// Number of output (return) values.
        out_count: u16,
        /// Whether the function is variadic (`...` final param).
        is_variadic: bool,
    },
    /// Interface type: `interface { ... }`.
    Interface {
        /// Number of methods in the interface.
        method_count: u64,
    },
    /// Map type: `map[K]V`.
    Map,
    /// Struct type: `struct { ... }`.
    Struct {
        /// Number of fields in the struct.
        field_count: u64,
    },
}

impl GoType {
    /// Extract the package path from the type name.
    ///
    /// Strips pointer/slice/array/map prefixes to find the base named type's package.
    pub fn package(&self) -> Option<&str> {
        let mut s = self.name.as_str();
        while let Some(rest) = s.strip_prefix('*') {
            s = rest;
        }
        if let Some(rest) = s.strip_prefix("[]") {
            s = rest;
            while let Some(rest) = s.strip_prefix('*') {
                s = rest;
            }
        }
        if s.starts_with('[') {
            if let Some(bracket_end) = s.find(']') {
                s = &s[bracket_end + 1..];
                while let Some(rest) = s.strip_prefix('*') {
                    s = rest;
                }
            }
        }
        if let Some(rest) = s.strip_prefix("map[") {
            s = rest;
        }
        s.find('.').map(|dot| &s[..dot]).filter(|pkg| {
            !pkg.is_empty()
                && pkg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '/' || c == '_' || c == '-')
        })
    }
}

/// Go type kinds, matching `abi.Kind` values.
///
/// Source: `src/internal/abi/type.go:52-80`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeKind {
    /// Invalid (0)
    Invalid,
    /// bool
    Bool,
    /// int
    Int,
    /// int8
    Int8,
    /// int16
    Int16,
    /// int32
    Int32,
    /// int64
    Int64,
    /// uint
    Uint,
    /// uint8
    Uint8,
    /// uint16
    Uint16,
    /// uint32
    Uint32,
    /// uint64
    Uint64,
    /// uintptr
    Uintptr,
    /// float32
    Float32,
    /// float64
    Float64,
    /// complex64
    Complex64,
    /// complex128
    Complex128,
    /// Array
    Array,
    /// Chan
    Chan,
    /// Func
    Func,
    /// Interface
    Interface,
    /// Map
    Map,
    /// Pointer
    Pointer,
    /// Slice
    Slice,
    /// String
    String,
    /// Struct
    Struct,
    /// unsafe.Pointer
    UnsafePointer,
}

impl TypeKind {
    /// Parse from the raw `Kind_` byte (low 5 bits).
    pub fn from_raw(raw: u8) -> Self {
        match raw & 0x1f {
            1 => Self::Bool,
            2 => Self::Int,
            3 => Self::Int8,
            4 => Self::Int16,
            5 => Self::Int32,
            6 => Self::Int64,
            7 => Self::Uint,
            8 => Self::Uint8,
            9 => Self::Uint16,
            10 => Self::Uint32,
            11 => Self::Uint64,
            12 => Self::Uintptr,
            13 => Self::Float32,
            14 => Self::Float64,
            15 => Self::Complex64,
            16 => Self::Complex128,
            17 => Self::Array,
            18 => Self::Chan,
            19 => Self::Func,
            20 => Self::Interface,
            21 => Self::Map,
            22 => Self::Pointer,
            23 => Self::Slice,
            24 => Self::String,
            25 => Self::Struct,
            26 => Self::UnsafePointer,
            _ => Self::Invalid,
        }
    }
}

impl std::fmt::Display for TypeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid",
            Self::Bool => "bool",
            Self::Int => "int",
            Self::Int8 => "int8",
            Self::Int16 => "int16",
            Self::Int32 => "int32",
            Self::Int64 => "int64",
            Self::Uint => "uint",
            Self::Uint8 => "uint8",
            Self::Uint16 => "uint16",
            Self::Uint32 => "uint32",
            Self::Uint64 => "uint64",
            Self::Uintptr => "uintptr",
            Self::Float32 => "float32",
            Self::Float64 => "float64",
            Self::Complex64 => "complex64",
            Self::Complex128 => "complex128",
            Self::Array => "array",
            Self::Chan => "chan",
            Self::Func => "func",
            Self::Interface => "interface",
            Self::Map => "map",
            Self::Pointer => "pointer",
            Self::Slice => "slice",
            Self::String => "string",
            Self::Struct => "struct",
            Self::UnsafePointer => "unsafe.Pointer",
        })
    }
}

/// Extract types deterministically from the binary.
///
/// Uses typed struct parsing via [`Moduledata`] and [`AbiType`] -- no ad-hoc
/// byte offset arithmetic.
pub fn extract_types(
    ctx: &BinaryContext<'_>,
    ptr_size: u8,
    pclntab_version: Option<PclntabVersion>,
    pclntab_offset: Option<usize>,
    go_version_minor: Option<u32>,
) -> Vec<GoType> {
    if !ctx.has_va_mapping() {
        return Vec::new();
    }

    let data = ctx.data();
    let sections = ctx.sections();
    let pv = pclntab_version.unwrap_or(PclntabVersion::Go120);
    let has_typelink = sections.typelink.is_some();

    // Find moduledata: from dedicated section, or by PE discovery
    let moduledata = if let Some(ref range) = sections.go_module {
        let md_data = &data[range.offset..range.offset + range.size];
        Moduledata::parse(md_data, ptr_size, pv, has_typelink, go_version_minor)
    } else if ctx.format() == BinaryFormat::Pe {
        discover_moduledata_pe(
            ctx,
            ptr_size,
            pv,
            has_typelink,
            go_version_minor,
            pclntab_offset,
        )
    } else {
        None
    };

    let md = match moduledata {
        Some(m) if m.types != 0 => m,
        _ => return Vec::new(),
    };

    // Strategy 1: use typelink section if available
    if let Some(ref range) = sections.typelink {
        let tl_data = &data[range.offset..range.offset + range.size];
        return extract_via_typelinks(data, tl_data, md.types, ptr_size, ctx);
    }

    // Strategy 1b: use typelinks from moduledata (Go 1.16-1.26 PE binaries)
    if let Some(ref tl_slice) = md.typelinks {
        if let Some(tl_file_off) = ctx.va_to_file(tl_slice.ptr) {
            let tl_byte_len = (tl_slice.len as usize) * 4;
            if tl_file_off + tl_byte_len <= data.len() {
                let tl_data = &data[tl_file_off..tl_file_off + tl_byte_len];
                return extract_via_typelinks(data, tl_data, md.types, ptr_size, ctx);
            }
        }
    }

    // Strategy 2: walk the type descriptor region
    if md.etypes > md.types {
        return walk_type_descriptors(data, md.types, md.etypes, ptr_size, ctx);
    }

    Vec::new()
}

/// Find moduledata in a PE binary by scanning `.data` for the pclntab VA pointer.
///
/// The first field of moduledata is `pcHeader *pcHeader`, which points to the
/// pclntab. We find the pclntab VA from its file offset, then scan the `.data`
/// section for that pointer value at pointer-aligned positions.
fn discover_moduledata_pe(
    ctx: &BinaryContext<'_>,
    ps: u8,
    pv: PclntabVersion,
    has_typelink: bool,
    go_version_minor: Option<u32>,
    pclntab_offset: Option<usize>,
) -> Option<Moduledata> {
    let data = ctx.data();
    let pclntab_file_off = pclntab_offset?;
    let pclntab_va = ctx.file_to_va(pclntab_file_off)?;

    let p = ps as usize;

    // Find .data section by looking for a PE section containing writable data
    // We scan the entire binary for the pclntab VA at pointer-aligned offsets
    // within data sections (typically the latter half of the binary)
    let search_start = data.len() / 4; // Skip text/code section
    let target_bytes = match ps {
        4 => (pclntab_va as u32).to_le_bytes().to_vec(),
        8 => pclntab_va.to_le_bytes().to_vec(),
        _ => return None,
    };

    let mut offset = search_start;
    while offset + p <= data.len() {
        // Align to pointer size
        if offset % p != 0 {
            offset += p - (offset % p);
            continue;
        }

        if &data[offset..offset + p] == target_bytes.as_slice() {
            // Candidate moduledata at `offset`. Validate by parsing.
            let remaining = &data[offset..];
            if let Some(md) = Moduledata::parse(remaining, ps, pv, has_typelink, go_version_minor) {
                // Sanity checks
                if md.minpc < md.maxpc && md.types != 0 {
                    // Verify funcnametab resolves to a valid file offset
                    if ctx.va_to_file(md.funcnametab.ptr).is_some() {
                        return Some(md);
                    }
                }
            }
        }
        offset += p;
    }
    None
}

/// Extract types via the typelink section (array of `int32` offsets from types base).
fn extract_via_typelinks(
    data: &[u8],
    tl_data: &[u8],
    types_base_va: u64,
    ps: u8,
    ctx: &BinaryContext<'_>,
) -> Vec<GoType> {
    let n_entries = tl_data.len() / 4;
    let mut types = Vec::with_capacity(n_entries);

    for i in 0..n_entries {
        let type_off = i32::from_le_bytes(tl_data[i * 4..(i + 1) * 4].try_into().unwrap());
        let type_va = (types_base_va as i64 + type_off as i64) as u64;

        if let Some(file_off) = ctx.va_to_file(type_va) {
            if let Some(go_type) = parse_type_at(data, file_off, types_base_va, ps, ctx) {
                types.push(go_type);
            }
        }
    }

    types
}

/// Walk the type descriptor region, advancing by `DescriptorSize`.
///
/// Mirrors Go runtime's `moduleTypelinks()` from `src/runtime/type.go:522-545`.
fn walk_type_descriptors(
    data: &[u8],
    types_base_va: u64,
    etypes_va: u64,
    ps: u8,
    ctx: &BinaryContext<'_>,
) -> Vec<GoType> {
    let p = ps as u64;
    let mut types = Vec::new();
    let mut td = types_base_va + p; // Skip ptrSize header

    while td < etypes_va {
        td = (td + p - 1) & !(p - 1); // Align to pointer size
        if td >= etypes_va {
            break;
        }

        let file_off = match ctx.va_to_file(td) {
            Some(off) => off,
            None => break,
        };

        // Parse AbiType to determine kind and descriptor size
        let remaining = match data.get(file_off..) {
            Some(d) if d.len() >= AbiType::size(ps) => d,
            _ => break,
        };

        let abi_type = match AbiType::parse(remaining, ps) {
            Some(t) => t,
            None => break,
        };

        let desc_size = match descriptor::descriptor_size(remaining, &abi_type, ps) {
            Some(s) if s > 0 => s,
            _ => break,
        };

        if let Some(go_type) = build_go_type(&abi_type, remaining, data, types_base_va, ps, ctx) {
            types.push(go_type);
        }

        td += desc_size as u64;
    }

    types
}

/// Parse a single `abi.Type` at the given file offset and build a `GoType`.
fn parse_type_at(
    data: &[u8],
    file_off: usize,
    types_base_va: u64,
    ps: u8,
    ctx: &BinaryContext<'_>,
) -> Option<GoType> {
    let remaining = data.get(file_off..)?;
    let abi_type = AbiType::parse(remaining, ps)?;
    build_go_type(&abi_type, remaining, data, types_base_va, ps, ctx)
}

/// Build a `GoType` from a parsed `AbiType` by resolving its name and
/// extracting kind-specific details.
fn build_go_type(
    abi_type: &AbiType,
    type_data: &[u8],
    full_data: &[u8],
    types_base_va: u64,
    ps: u8,
    ctx: &BinaryContext<'_>,
) -> Option<GoType> {
    let kind = TypeKind::from_raw(abi_type.kind());

    // Resolve name via Str (NameOff from types base)
    let name_va = (types_base_va as i64 + abi_type.str_off as i64) as u64;
    let name = ctx
        .va_to_file(name_va)
        .and_then(|off| full_data.get(off..))
        .and_then(|d| decode_name(d))
        .unwrap_or("")
        .to_string();

    if name.is_empty() && kind == TypeKind::Invalid {
        return None;
    }

    let is_exported = name.chars().next().is_some_and(|c| {
        let c = if c == '*' {
            name.chars().nth(1).unwrap_or('a')
        } else {
            c
        };
        c.is_ascii_uppercase()
    });

    let base_sz = AbiType::size(ps);

    // Parse kind-specific extra fields
    let detail = match kind {
        TypeKind::Array => type_data
            .get(base_sz..)
            .and_then(|d| ArrayTypeExtra::parse(d, ps))
            .map(|a| TypeDetail::Array { len: a.len })
            .unwrap_or(TypeDetail::None),
        TypeKind::Chan => type_data
            .get(base_sz..)
            .and_then(|d| ChanTypeExtra::parse(d, ps))
            .map(|c| TypeDetail::Chan { dir: c.dir })
            .unwrap_or(TypeDetail::None),
        TypeKind::Func => type_data
            .get(base_sz..)
            .and_then(FuncTypeExtra::parse)
            .map(|f| TypeDetail::Func {
                in_count: f.in_count,
                out_count: f.num_out(),
                is_variadic: f.is_variadic(),
            })
            .unwrap_or(TypeDetail::None),
        TypeKind::Interface => type_data
            .get(base_sz..)
            .and_then(|d| InterfaceTypeExtra::parse(d, ps))
            .map(|i| TypeDetail::Interface {
                method_count: i.methods.len,
            })
            .unwrap_or(TypeDetail::None),
        TypeKind::Map => TypeDetail::Map,
        TypeKind::Struct => type_data
            .get(base_sz..)
            .and_then(|d| StructTypeExtra::parse(d, ps))
            .map(|s| TypeDetail::Struct {
                field_count: s.fields.len,
            })
            .unwrap_or(TypeDetail::None),
        _ => TypeDetail::None,
    };

    // Parse UncommonType for method counts
    let (method_count, exported_method_count) = if abi_type.has_uncommon() {
        let concrete_sz = match kind {
            TypeKind::Array => base_sz + ArrayTypeExtra::size(ps),
            TypeKind::Chan => base_sz + ChanTypeExtra::size(ps),
            TypeKind::Func => base_sz + FuncTypeExtra::SIZE,
            TypeKind::Interface => base_sz + InterfaceTypeExtra::size(ps),
            TypeKind::Map => base_sz + MapTypeExtra::size(ps),
            TypeKind::Pointer | TypeKind::Slice => base_sz + ElemTypeExtra::size(ps),
            TypeKind::Struct => base_sz + StructTypeExtra::size(ps),
            _ => base_sz,
        };
        type_data
            .get(concrete_sz..)
            .and_then(UncommonType::parse)
            .map(|u| (u.mcount, u.xcount))
            .unwrap_or((0, 0))
    } else {
        (0, 0)
    };

    Some(GoType {
        name,
        kind,
        size: abi_type.size_,
        align: abi_type.align_,
        field_align: abi_type.field_align_,
        ptr_bytes: abi_type.ptr_bytes,
        hash: abi_type.hash,
        has_uncommon: abi_type.has_uncommon(),
        is_named: abi_type.is_named(),
        is_exported,
        method_count,
        exported_method_count,
        detail,
    })
}
