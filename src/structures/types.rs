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
        PclntabVersion,
        abitype::AbiType,
        arraytype::ArrayTypeExtra,
        chantype::ChanTypeExtra,
        descriptor,
        elemtype::ElemTypeExtra,
        functype::FuncTypeExtra,
        interfacetype::InterfaceTypeExtra,
        maptype::MapTypeExtra,
        method::GoImethod,
        method::GoMethod,
        moduledata::Moduledata,
        name::{NAME_FLAG_EMBEDDED, NAME_FLAG_EXPORTED, decode_name, decode_name_with_flags},
        structtype::{GoStructField, StructTypeExtra},
        uncommon::UncommonType,
        util::align_up_u64,
    },
};

/// A type extracted deterministically from Go type descriptors.
///
/// All string fields borrow from the underlying binary data via the lifetime
/// `'a`. To keep results past the binary's lifetime, copy individual fields
/// or `.clone()` and convert borrows to owned `String`s at the boundary.
#[derive(Debug, Clone)]
pub struct GoType<'a> {
    /// Full type name as stored in the binary (e.g. `"*net/http.Client"`).
    pub name: &'a str,
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
    pub detail: TypeDetail<'a>,
    /// Resolved method list for this type (concrete-type methods only —
    /// interface methods live on [`TypeDetail::Interface`]). Empty if
    /// [`Self::has_uncommon`] is `false`.
    pub methods: Vec<MethodEntry<'a>>,
}

/// One concrete-type method recovered from the [`UncommonType`] method array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodEntry<'a> {
    /// Method name as decoded from the names table (borrowed from binary).
    pub name: &'a str,
    /// Type-descriptor offset relative to `moduledata.types` (`mtyp` field).
    pub type_descriptor_offset: i32,
    /// Text offset relative to `runtime.text` for the direct-call entry, if
    /// non-zero. `None` for methods only reachable via interface dispatch
    /// (the linker omits the direct entry when not used).
    pub function_text_offset: Option<i32>,
    /// Whether the method's name starts with an uppercase letter.
    pub is_exported: bool,
}

/// One field of a [`TypeDetail::Struct`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructField<'a> {
    /// Field name (borrowed from binary; empty for the rare anonymous field case).
    pub name: &'a str,
    /// Virtual address of the field's type descriptor.
    pub type_va: u64,
    /// Byte offset of the field within the parent struct.
    pub offset: u64,
    /// Whether the field is embedded (anonymous Go field).
    pub is_embedded: bool,
}

/// One method declared on a [`TypeDetail::Interface`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceMethod<'a> {
    /// Method name as decoded from the names table (borrowed from binary).
    pub name: &'a str,
    /// Type-descriptor offset relative to `moduledata.types`.
    pub type_descriptor_offset: i32,
}

/// Kind-specific details parsed from Go type descriptors.
///
/// Each composite type kind carries extra fields after the base `abi.Type`.
/// These are parsed from the binary and surfaced here, with structural detail
/// (field/method names, key/value types, element types) preserved for
/// downstream type-shape similarity work.
#[derive(Debug, Clone)]
pub enum TypeDetail<'a> {
    /// No extra detail (scalar types, string, unsafe.Pointer).
    None,
    /// Array type: fixed-size `[N]T`.
    Array {
        /// Array length.
        len: u64,
        /// Virtual address of the element type descriptor.
        elem_va: u64,
    },
    /// Channel type: `chan T`, `<-chan T`, or `chan<- T`.
    Chan {
        /// Channel direction: 1=recv only, 2=send only, 3=bidirectional.
        dir: u64,
        /// Virtual address of the element type descriptor.
        elem_va: u64,
    },
    /// Function type: `func(args...) (returns...)`.
    Func {
        /// Number of input parameters.
        in_count: u16,
        /// Number of output (return) values.
        out_count: u16,
        /// Whether the function is variadic (`...` final param).
        is_variadic: bool,
        /// Virtual addresses of input parameter type descriptors, in
        /// declaration order. Length matches [`in_count`] when the descriptor
        /// is well-formed; may be shorter on truncated input.
        ///
        /// [`in_count`]: TypeDetail::Func::in_count
        inputs: Vec<u64>,
        /// Virtual addresses of output (return) type descriptors, in
        /// declaration order. Length matches [`out_count`] when the
        /// descriptor is well-formed; may be shorter on truncated input.
        ///
        /// [`out_count`]: TypeDetail::Func::out_count
        outputs: Vec<u64>,
    },
    /// Interface type: `interface { ... }`.
    Interface {
        /// Number of methods in the interface.
        method_count: u64,
        /// Resolved method names + type offsets (empty if the interface has
        /// no methods, e.g. `interface{}`).
        methods: Vec<InterfaceMethod<'a>>,
    },
    /// Map type: `map[K]V`.
    Map {
        /// Virtual address of the key type descriptor.
        key_va: u64,
        /// Virtual address of the element (value) type descriptor.
        elem_va: u64,
    },
    /// Pointer type: `*T`.
    Pointer {
        /// Virtual address of the pointee type descriptor.
        elem_va: u64,
    },
    /// Slice type: `[]T`.
    Slice {
        /// Virtual address of the element type descriptor.
        elem_va: u64,
    },
    /// Struct type: `struct { ... }`.
    Struct {
        /// Number of fields in the struct.
        field_count: u64,
        /// Resolved field names + type VAs + offsets + embedded flag.
        fields: Vec<StructField<'a>>,
    },
}

impl<'a> GoType<'a> {
    /// Extract the package path from the type name.
    ///
    /// Strips pointer/slice/array/map prefixes to find the base named type's package.
    pub fn package(&self) -> Option<&'a str> {
        let mut s = self.name;
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
                if let Some(after) = bracket_end.checked_add(1).and_then(|i| s.get(i..)) {
                    s = after;
                    while let Some(rest) = s.strip_prefix('*') {
                        s = rest;
                    }
                }
            }
        }
        if let Some(rest) = s.strip_prefix("map[") {
            s = rest;
        }
        s.find('.').and_then(|dot| s.get(..dot)).filter(|pkg| {
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

/// Streaming iterator over [`GoType`]s extracted from a binary.
///
/// Backed by [`extract_types_iter`]. Each [`Iterator::next`] call parses one
/// `abi.Type` lazily — no `Vec` is allocated up front. Skips any descriptor
/// that fails to parse (adversarial input cannot panic the iteration).
pub struct TypeIter<'ctx, 'a> {
    ctx: &'ctx BinaryContext<'a>,
    data: &'a [u8],
    types_base_va: u64,
    ps: u8,
    strategy: TypeIterStrategy<'a>,
}

enum TypeIterStrategy<'a> {
    /// Iterate `int32` offsets from a typelink array.
    Typelinks { tl_data: &'a [u8], pos: usize },
    /// Walk `[types_base_va + ps .. etypes_va]` advancing by `DescriptorSize`.
    Walk { td: u64, etypes_va: u64 },
    /// No types reachable.
    Empty,
}

impl<'ctx, 'a> TypeIter<'ctx, 'a> {
    fn empty(ctx: &'ctx BinaryContext<'a>) -> Self {
        Self {
            ctx,
            data: ctx.data(),
            types_base_va: 0,
            ps: 0,
            strategy: TypeIterStrategy::Empty,
        }
    }
}

impl<'a> Iterator for TypeIter<'_, 'a> {
    type Item = GoType<'a>;

    fn next(&mut self) -> Option<GoType<'a>> {
        match &mut self.strategy {
            TypeIterStrategy::Empty => None,
            TypeIterStrategy::Typelinks { tl_data, pos } => {
                while let Some(end) = pos.checked_add(4) {
                    if end > tl_data.len() {
                        return None;
                    }
                    let bytes = tl_data.get(*pos..end).and_then(|s| s.try_into().ok())?;
                    *pos = end;
                    let type_off = i32::from_le_bytes(bytes);
                    let type_va =
                        (self.types_base_va as i64).saturating_add(type_off as i64) as u64;
                    if let Some(file_off) = self.ctx.va_to_file(type_va) {
                        if let Some(go_type) = parse_type_at(
                            self.data,
                            file_off,
                            self.types_base_va,
                            self.ps,
                            self.ctx,
                        ) {
                            return Some(go_type);
                        }
                    }
                    // Failed to parse this entry — fall through to the next.
                }
                None
            }
            TypeIterStrategy::Walk { td, etypes_va } => {
                let p = self.ps as u64;
                if p == 0 {
                    return None;
                }
                while *td < *etypes_va {
                    *td = align_up_u64(*td, p)?;
                    if *td >= *etypes_va {
                        return None;
                    }
                    let file_off = self.ctx.va_to_file(*td)?;
                    let remaining = match self.data.get(file_off..) {
                        Some(d) if d.len() >= AbiType::size(self.ps) => d,
                        _ => return None,
                    };
                    let abi_type = AbiType::parse(remaining, self.ps)?;
                    let desc_size = match descriptor::descriptor_size(remaining, &abi_type, self.ps)
                    {
                        Some(s) if s > 0 => s,
                        _ => return None,
                    };
                    let go_type = build_go_type(
                        &abi_type,
                        remaining,
                        self.data,
                        self.types_base_va,
                        self.ps,
                        self.ctx,
                    );
                    *td = td.checked_add(desc_size as u64)?;
                    if let Some(t) = go_type {
                        return Some(t);
                    }
                    // Else fall through to next iteration.
                }
                None
            }
        }
    }
}

/// Construct a streaming type iterator. The constructor performs moduledata
/// discovery up front (cheap on ELF / Mach-O, scan-based on PE) so each
/// [`Iterator::next`] call does only the per-type work.
///
/// Strategy selection mirrors the previous eager implementation:
/// 1. Dedicated `.typelink` / `__typelink` section if present.
/// 2. `moduledata.typelinks` slice (PE / older Go).
/// 3. Descriptor walk over `[types .. etypes]`.
/// 4. Empty iterator if none of the above is available.
pub fn extract_types_iter<'ctx, 'a>(
    ctx: &'ctx BinaryContext<'a>,
    ptr_size: u8,
    pclntab_version: Option<PclntabVersion>,
    pclntab_offset: Option<usize>,
    go_version_minor: Option<u32>,
) -> TypeIter<'ctx, 'a> {
    if !ctx.has_va_mapping() {
        return TypeIter::empty(ctx);
    }

    let data = ctx.data();
    let sections = ctx.sections();
    let pv = pclntab_version.unwrap_or(PclntabVersion::Go120);
    let has_typelink = sections.typelink.is_some();

    // Find moduledata: dedicated section, or PE pointer-scan discovery.
    let moduledata = if let Some(ref range) = sections.go_module {
        let end = match range.offset.checked_add(range.size) {
            Some(e) => e,
            None => return TypeIter::empty(ctx),
        };
        let md_data = match data.get(range.offset..end) {
            Some(s) => s,
            None => return TypeIter::empty(ctx),
        };
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
        _ => return TypeIter::empty(ctx),
    };

    // Strategy 1: dedicated typelink section.
    if let Some(ref range) = sections.typelink {
        if let Some(end) = range.offset.checked_add(range.size) {
            if let Some(tl_data) = data.get(range.offset..end) {
                return TypeIter {
                    ctx,
                    data,
                    types_base_va: md.types,
                    ps: ptr_size,
                    strategy: TypeIterStrategy::Typelinks { tl_data, pos: 0 },
                };
            }
        }
    }

    // Strategy 1b: typelinks slice from moduledata (Go 1.16-1.26 PE).
    if let Some(ref tl_slice) = md.typelinks {
        if let Some(tl_file_off) = ctx.va_to_file(tl_slice.ptr) {
            if let Some(tl_byte_len) = (tl_slice.len as usize).checked_mul(4) {
                if let Some(tl_end) = tl_file_off.checked_add(tl_byte_len) {
                    if let Some(tl_data) = data.get(tl_file_off..tl_end) {
                        return TypeIter {
                            ctx,
                            data,
                            types_base_va: md.types,
                            ps: ptr_size,
                            strategy: TypeIterStrategy::Typelinks { tl_data, pos: 0 },
                        };
                    }
                }
            }
        }
    }

    // Strategy 2: walk the type descriptor region.
    if md.etypes > md.types {
        let td = md.types.saturating_add(ptr_size as u64); // skip ptrSize header
        return TypeIter {
            ctx,
            data,
            types_base_va: md.types,
            ps: ptr_size,
            strategy: TypeIterStrategy::Walk {
                td,
                etypes_va: md.etypes,
            },
        };
    }

    TypeIter::empty(ctx)
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
    if p == 0 {
        return None;
    }
    let search_start = data.len().checked_div(4).unwrap_or(0); // Skip text/code section
    let target_bytes = match ps {
        4 => (pclntab_va as u32).to_le_bytes().to_vec(),
        8 => pclntab_va.to_le_bytes().to_vec(),
        _ => return None,
    };

    let mut offset = search_start;
    while let Some(end) = offset.checked_add(p) {
        if end > data.len() {
            break;
        }
        // Align to pointer size
        let rem = offset.checked_rem(p).unwrap_or(0);
        if rem != 0 {
            let bump = p.saturating_sub(rem);
            offset = match offset.checked_add(bump) {
                Some(o) => o,
                None => break,
            };
            continue;
        }

        if data.get(offset..end) == Some(target_bytes.as_slice()) {
            // Candidate moduledata at `offset`. Validate by parsing.
            let remaining = match data.get(offset..) {
                Some(r) => r,
                None => break,
            };
            if let Some(md) = Moduledata::parse(remaining, ps, pv, has_typelink, go_version_minor) {
                // Sanity checks
                if md.minpc < md.maxpc
                    && md.types != 0
                    && ctx.va_to_file(md.funcnametab.ptr).is_some()
                {
                    return Some(md);
                }
            }
        }
        offset = match offset.checked_add(p) {
            Some(o) => o,
            None => break,
        };
    }
    None
}

/// Parse a single `abi.Type` at the given file offset and build a `GoType`.
fn parse_type_at<'a>(
    data: &'a [u8],
    file_off: usize,
    types_base_va: u64,
    ps: u8,
    ctx: &BinaryContext<'a>,
) -> Option<GoType<'a>> {
    let remaining = data.get(file_off..)?;
    let abi_type = AbiType::parse(remaining, ps)?;
    build_go_type(&abi_type, remaining, data, types_base_va, ps, ctx)
}

/// Build a `GoType` from a parsed `AbiType` by resolving its name and
/// extracting kind-specific details.
fn build_go_type<'a>(
    abi_type: &AbiType,
    type_data: &'a [u8],
    full_data: &'a [u8],
    types_base_va: u64,
    ps: u8,
    ctx: &BinaryContext<'a>,
) -> Option<GoType<'a>> {
    let kind = TypeKind::from_raw(abi_type.kind());

    // Resolve name via Str (NameOff from types base)
    let name_va = (types_base_va as i64).saturating_add(abi_type.str_off as i64) as u64;
    let name: &'a str = ctx
        .va_to_file(name_va)
        .and_then(|off| full_data.get(off..))
        .and_then(decode_name)
        .unwrap_or("");

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
            .map(|a| TypeDetail::Array {
                len: a.len,
                elem_va: a.elem,
            })
            .unwrap_or(TypeDetail::None),
        TypeKind::Chan => type_data
            .get(base_sz..)
            .and_then(|d| ChanTypeExtra::parse(d, ps))
            .map(|c| TypeDetail::Chan {
                dir: c.dir,
                elem_va: c.elem,
            })
            .unwrap_or(TypeDetail::None),
        TypeKind::Func => type_data
            .get(base_sz..)
            .and_then(FuncTypeExtra::parse)
            .map(|f| {
                let (inputs, outputs) =
                    read_func_params(type_data, base_sz, f.in_count, f.num_out(), ps);
                TypeDetail::Func {
                    in_count: f.in_count,
                    out_count: f.num_out(),
                    is_variadic: f.is_variadic(),
                    inputs,
                    outputs,
                }
            })
            .unwrap_or(TypeDetail::None),
        TypeKind::Interface => type_data
            .get(base_sz..)
            .and_then(|d| InterfaceTypeExtra::parse(d, ps))
            .map(|i| {
                let methods = resolve_interface_methods(&i, full_data, types_base_va, ctx);
                TypeDetail::Interface {
                    method_count: i.methods.len,
                    methods,
                }
            })
            .unwrap_or(TypeDetail::None),
        TypeKind::Map => type_data
            .get(base_sz..)
            .and_then(|d| MapTypeExtra::parse(d, ps))
            .map(|m| TypeDetail::Map {
                key_va: m.key,
                elem_va: m.elem,
            })
            .unwrap_or(TypeDetail::None),
        TypeKind::Pointer => type_data
            .get(base_sz..)
            .and_then(|d| ElemTypeExtra::parse(d, ps))
            .map(|e| TypeDetail::Pointer { elem_va: e.elem })
            .unwrap_or(TypeDetail::None),
        TypeKind::Slice => type_data
            .get(base_sz..)
            .and_then(|d| ElemTypeExtra::parse(d, ps))
            .map(|e| TypeDetail::Slice { elem_va: e.elem })
            .unwrap_or(TypeDetail::None),
        TypeKind::Struct => type_data
            .get(base_sz..)
            .and_then(|d| StructTypeExtra::parse(d, ps))
            .map(|s| {
                let fields = resolve_struct_fields(&s, full_data, ps, ctx);
                TypeDetail::Struct {
                    field_count: s.fields.len,
                    fields,
                }
            })
            .unwrap_or(TypeDetail::None),
        _ => TypeDetail::None,
    };

    // Parse UncommonType for method counts and (optionally) method list.
    let (method_count, exported_method_count, methods) = if abi_type.has_uncommon() {
        let extra = match kind {
            TypeKind::Array => ArrayTypeExtra::size(ps),
            TypeKind::Chan => ChanTypeExtra::size(ps),
            TypeKind::Func => FuncTypeExtra::SIZE,
            TypeKind::Interface => InterfaceTypeExtra::size(ps),
            TypeKind::Map => MapTypeExtra::size(ps),
            TypeKind::Pointer | TypeKind::Slice => ElemTypeExtra::size(ps),
            TypeKind::Struct => StructTypeExtra::size(ps),
            _ => 0,
        };
        let concrete_sz = base_sz.saturating_add(extra);
        match type_data.get(concrete_sz..).and_then(UncommonType::parse) {
            Some(u) => {
                let methods = resolve_concrete_methods(
                    &u,
                    type_data,
                    concrete_sz,
                    full_data,
                    types_base_va,
                    ctx,
                );
                (u.mcount, u.xcount, methods)
            }
            None => (0, 0, Vec::new()),
        }
    } else {
        (0, 0, Vec::new())
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
        methods,
    })
}

/// Resolve the methods array hanging off an [`UncommonType`].
///
/// The methods array starts at `<uncommon_addr> + uncommon.moff`, where
/// `<uncommon_addr>` is the type-descriptor offset where the UncommonType
/// begins. Each entry is a [`GoMethod`] (16 bytes).
/// Read the in/out parameter type-descriptor VAs that follow `FuncTypeExtra`
/// in a function-type descriptor.
///
/// Layout (after the embedded `abi.Type`):
/// - 4 bytes: `FuncTypeExtra` (`InCount` u16, `OutCount` u16)
/// - Padding to pointer-size alignment
/// - `(in_count + out_count) * ps` bytes: `*Type` pointers
///
/// Returns `(inputs, outputs)`. Lengths may be shorter than the requested
/// counts on truncated input — callers should treat that as malformed.
fn read_func_params(
    type_data: &[u8],
    base_sz: usize,
    in_count: u16,
    out_count: u16,
    ps: u8,
) -> (Vec<u64>, Vec<u64>) {
    use crate::structures::util::{align_up, read_uintptr};

    let p = ps as usize;
    if p == 0 {
        return (Vec::new(), Vec::new());
    }
    // Params start after FuncTypeExtra (4 bytes), aligned to ptr size.
    let params_off = match base_sz
        .checked_add(FuncTypeExtra::SIZE)
        .and_then(|x| align_up(x, p))
    {
        Some(o) => o,
        None => return (Vec::new(), Vec::new()),
    };

    let read_one = |idx: usize| -> Option<u64> {
        let pos = params_off.checked_add(idx.checked_mul(p)?)?;
        read_uintptr(type_data, pos, ps)
    };

    let mut inputs = Vec::with_capacity(in_count as usize);
    for i in 0..(in_count as usize) {
        match read_one(i) {
            Some(v) => inputs.push(v),
            None => break,
        }
    }
    let mut outputs = Vec::with_capacity(out_count as usize);
    for i in 0..(out_count as usize) {
        let idx = match (in_count as usize).checked_add(i) {
            Some(v) => v,
            None => break,
        };
        match read_one(idx) {
            Some(v) => outputs.push(v),
            None => break,
        }
    }
    (inputs, outputs)
}

fn resolve_concrete_methods<'a>(
    uncommon: &UncommonType,
    type_data: &'a [u8],
    uncommon_off_in_type: usize,
    full_data: &'a [u8],
    types_base_va: u64,
    ctx: &BinaryContext<'a>,
) -> Vec<MethodEntry<'a>> {
    let mcount = uncommon.mcount as usize;
    if mcount == 0 {
        return Vec::new();
    }
    let methods_start = match uncommon_off_in_type.checked_add(uncommon.moff as usize) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let mut out = Vec::with_capacity(mcount);
    for i in 0..mcount {
        let off = match i
            .checked_mul(GoMethod::SIZE)
            .and_then(|delta| methods_start.checked_add(delta))
        {
            Some(o) => o,
            None => break,
        };
        let m = match type_data.get(off..).and_then(GoMethod::parse) {
            Some(m) => m,
            None => break,
        };
        let name_va = (types_base_va as i64).saturating_add(m.name as i64) as u64;
        let (name, flags): (&'a str, u8) = ctx
            .va_to_file(name_va)
            .and_then(|o| full_data.get(o..))
            .and_then(decode_name_with_flags)
            .unwrap_or(("", 0));
        let is_exported = (flags & NAME_FLAG_EXPORTED) != 0
            || name.chars().next().is_some_and(|c| c.is_ascii_uppercase());
        let function_text_offset = if m.tfn != 0 { Some(m.tfn) } else { None };
        out.push(MethodEntry {
            name,
            type_descriptor_offset: m.mtyp,
            function_text_offset,
            is_exported,
        });
    }
    out
}

/// Resolve interface method names + type offsets from an [`InterfaceTypeExtra`].
fn resolve_interface_methods<'a>(
    iface: &InterfaceTypeExtra,
    full_data: &'a [u8],
    types_base_va: u64,
    ctx: &BinaryContext<'a>,
) -> Vec<InterfaceMethod<'a>> {
    let count = iface.methods.len as usize;
    if count == 0 {
        return Vec::new();
    }
    let array_off = match ctx.va_to_file(iface.methods.ptr) {
        Some(o) => o,
        None => return Vec::new(),
    };
    let bytes = match full_data.get(array_off..) {
        Some(b) => b,
        None => return Vec::new(),
    };
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = match i.checked_mul(GoImethod::SIZE) {
            Some(o) => o,
            None => break,
        };
        let im = match bytes.get(off..).and_then(GoImethod::parse) {
            Some(im) => im,
            None => break,
        };
        let name_va = (types_base_va as i64).saturating_add(im.name as i64) as u64;
        let name: &'a str = ctx
            .va_to_file(name_va)
            .and_then(|o| full_data.get(o..))
            .and_then(decode_name)
            .unwrap_or("");
        out.push(InterfaceMethod {
            name,
            type_descriptor_offset: im.typ,
        });
    }
    out
}

/// Resolve struct field name/type/offset/embedded info.
fn resolve_struct_fields<'a>(
    extra: &StructTypeExtra,
    full_data: &'a [u8],
    ps: u8,
    ctx: &BinaryContext<'a>,
) -> Vec<StructField<'a>> {
    let count = extra.fields.len as usize;
    if count == 0 {
        return Vec::new();
    }
    let array_off = match ctx.va_to_file(extra.fields.ptr) {
        Some(o) => o,
        None => return Vec::new(),
    };
    let bytes = match full_data.get(array_off..) {
        Some(b) => b,
        None => return Vec::new(),
    };
    let stride = GoStructField::size(ps);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = match i.checked_mul(stride) {
            Some(o) => o,
            None => break,
        };
        let f = match bytes.get(off..).and_then(|d| GoStructField::parse(d, ps)) {
            Some(f) => f,
            None => break,
        };
        let (name, flags): (&'a str, u8) = ctx
            .va_to_file(f.name)
            .and_then(|o| full_data.get(o..))
            .and_then(decode_name_with_flags)
            .unwrap_or(("", 0));
        let is_embedded = (flags & NAME_FLAG_EMBEDDED) != 0;
        out.push(StructField {
            name,
            type_va: f.typ,
            offset: f.offset,
            is_embedded,
        });
    }
    out
}
