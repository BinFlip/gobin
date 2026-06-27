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

use std::collections::{HashSet, VecDeque};

use crate::{
    formats::{BinaryContext, BinaryFormat},
    metadata::{is_internal_path, is_runtime_path, is_stdlib_path},
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
        moduledata::{Moduledata, ModuledataVersion},
        name::{
            NAME_FLAG_EMBEDDED, NAME_FLAG_EXPORTED, decode_name, decode_name_and_tag,
            decode_name_with_flags,
        },
        structtype::{GoStructField, StructTypeExtra},
        uncommon::UncommonType,
        util::{align_up, align_up_u64, read_uintptr},
    },
};

/// A type extracted deterministically from Go type descriptors.
///
/// All string fields borrow from the underlying binary data via the lifetime
/// `'a`. To keep results past the binary's lifetime, copy individual fields
/// or `.clone()` and convert borrows to owned `String`s at the boundary.
#[derive(Debug, Clone)]
pub struct GoType<'a> {
    /// Virtual address of this type's `abi.Type` descriptor. `0` if unknown
    /// (the value was constructed without a known location).
    pub descriptor_va: u64,
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
    /// Raw `TFlag` byte (`abi.TFlag*` bits: uncommon, extra-star, named,
    /// regular-memory, gc-mask-on-demand, direct-iface). `is_named` /
    /// `is_exported` are derived from it; this exposes the unparsed value.
    pub tflag: u8,
    /// `PtrToThis` — `TypeOff` (offset from `moduledata.types`) of the
    /// pointer-to-this (`*T`) type descriptor, or `0` if the linker emitted
    /// none.
    pub ptr_to_this: i32,
    /// VA of the type's equality function (`abi.Type.Equal`), or `0`.
    pub equal_va: u64,
    /// VA of the type's GC bitmap (`abi.Type.GCData`), or `0`.
    pub gcdata_va: u64,
    /// Package import path from the [`UncommonType`] (e.g.
    /// `"net/http"`), if this is a named type with methods. `None` for types
    /// without an uncommon section. Distinct from [`Self::package`], which is
    /// derived from the type name.
    pub pkg_path: Option<&'a str>,
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

/// A reference to another type descriptor: its virtual address plus, when it
/// resolves, the type's display name (e.g. `"int"`, `"*os.File"`,
/// `"[]uint8"`, `"map[string]int"`).
///
/// `name` is `None` when the descriptor could not be located or carries no
/// name — callers keep the raw `va` and avoid fabricating a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeRef<'a> {
    /// Virtual address of the referenced type descriptor.
    pub va: u64,
    /// Resolved type display name, if the descriptor was reachable.
    pub name: Option<&'a str>,
}

/// One concrete-type method recovered from the [`UncommonType`] method array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodEntry<'a> {
    /// Method name as decoded from the names table (borrowed from binary).
    pub name: &'a str,
    /// Type-descriptor offset relative to `moduledata.types` (`mtyp` field).
    pub type_descriptor_offset: i32,
    /// Resolved name of the method's signature-type descriptor, if it carries
    /// one. Usually `None`: Go func types are unnamed, so the *name* is empty —
    /// resolve [`Self::type_descriptor_offset`] to a [`TypeDetail::Func`]
    /// (whose params now carry names) for the full signature.
    pub type_name: Option<&'a str>,
    /// Text offset relative to `runtime.text` for the direct-call entry
    /// (`tfn`), if non-zero. `None` for methods only reachable via interface
    /// dispatch (the linker omits the direct entry when not used).
    pub function_text_offset: Option<i32>,
    /// Text offset relative to `runtime.text` for the interface-call wrapper
    /// (`ifn`), if non-zero. `None` when the linker omitted it.
    pub interface_text_offset: Option<i32>,
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
    /// Resolved name of the field's type (e.g. `"int"`, `"*bytes.Buffer"`),
    /// if the descriptor was reachable. `None` when unresolved.
    pub type_name: Option<&'a str>,
    /// The field's struct tag (e.g. `json:"id" db:"id"`), if present.
    pub tag: Option<&'a str>,
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
    /// Resolved name of the method's signature-type descriptor, if it carries
    /// one. Usually `None` (Go func types are unnamed); resolve
    /// [`Self::type_descriptor_offset`] to a [`TypeDetail::Func`] for the
    /// full, name-resolved signature.
    pub type_name: Option<&'a str>,
}

/// Kind-specific details parsed from Go type descriptors.
///
/// Each composite type kind carries extra fields after the base `abi.Type`.
/// These are parsed from the binary and surfaced here, with structural detail
/// (field/method names, key/value types, element types) preserved for
/// downstream type-shape similarity work.
///
/// # Stability
///
/// Consumers persist this enum's *kind tag* into long-lived schemas
/// (database columns, structured logs). The contract:
///
/// - **Variants** — append-only. New kinds appear as new variants; existing
///   variants are never renamed or removed.
/// - **[`Self::kind_str`]** — fixed forever once shipped; treat the
///   returned strings as serialization keys.
/// - **`Debug` strings** — *not* a stability surface.
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
        /// Virtual address of the corresponding slice type descriptor (`[]T`).
        slice_va: u64,
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
        /// Input parameter type references (VA + resolved name), in
        /// declaration order. Length matches [`in_count`] when the descriptor
        /// is well-formed; may be shorter on truncated input.
        ///
        /// [`in_count`]: TypeDetail::Func::in_count
        inputs: Vec<TypeRef<'a>>,
        /// Output (return) type references (VA + resolved name), in
        /// declaration order. Length matches [`out_count`] when the
        /// descriptor is well-formed; may be shorter on truncated input.
        ///
        /// [`out_count`]: TypeDetail::Func::out_count
        outputs: Vec<TypeRef<'a>>,
    },
    /// Interface type: `interface { ... }`.
    Interface {
        /// Number of methods in the interface.
        method_count: u64,
        /// Resolved method names + type offsets (empty if the interface has
        /// no methods, e.g. `interface{}`).
        methods: Vec<InterfaceMethod<'a>>,
        /// Package import path of the interface type, if named (from the
        /// interface descriptor's `PkgPath`). `None` for anonymous interfaces.
        pkg_path: Option<&'a str>,
    },
    /// Map type: `map[K]V`.
    Map {
        /// Virtual address of the key type descriptor.
        key_va: u64,
        /// Virtual address of the element (value) type descriptor.
        elem_va: u64,
        /// Virtual address of the internal bucket/group type descriptor.
        group_va: u64,
        /// Virtual address of the key-hashing function.
        hasher_va: u64,
        /// Byte stride between keys in a bucket/group.
        key_stride: u64,
        /// Byte stride between elements in a bucket/group.
        elem_stride: u64,
        /// Map implementation flags (`abi.MapType.Flags` /
        /// `maptype.flags` — indirect-key/elem, reflexive-key, etc.).
        flags: u32,
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

impl<'a> TypeDetail<'a> {
    /// Stable lowercase identifier for the structural-detail variant
    /// (`"none"` / `"array"` / `"chan"` / `"func"` / `"interface"` /
    /// `"map"` / `"pointer"` / `"slice"` / `"struct"`). See the
    /// `# Stability` section on [`TypeDetail`] for the durability contract.
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Array { .. } => "array",
            Self::Chan { .. } => "chan",
            Self::Func { .. } => "func",
            Self::Interface { .. } => "interface",
            Self::Map { .. } => "map",
            Self::Pointer { .. } => "pointer",
            Self::Slice { .. } => "slice",
            Self::Struct { .. } => "struct",
        }
    }

    /// Array length for `Self::Array`, otherwise `None`.
    pub fn array_len(&self) -> Option<u64> {
        match self {
            Self::Array { len, .. } => Some(*len),
            _ => None,
        }
    }

    /// Channel direction for `Self::Chan`, otherwise `None`.
    ///
    /// Encoding (matches `abi.ChanDir`): `1 = recv-only`, `2 = send-only`,
    /// `3 = bidirectional`.
    pub fn chan_dir(&self) -> Option<u64> {
        match self {
            Self::Chan { dir, .. } => Some(*dir),
            _ => None,
        }
    }

    /// `(in_count, out_count)` arity for `Self::Func`, otherwise `None`.
    pub fn func_arity(&self) -> Option<(u16, u16)> {
        match self {
            Self::Func {
                in_count,
                out_count,
                ..
            } => Some((*in_count, *out_count)),
            _ => None,
        }
    }

    /// Field count for `Self::Struct`, otherwise `None`.
    pub fn struct_field_count(&self) -> Option<u64> {
        match self {
            Self::Struct { field_count, .. } => Some(*field_count),
            _ => None,
        }
    }

    /// Method count for `Self::Interface`, otherwise `None`.
    pub fn interface_method_count(&self) -> Option<u64> {
        match self {
            Self::Interface { method_count, .. } => Some(*method_count),
            _ => None,
        }
    }
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
        if s.starts_with('[')
            && let Some(bracket_end) = s.find(']')
            && let Some(after) = bracket_end.checked_add(1).and_then(|i| s.get(i..))
        {
            s = after;
            while let Some(rest) = s.strip_prefix('*') {
                s = rest;
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

    /// Whether this type belongs to the Go runtime (`runtime` /
    /// `runtime/<sub>` package). Mirrors
    /// [`crate::metadata::FunctionInfo::is_runtime`] so type-side and
    /// function-side classifications agree on one canonical rule.
    pub fn is_runtime(&self) -> bool {
        self.package().is_some_and(is_runtime_path)
    }

    /// Whether this type belongs to a Go-internal package (runtime,
    /// `internal/*`, `vendor/*`, or compiler-emitted pseudo-paths).
    pub fn is_internal(&self) -> bool {
        self.package().is_some_and(is_internal_path)
    }

    /// Whether this type belongs to the Go standard library (not user code,
    /// not runtime internals). Stdlib package paths never contain `.`;
    /// third-party deps do (`github.com/...`, `golang.org/x/...`,
    /// `gopkg.in/...`).
    pub fn is_stdlib(&self) -> bool {
        self.package().is_some_and(is_stdlib_path)
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
pub struct TypeIter<'a> {
    ctx: &'a BinaryContext<'a>,
    data: &'a [u8],
    types_base_va: u64,
    ps: u8,
    /// Pre-1.17 (`Go116`) name length encoding (2-byte big-endian vs varint).
    legacy: bool,
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

impl<'a> TypeIter<'a> {
    fn empty(ctx: &'a BinaryContext<'a>) -> Self {
        Self {
            ctx,
            data: ctx.structure_search_data(),
            types_base_va: 0,
            ps: 0,
            legacy: false,
            strategy: TypeIterStrategy::Empty,
        }
    }
}

impl<'a> Iterator for TypeIter<'a> {
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
                    if let Some(file_off) = self.ctx.va_to_file(type_va)
                        && let Some(go_type) = parse_type_at(
                            self.data,
                            file_off,
                            type_va,
                            self.types_base_va,
                            self.ps,
                            self.legacy,
                            self.ctx,
                        )
                    {
                        return Some(go_type);
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
                        self.legacy,
                        self.ctx,
                    );
                    let here = *td;
                    *td = td.checked_add(desc_size as u64)?;
                    if let Some(mut t) = go_type {
                        t.descriptor_va = here;
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
/// Strategy selection:
/// 1. Dedicated `.typelink` / `__typelink` section if present.
/// 2. `moduledata.typelinks` slice (PE / older Go).
/// 3. Descriptor walk over `[types .. etypes]`.
/// 4. Empty iterator if none of the above is available.
pub fn extract_types_iter<'a>(
    ctx: &'a BinaryContext<'a>,
    ptr_size: u8,
    pclntab_version: Option<PclntabVersion>,
    pclntab_offset: Option<usize>,
    go_version_minor: Option<u32>,
) -> TypeIter<'a> {
    if !ctx.has_va_mapping() {
        return TypeIter::empty(ctx);
    }

    // Read all runtime structures through the address-space view: file
    // bytes for ELF/Mach-O/PE, the reconstructed linear-memory image for
    // wasm. Wasm pclntab/moduledata/types live in linear memory and span
    // multiple disjoint data segments, so accessing them via file offsets
    // alone would split structures at segment boundaries.
    let data = ctx.structure_search_data();
    let sections = ctx.sections();
    let pv = pclntab_version.unwrap_or(PclntabVersion::Go120);
    let has_typelink = sections.typelink.is_some();
    // Go ≤1.16 encodes type-name lengths as a 2-byte big-endian uint16; 1.17+
    // uses a varint. See `name::decode_name`.
    let legacy = matches!(pv, PclntabVersion::Go116 | PclntabVersion::Go12);

    // Find moduledata: the dedicated `.go.module` section (Go 1.26+), else a
    // pointer-scan for its pcHeader pointer. The section is absent on PE, on
    // wasm, and on ELF / Mach-O before Go 1.26, so the scan is the fallback for
    // every non-section case.
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
    } else {
        discover_moduledata_via_pcheader(
            ctx,
            ptr_size,
            pv,
            has_typelink,
            go_version_minor,
            pclntab_offset,
        )
    };

    let md = match moduledata {
        Some(m) if m.types != 0 => m,
        _ => return TypeIter::empty(ctx),
    };

    // Strategy 1: dedicated typelink section.
    if let Some(ref range) = sections.typelink
        && let Some(end) = range.offset.checked_add(range.size)
        && let Some(tl_data) = data.get(range.offset..end)
    {
        return TypeIter {
            ctx,
            data,
            types_base_va: md.types,
            ps: ptr_size,
            legacy,
            strategy: TypeIterStrategy::Typelinks { tl_data, pos: 0 },
        };
    }

    // Strategy 1b: typelinks slice from moduledata (Go 1.16-1.26 PE).
    if let Some(ref tl_slice) = md.typelinks
        && let Some(tl_file_off) = ctx.va_to_file(tl_slice.ptr)
        && let Some(tl_byte_len) = (tl_slice.len as usize).checked_mul(4)
        && let Some(tl_end) = tl_file_off.checked_add(tl_byte_len)
        && let Some(tl_data) = data.get(tl_file_off..tl_end)
    {
        return TypeIter {
            ctx,
            data,
            types_base_va: md.types,
            ps: ptr_size,
            legacy,
            strategy: TypeIterStrategy::Typelinks { tl_data, pos: 0 },
        };
    }

    // Strategy 2: walk the type descriptor region.
    if md.etypes > md.types {
        let td = md.types.saturating_add(ptr_size as u64); // skip ptrSize header
        return TypeIter {
            ctx,
            data,
            types_base_va: md.types,
            ps: ptr_size,
            legacy,
            strategy: TypeIterStrategy::Walk {
                td,
                etypes_va: md.etypes,
            },
        };
    }

    TypeIter::empty(ctx)
}

/// Find moduledata by scanning the address-space view for a pointer-aligned
/// value equal to the pclntab's VA.
///
/// The first field of moduledata is `pcHeader *pcHeader`, which points to the
/// pclntab. For PE we scan `data` (file bytes) for that pointer at pointer-
/// aligned positions; for wasm we scan the reconstructed linear-memory image
/// the same way (offsets in the image are linear-memory addresses, exactly
/// what the runtime stores).
fn discover_moduledata_via_pcheader(
    ctx: &BinaryContext<'_>,
    ps: u8,
    pv: PclntabVersion,
    has_typelink: bool,
    go_version_minor: Option<u32>,
    pclntab_offset: Option<usize>,
) -> Option<Moduledata> {
    let data = ctx.structure_search_data();
    let pclntab_off = pclntab_offset?;
    let pclntab_va = if ctx.format() == BinaryFormat::Wasm {
        pclntab_off as u64
    } else {
        ctx.file_to_va(pclntab_off)?
    };

    let p = ps as usize;

    if p == 0 {
        return None;
    }
    let search_start = data.len().checked_div(4).unwrap_or(0); // skip code region
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
            let remaining = match data.get(offset..) {
                Some(r) => r,
                None => break,
            };
            if let Some(md) = Moduledata::parse(remaining, ps, pv, has_typelink, go_version_minor) {
                let anchored = match md.version {
                    ModuledataVersion::V1 => md.text != 0 && ctx.va_to_file(md.text).is_some(),
                    _ => md.types != 0 && ctx.va_to_file(md.funcnametab.ptr).is_some(),
                };
                if md.minpc < md.maxpc && anchored {
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
    type_va: u64,
    types_base_va: u64,
    ps: u8,
    legacy: bool,
    ctx: &BinaryContext<'a>,
) -> Option<GoType<'a>> {
    let remaining = data.get(file_off..)?;
    let abi_type = AbiType::parse(remaining, ps)?;
    let mut t = build_go_type(&abi_type, remaining, data, types_base_va, ps, legacy, ctx)?;
    t.descriptor_va = type_va;
    Some(t)
}

/// Parse the type descriptor at virtual address `va` into a [`GoType`].
pub fn type_at_va<'a>(
    ctx: &'a BinaryContext<'a>,
    va: u64,
    types_base_va: u64,
    ps: u8,
    legacy: bool,
) -> Option<GoType<'a>> {
    let data = ctx.structure_search_data();
    let file_off = ctx.va_to_file(va)?;
    let t = parse_type_at(data, file_off, va, types_base_va, ps, legacy, ctx)?;
    // Validate this is a real descriptor, not a mid-descriptor / non-type
    // address a stray reference pointed at: the kind must be known and the
    // name must be clean (Go type names never contain control characters).
    if t.kind == TypeKind::Invalid {
        return None;
    }
    if t.name.bytes().any(|b| b < 0x20) {
        return None;
    }
    Some(t)
}

/// Transitively enumerate every type reachable from `seeds`.
///
/// BFS over type-descriptor virtual addresses: each popped VA is parsed
/// independently (robust — no reliance on descriptor sizing), and all the
/// types it references are enqueued. Reaches types absent from the seed set
/// (typically `typelink`), e.g. a struct used only as a pointer's element.
pub fn extract_all_types<'a>(
    ctx: &'a BinaryContext<'a>,
    ptr_size: u8,
    seeds: Vec<GoType<'a>>,
    types_base: u64,
    etypes: u64,
    legacy: bool,
) -> Vec<GoType<'a>> {
    const CAP: usize = 2_000_000;
    // Every Go type descriptor lives in [types, etypes). Bounding the traversal
    // to that range keeps the walk from following a stray reference into
    // non-type data and parsing cascading garbage.
    let in_range = |va: u64| va >= types_base && (etypes == 0 || va < etypes);
    let mut visited: HashSet<u64> = HashSet::new();
    let mut queue: VecDeque<u64> = VecDeque::new();
    let mut out: Vec<GoType<'a>> = Vec::new();
    for t in &seeds {
        if in_range(t.descriptor_va) {
            queue.push_back(t.descriptor_va);
        }
    }
    while let Some(va) = queue.pop_front() {
        if out.len() >= CAP {
            break;
        }
        if !in_range(va) || !visited.insert(va) {
            continue;
        }
        let t = match type_at_va(ctx, va, types_base, ptr_size, legacy) {
            Some(t) => t,
            None => continue,
        };
        collect_type_refs(&t, types_base, |r| {
            if in_range(r) && !visited.contains(&r) {
                queue.push_back(r);
            }
        });
        out.push(t);
    }
    out
}

/// Invoke `push` with the VA of every type descriptor `t` references.
fn collect_type_refs(t: &GoType<'_>, types_base: u64, mut push: impl FnMut(u64)) {
    let off_to_va = |off: i32| (types_base as i64).saturating_add(off as i64) as u64;
    if t.ptr_to_this != 0 {
        push(off_to_va(t.ptr_to_this));
    }
    match &t.detail {
        TypeDetail::Array { elem_va, .. }
        | TypeDetail::Chan { elem_va, .. }
        | TypeDetail::Pointer { elem_va }
        | TypeDetail::Slice { elem_va } => push(*elem_va),
        TypeDetail::Map {
            key_va,
            elem_va,
            group_va,
            ..
        } => {
            push(*key_va);
            push(*elem_va);
            push(*group_va);
        }
        TypeDetail::Struct { fields, .. } => {
            for f in fields {
                push(f.type_va);
            }
        }
        TypeDetail::Func {
            inputs, outputs, ..
        } => {
            for r in inputs.iter().chain(outputs.iter()) {
                push(r.va);
            }
        }
        TypeDetail::Interface { methods, .. } => {
            for m in methods {
                push(off_to_va(m.type_descriptor_offset));
            }
        }
        TypeDetail::None => {}
    }
    for m in &t.methods {
        if m.type_descriptor_offset != 0 {
            push(off_to_va(m.type_descriptor_offset));
        }
    }
}

/// Resolve a Go encoded name located at virtual address `va` to a string.
fn resolve_name_at_va<'a>(
    va: u64,
    full_data: &'a [u8],
    legacy: bool,
    ctx: &BinaryContext<'a>,
) -> Option<&'a str> {
    if va == 0 {
        return None;
    }
    ctx.va_to_file(va)
        .and_then(|o| full_data.get(o..))
        .and_then(|d| decode_name(d, legacy))
        .filter(|s| !s.is_empty())
}

/// Resolve a referenced type descriptor at `type_va` to its display name.
///
/// Parses the `abi.Type` at the target VA and decodes its `Str` (a NameOff
/// relative to `types_base_va`). One level deep only — Go already stores
/// constructed names like `[]uint8` / `map[string]int` in `Str` for composite
/// types, so this yields a usable label without reimplementing the runtime's
/// recursive type formatter. Returns `None` (rather than guessing) when the
/// descriptor is unreachable or unnamed.
fn resolve_type_name<'a>(
    type_va: u64,
    full_data: &'a [u8],
    types_base_va: u64,
    ps: u8,
    legacy: bool,
    ctx: &BinaryContext<'a>,
) -> Option<&'a str> {
    if type_va == 0 {
        return None;
    }
    let off = ctx.va_to_file(type_va)?;
    let abi = AbiType::parse(full_data.get(off..)?, ps)?;
    let name_va = (types_base_va as i64).saturating_add(abi.str_off as i64) as u64;
    let name = ctx
        .va_to_file(name_va)
        .and_then(|o| full_data.get(o..))
        .and_then(|d| decode_name(d, legacy))?;
    if name.is_empty() { None } else { Some(name) }
}

/// Build a `GoType` from a parsed `AbiType` by resolving its name and
/// extracting kind-specific details.
fn build_go_type<'a>(
    abi_type: &AbiType,
    type_data: &'a [u8],
    full_data: &'a [u8],
    types_base_va: u64,
    ps: u8,
    legacy: bool,
    ctx: &BinaryContext<'a>,
) -> Option<GoType<'a>> {
    let kind = TypeKind::from_raw(abi_type.kind());

    // Resolve name via Str (NameOff from types base)
    let name_va = (types_base_va as i64).saturating_add(abi_type.str_off as i64) as u64;
    let name: &'a str = ctx
        .va_to_file(name_va)
        .and_then(|off| full_data.get(off..))
        .and_then(|d| decode_name(d, legacy))
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
                slice_va: a.slice,
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
                let (inputs, outputs) = read_func_params(
                    type_data,
                    base_sz,
                    f.in_count,
                    f.num_out(),
                    abi_type.has_uncommon(),
                    ps,
                    legacy,
                    full_data,
                    types_base_va,
                    ctx,
                );
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
                let methods =
                    resolve_interface_methods(&i, full_data, types_base_va, ps, legacy, ctx);
                let pkg_path = resolve_name_at_va(i.pkg_path, full_data, legacy, ctx);
                TypeDetail::Interface {
                    method_count: i.methods.len,
                    methods,
                    pkg_path,
                }
            })
            .unwrap_or(TypeDetail::None),
        TypeKind::Map => type_data
            .get(base_sz..)
            .and_then(|d| MapTypeExtra::parse(d, ps))
            .map(|m| TypeDetail::Map {
                key_va: m.key,
                elem_va: m.elem,
                group_va: m.group,
                hasher_va: m.hasher,
                key_stride: m.key_stride,
                elem_stride: m.elem_stride,
                flags: m.flags,
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
                let fields = resolve_struct_fields(&s, full_data, types_base_va, ps, legacy, ctx);
                TypeDetail::Struct {
                    field_count: s.fields.len,
                    fields,
                }
            })
            .unwrap_or(TypeDetail::None),
        _ => TypeDetail::None,
    };

    // Parse UncommonType for method counts and (optionally) method list.
    let (method_count, exported_method_count, methods, pkg_path) = if abi_type.has_uncommon() {
        let extra = match kind {
            TypeKind::Array => ArrayTypeExtra::size(ps),
            TypeKind::Chan => ChanTypeExtra::size(ps),
            // The `funcType` struct is padded to pointer-size alignment before
            // the `UncommonType` (the inline parameter array follows it). Using
            // the bare `FuncTypeExtra::SIZE` here would land the `UncommonType`
            // parse short by the padding, yielding a garbage `mcount`/`moff`.
            // Mirror `descriptor::descriptor_size`'s accounting.
            TypeKind::Func => {
                match align_up(base_sz.saturating_add(FuncTypeExtra::SIZE), ps as usize) {
                    Some(off) => off.saturating_sub(base_sz),
                    None => return None,
                }
            }
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
                    ps,
                    legacy,
                    ctx,
                );
                // pkg_path is a NameOff (relative to types base) into the names
                // table; 0 means "no package path".
                let pkg_path = if u.pkg_path != 0 {
                    let name_va = (types_base_va as i64).saturating_add(u.pkg_path as i64) as u64;
                    ctx.va_to_file(name_va)
                        .and_then(|o| full_data.get(o..))
                        .and_then(|d| decode_name(d, legacy))
                        .filter(|s| !s.is_empty())
                } else {
                    None
                };
                (u.mcount, u.xcount, methods, pkg_path)
            }
            None => (0, 0, Vec::new(), None),
        }
    } else {
        (0, 0, Vec::new(), None)
    };

    Some(GoType {
        descriptor_va: 0, // set by the caller, which knows the type's VA
        name,
        kind,
        size: abi_type.size_,
        align: abi_type.align_,
        field_align: abi_type.field_align_,
        ptr_bytes: abi_type.ptr_bytes,
        hash: abi_type.hash,
        tflag: abi_type.tflag,
        ptr_to_this: abi_type.ptr_to_this,
        equal_va: abi_type.equal,
        gcdata_va: abi_type.gcdata,
        pkg_path,
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
/// - `UncommonType` (16 bytes) when the type carries one — the parameter array
///   follows it (see `abi.FuncType.InSlice`)
/// - `(in_count + out_count) * ps` bytes: `*Type` pointers
///
/// Returns `(inputs, outputs)`. Lengths may be shorter than the requested
/// counts on truncated input — callers should treat that as malformed.
#[allow(clippy::too_many_arguments)]
fn read_func_params<'a>(
    type_data: &'a [u8],
    base_sz: usize,
    in_count: u16,
    out_count: u16,
    has_uncommon: bool,
    ps: u8,
    legacy: bool,
    full_data: &'a [u8],
    types_base_va: u64,
    ctx: &BinaryContext<'a>,
) -> (Vec<TypeRef<'a>>, Vec<TypeRef<'a>>) {
    let p = ps as usize;
    if p == 0 {
        return (Vec::new(), Vec::new());
    }
    // Params start after the (ptr-aligned) `funcType` struct, then after the
    // `UncommonType` when present — Go places the inline parameter array *after*
    // the uncommon block (`abi.FuncType.InSlice`), so skipping it here is what
    // keeps the parameter VAs (and the types they reach) correct.
    let uncommon_sz = if has_uncommon { UncommonType::SIZE } else { 0 };
    let params_off = match base_sz
        .checked_add(FuncTypeExtra::SIZE)
        .and_then(|x| align_up(x, p))
        .and_then(|x| x.checked_add(uncommon_sz))
    {
        Some(o) => o,
        None => return (Vec::new(), Vec::new()),
    };

    let read_one = |idx: usize| -> Option<TypeRef<'a>> {
        let pos = params_off.checked_add(idx.checked_mul(p)?)?;
        let va = read_uintptr(type_data, pos, ps)?;
        let name = resolve_type_name(va, full_data, types_base_va, ps, legacy, ctx);
        Some(TypeRef { va, name })
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

#[allow(clippy::too_many_arguments)]
fn resolve_concrete_methods<'a>(
    uncommon: &UncommonType,
    type_data: &'a [u8],
    uncommon_off_in_type: usize,
    full_data: &'a [u8],
    types_base_va: u64,
    ps: u8,
    legacy: bool,
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
    let mut out = Vec::new();
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
        // A concrete-type method always has a name. An empty / unresolved name
        // means `mcount` over-ran the real method array and the loop is now
        // reading unrelated bytes — this happens when a stray reference is
        // mis-parsed as a type descriptor and its `UncommonType.mcount` is
        // garbage (e.g. `0xFFFF` read from padding). Stop rather than fabricate
        // thousands of empty methods. `mcount` cannot be bounded by a VA range
        // here because method arrays may be pooled outside `[types, etypes)`.
        let name_va = (types_base_va as i64).saturating_add(m.name as i64) as u64;
        let (name, flags): (&'a str, u8) = match ctx
            .va_to_file(name_va)
            .and_then(|o| full_data.get(o..))
            .and_then(|d| decode_name_with_flags(d, legacy))
        {
            Some((n, f)) if !n.is_empty() => (n, f),
            _ => break,
        };
        let is_exported = (flags & NAME_FLAG_EXPORTED) != 0
            || name.chars().next().is_some_and(|c| c.is_ascii_uppercase());
        // `tfn`/`ifn` are `textOff`s; the linker writes `-1` when the method
        // has no generated body, so only positive offsets are real entries.
        let function_text_offset = if m.tfn > 0 { Some(m.tfn) } else { None };
        let interface_text_offset = if m.ifn > 0 { Some(m.ifn) } else { None };
        let type_va = (types_base_va as i64).saturating_add(m.mtyp as i64) as u64;
        let type_name = resolve_type_name(type_va, full_data, types_base_va, ps, legacy, ctx);
        out.push(MethodEntry {
            name,
            type_descriptor_offset: m.mtyp,
            type_name,
            function_text_offset,
            interface_text_offset,
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
    ps: u8,
    legacy: bool,
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
    let mut out = Vec::new();
    for i in 0..count {
        let off = match i.checked_mul(GoImethod::SIZE) {
            Some(o) => o,
            None => break,
        };
        let im = match bytes.get(off..).and_then(GoImethod::parse) {
            Some(im) => im,
            None => break,
        };
        // An interface method always has a name. An empty / unresolved name
        // means `methods.len` over-ran the real array into unrelated bytes (a
        // mis-parsed descriptor with a garbage slice length); stop rather than
        // fabricate thousands of empty methods.
        let name_va = (types_base_va as i64).saturating_add(im.name as i64) as u64;
        let name: &'a str = match ctx
            .va_to_file(name_va)
            .and_then(|o| full_data.get(o..))
            .and_then(|d| decode_name(d, legacy))
        {
            Some(n) if !n.is_empty() => n,
            _ => break,
        };
        let type_va = (types_base_va as i64).saturating_add(im.typ as i64) as u64;
        let type_name = resolve_type_name(type_va, full_data, types_base_va, ps, legacy, ctx);
        out.push(InterfaceMethod {
            name,
            type_descriptor_offset: im.typ,
            type_name,
        });
    }
    out
}

/// Resolve struct field name/type/offset/embedded info.
fn resolve_struct_fields<'a>(
    extra: &StructTypeExtra,
    full_data: &'a [u8],
    types_base_va: u64,
    ps: u8,
    legacy: bool,
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
    let mut out = Vec::new();
    for i in 0..count {
        let off = match i.checked_mul(stride) {
            Some(o) => o,
            None => break,
        };
        let f = match bytes.get(off..).and_then(|d| GoStructField::parse(d, ps)) {
            Some(f) => f,
            None => break,
        };
        let (name, flags, tag): (&'a str, u8, Option<&'a str>) = ctx
            .va_to_file(f.name)
            .and_then(|o| full_data.get(o..))
            .and_then(|d| decode_name_and_tag(d, legacy))
            .unwrap_or(("", 0, None));
        let is_embedded = (flags & NAME_FLAG_EMBEDDED) != 0;
        let type_name = resolve_type_name(f.typ, full_data, types_base_va, ps, legacy, ctx);
        out.push(StructField {
            name,
            type_va: f.typ,
            type_name,
            tag,
            offset: f.offset,
            is_embedded,
        });
    }
    out
}
