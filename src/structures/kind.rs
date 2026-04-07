//! Go type kind constants (`abi.Kind`).
//!
//! The low 5 bits of `abi.Type.Kind_` encode the type kind.
//! These values have been stable since Go 1.2.
//!
//! Source: `src/internal/abi/type.go:52-80`

/// `bool`
pub const BOOL: u8 = 1;
/// `int`
pub const INT: u8 = 2;
/// `int8`
pub const INT8: u8 = 3;
/// `int16`
pub const INT16: u8 = 4;
/// `int32`
pub const INT32: u8 = 5;
/// `int64`
pub const INT64: u8 = 6;
/// `uint`
pub const UINT: u8 = 7;
/// `uint8` (alias: `byte`)
pub const UINT8: u8 = 8;
/// `uint16`
pub const UINT16: u8 = 9;
/// `uint32` (alias: `rune`)
pub const UINT32: u8 = 10;
/// `uint64`
pub const UINT64: u8 = 11;
/// `uintptr`
pub const UINTPTR: u8 = 12;
/// `float32`
pub const FLOAT32: u8 = 13;
/// `float64`
pub const FLOAT64: u8 = 14;
/// `complex64`
pub const COMPLEX64: u8 = 15;
/// `complex128`
pub const COMPLEX128: u8 = 16;
/// Fixed-size array `[N]T`
pub const ARRAY: u8 = 17;
/// Channel `chan T`
pub const CHAN: u8 = 18;
/// Function type `func(...) ...`
pub const FUNC: u8 = 19;
/// Interface type `interface { ... }`
pub const INTERFACE: u8 = 20;
/// Map type `map[K]V`
pub const MAP: u8 = 21;
/// Pointer type `*T`
pub const POINTER: u8 = 22;
/// Slice type `[]T`
pub const SLICE: u8 = 23;
/// `string`
pub const STRING: u8 = 24;
/// Struct type `struct { ... }`
pub const STRUCT: u8 = 25;
/// `unsafe.Pointer`
pub const UNSAFE_POINTER: u8 = 26;
