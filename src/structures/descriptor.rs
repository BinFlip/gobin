//! Type descriptor size computation.
//!
//! Go's `abi.Type.DescriptorSize()` computes the total size of a concrete type
//! descriptor including the base `abi.Type`, the concrete-type extra fields,
//! an optional `UncommonType`, variable-length data (parameters, fields, methods),
//! and the method array.
//!
//! Source: `src/internal/abi/type.go:750-799`

use crate::structures::{
    abitype::AbiType,
    arraytype::ArrayTypeExtra,
    chantype::ChanTypeExtra,
    elemtype::ElemTypeExtra,
    functype::FuncTypeExtra,
    interfacetype::InterfaceTypeExtra,
    kind,
    maptype::MapTypeExtra,
    method::{GoImethod, GoMethod},
    structtype::{GoStructField, StructTypeExtra},
    uncommon::UncommonType,
};

/// Compute the total descriptor size for a type, equivalent to Go's
/// `abi.Type.DescriptorSize()` from `src/internal/abi/type.go:750-799`.
///
/// The total is: concrete_type_size + uncommon_type_size + variable_data + methods.
pub fn descriptor_size(type_data: &[u8], abi_type: &AbiType, ps: u8) -> Option<usize> {
    let p = ps as usize;
    let base_sz = AbiType::size(ps);

    let (concrete_sz, var_sz) = match abi_type.kind() {
        kind::ARRAY => (base_sz + ArrayTypeExtra::size(ps), 0),
        kind::CHAN => (base_sz + ChanTypeExtra::size(ps), 0),
        kind::FUNC => {
            let extra_off = base_sz;
            let extra = FuncTypeExtra::parse(type_data.get(extra_off..)?)?;
            let param_count = extra.in_count as usize + extra.num_out() as usize;
            (base_sz + FuncTypeExtra::SIZE, param_count * p)
        }
        kind::INTERFACE => {
            let extra_off = base_sz;
            let extra = InterfaceTypeExtra::parse(type_data.get(extra_off..)?, ps)?;
            (
                base_sz + InterfaceTypeExtra::size(ps),
                extra.methods.len as usize * GoImethod::SIZE,
            )
        }
        kind::MAP => (base_sz + MapTypeExtra::size(ps), 0),
        kind::POINTER => (base_sz + ElemTypeExtra::size(ps), 0),
        kind::SLICE => (base_sz + ElemTypeExtra::size(ps), 0),
        kind::STRUCT => {
            let extra_off = base_sz;
            let extra = StructTypeExtra::parse(type_data.get(extra_off..)?, ps)?;
            (
                base_sz + StructTypeExtra::size(ps),
                extra.fields.len as usize * GoStructField::size(ps),
            )
        }
        kind::BOOL
        | kind::INT
        | kind::INT8
        | kind::INT16
        | kind::INT32
        | kind::INT64
        | kind::UINT
        | kind::UINT8
        | kind::UINT16
        | kind::UINT32
        | kind::UINT64
        | kind::UINTPTR
        | kind::FLOAT32
        | kind::FLOAT64
        | kind::COMPLEX64
        | kind::COMPLEX128
        | kind::STRING
        | kind::UNSAFE_POINTER => (base_sz, 0),
        _ => return None,
    };

    let mut total = concrete_sz;

    let mcount = if abi_type.has_uncommon() {
        let ut_off = concrete_sz;
        let ut = UncommonType::parse(type_data.get(ut_off..)?)?;
        total += UncommonType::SIZE;
        ut.mcount as usize
    } else {
        0
    };

    total += var_sz;
    total += mcount * GoMethod::SIZE;

    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_abitype_buf(ps: u8, kind: u8, tflag: u8) -> Vec<u8> {
        let size = AbiType::size(ps);
        let mut buf = vec![0u8; size];
        let p = ps as usize;
        // Kind_ is at offset 2*ps + 7
        buf[2 * p + 7] = kind;
        // TFlag is at offset 2*ps + 4
        buf[2 * p + 4] = tflag;
        buf
    }

    #[test]
    fn scalar_type_size() {
        let buf = make_abitype_buf(8, kind::INT, 0);
        let abi = AbiType::parse(&buf, 8).unwrap();
        let sz = descriptor_size(&buf, &abi, 8).unwrap();
        assert_eq!(sz, AbiType::size(8));
    }

    #[test]
    fn pointer_type_size() {
        let mut buf = make_abitype_buf(8, kind::POINTER, 0);
        buf.extend(vec![0u8; ElemTypeExtra::size(8)]);
        let abi = AbiType::parse(&buf, 8).unwrap();
        let sz = descriptor_size(&buf, &abi, 8).unwrap();
        assert_eq!(sz, AbiType::size(8) + ElemTypeExtra::size(8));
    }

    #[test]
    fn unknown_kind_returns_none() {
        let buf = make_abitype_buf(8, 0xFF, 0);
        let abi = AbiType::parse(&buf, 8).unwrap();
        assert!(descriptor_size(&buf, &abi, 8).is_none());
    }
}
