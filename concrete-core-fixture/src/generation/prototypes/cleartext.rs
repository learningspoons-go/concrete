use crate::generation::{FloatPrecision, IntegerPrecision, Precision32, Precision64, PrecisionF64};
use concrete_core::prelude::{Cleartext32, Cleartext64, CleartextF64};

/// A trait implemented by cleartext prototypes.
pub trait CleartextPrototype {
    type Precision: IntegerPrecision;
}

/// A trait implemented by cleartext float prototypes.
pub trait CleartextFloatPrototype {
    type Precision: FloatPrecision;
}

/// A type representing the prototype of a 32 bit cleartext entity.
pub struct ProtoCleartext32(pub(crate) Cleartext32);
impl CleartextPrototype for ProtoCleartext32 {
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit cleartext entity.
pub struct ProtoCleartext64(pub(crate) Cleartext64);
impl CleartextPrototype for ProtoCleartext64 {
    type Precision = Precision64;
}

/// A type representing the prototype of a 64 bit float cleartext entity.
pub struct ProtoCleartextF64(pub(crate) CleartextF64);
impl CleartextFloatPrototype for ProtoCleartextF64 {
    type Precision = PrecisionF64;
}