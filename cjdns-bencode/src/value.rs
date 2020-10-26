//! Generic Bencode value.

use std::borrow::Cow;
use std::collections::BTreeMap;

use bendy::{decoding::FromBencode, encoding::ToBencode};
pub use bendy::decoding::Error as BdecodeError;
pub use bendy::encoding::Error as BencodeError;
use bendy::value::Value as BendyValue;

pub trait AsBValue {
    fn as_bvalue(&self) -> Result<BValue, ()>;
}

/// Generic Bencode value.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct BValue(BendyValue<'static>);

impl BValue {
    /// Create `BValue` from bencoded data bytes.
    pub fn decode(data: &[u8]) -> Result<Self, BdecodeError> {
        let v = BendyValue::from_bencode(data)?;
        Ok(BValue(v))
    }

    /// Encode this `BValue` as bencoded data bytes.
    pub fn encode(&self) -> Result<Vec<u8>, BencodeError> {
        let BValue(v) = self;
        v.to_bencode()
    }

    /// Access stored Integer value.
    pub fn as_int(&self) -> Result<i64, ()> {
        match self {
            &BValue(BendyValue::Integer(value)) => Ok(value),
            _ => Err(()),
        }
    }

    /// Access stored bytes value as UTF-8 string.
    pub fn as_string(&self) -> Result<String, ()> {
        match self {
            &BValue(BendyValue::Bytes(ref value)) => Ok(String::from_utf8(value.to_vec()).map_err(|_| ())?),
            _ => Err(()),
        }
    }

    /// Access stored bytes value.
    pub fn as_bytes(&self) -> Result<Vec<u8>, ()> {
        match self {
            &BValue(BendyValue::Bytes(ref value)) => Ok(value.to_vec()),
            _ => Err(()),
        }
    }

    /// Access stored Dict value by key and return the data under that key.
    pub fn get_dict_value(&self, key: &str) -> Result<Option<BValue>, ()> {
        // TODO 1) as_dict? 2) `&*self.as_mut_dict()?`
        let dict = match self {
            &BValue(BendyValue::Dict(ref value)) => value,
            _ => return Err(()),
        };
        let value = dict.get(key.as_bytes());
        Ok(value.cloned().map(|v| BValue(v)))
    }

    pub fn delete_dict_value(&mut self, key: &str) -> Result<(), ()> {
        let dict = self.as_mut_dict()?;
        let _ = dict.remove(key.as_bytes());
        Ok(())
    }

    pub fn set_dict_value(&mut self, key: &'static str, value: BValue) -> Result<(), ()> {
        let dict = self.as_mut_dict()?;
        let _ = dict.insert(Cow::from(key.as_bytes()), value.0);
        Ok(())
    }

    fn as_mut_dict(&mut self) -> Result<&mut BTreeMap<Cow<'static, [u8]>, BendyValue<'static>>, ()> {
        match self {
            BValue(BendyValue::Dict(value)) => Ok(value),
            _ => Err(()),
        }
    }
}

mod as_bendy_impl {
    use std::borrow::Cow;
    use std::convert::TryFrom;

    use super::{AsBValue, BendyValue, BValue};

    // TODO I have an intention to simplify in a way, that:
    // 1) one impl will be used for String, slice and vec
    // 2) there will be no need to do such things in user code: some_value.as_slice/as_bytes/as_ref.
    impl AsBValue for &[u8] {
        fn as_bvalue(&self) -> Result<BValue, ()> {
            let bendy = BendyValue::Bytes(Cow::Owned(self.to_vec()));
            Ok(BValue(bendy))
        }
    }

    impl AsBValue for u64 {
        fn as_bvalue(&self) -> Result<BValue, ()> {
            let i = i64::try_from(*self).map_err(|_| ())?;
            let bendy = BendyValue::Integer(i);
            Ok(BValue(bendy))
        }
    }

    impl AsBValue for u16 {
        fn as_bvalue(&self) -> Result<BValue, ()> {
            let i = i64::from(*self);
            let bendy = BendyValue::Integer(i);
            Ok(BValue(bendy))
        }
    }

    impl AsBValue for String {
        fn as_bvalue(&self) -> Result<BValue, ()> {
            let string_bytes = self.as_bytes().to_vec();
            let bendy = BendyValue::Bytes(Cow::Owned(string_bytes));
            Ok(BValue(bendy))
        }
    }
}