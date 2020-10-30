//! Generic Bencode value.

use std::borrow::Cow;
use std::collections::BTreeMap;

use bendy::{decoding::FromBencode, encoding::ToBencode};
pub use bendy::decoding::Error as BdecodeError;
pub use bendy::encoding::Error as BencodeError;
use bendy::value::Value as BendyValue;

/// Generic Bencode value.
#[derive(PartialEq, Eq, Clone)]
pub struct BValue(BendyValue<'static>);

pub struct BValueBuilder(Option<BendyValue<'static>>);

impl BValue {
    /// Create new `BValue` using builder.
    pub fn builder() -> BValueBuilder {
        BValueBuilder(None)
    }

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

    /// Check whether stored Dict has specified key.
    pub fn has_dict_entry(&self, key: &str) -> bool {
        let dict = match self {
            &BValue(BendyValue::Dict(ref value)) => value,
            _ => return false,
        };
        dict.contains_key(key.as_bytes())
    }

    /// Access stored Dict value by key and return the data under that key.
    pub fn get_dict_value(&self, key: &str) -> Result<Option<BValue>, ()> {
        let dict = match self {
            &BValue(BendyValue::Dict(ref value)) => value,
            _ => return Err(()),
        };
        let value = dict.get(key.as_bytes());
        Ok(value.cloned().map(|v| BValue(v)))
    }

    /// Access stored Dict value by key and return the string data under that key.
    /// If key does not exist, or associated value is not string, error is returned.
    pub fn get_dict_value_str(&self, key: &str) -> Result<String, ()> {
        self.get_dict_value(key)?.ok_or(())?.as_string()
    }

    /// Access stored Dict value by key and return the bytes data under that key.
    /// If key does not exist, or associated value is not bytes, error is returned.
    pub fn get_dict_value_bytes(&self, key: &str) -> Result<Vec<u8>, ()> {
        self.get_dict_value(key)?.ok_or(())?.as_bytes()
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

impl BValueBuilder {
    /// Finish building BValue
    pub fn build(self) -> BValue {
        let BValueBuilder(try_value) = self;
        let value = try_value.expect("set BValue data before calling build()");
        BValue(value)
    }

    /// Set BValue as value
    pub fn set_value(self, value: BValue) -> Self {
        let BValueBuilder(try_value) = self;
        assert!(try_value.is_none(), "BValue already set");
        let BValue(value) = value;
        BValueBuilder(Some(value))
    }

    /// Set integer as value
    pub fn set_int(self, data: i64) -> Self {
        let BValueBuilder(try_value) = self;
        assert!(try_value.is_none(), "BValue already set");
        let value = BendyValue::Integer(data);
        BValueBuilder(Some(value))
    }

    /// Set raw bytes as value
    pub fn set_bytes(self, data: Vec<u8>) -> Self {
        let BValueBuilder(try_value) = self;
        assert!(try_value.is_none(), "BValue already set");
        let value = BendyValue::Bytes(Cow::Owned(data));
        BValueBuilder(Some(value))
    }

    /// Set string as value
    pub fn set_str(self, s: String) -> Self {
        let BValueBuilder(try_value) = self;
        assert!(try_value.is_none(), "BValue already set");
        let value = BendyValue::Bytes(Cow::Owned(s.into_boxed_str().into_boxed_bytes().into_vec()));
        BValueBuilder(Some(value))
    }

    /// Set empty list as value (can add items later)
    pub fn set_list(self) -> Self {
        let BValueBuilder(try_value) = self;
        assert!(try_value.is_none(), "BValue already set");
        let value = BendyValue::List(Vec::new());
        BValueBuilder(Some(value))
    }

    /// Set empty dict as value (can add entries later)
    pub fn set_dict(self) -> Self {
        let BValueBuilder(try_value) = self;
        assert!(try_value.is_none(), "BValue already set");
        let value = BendyValue::Dict(BTreeMap::new());
        BValueBuilder(Some(value))
    }

    /// Add list item (panics if current value is not a list)
    pub fn add_list_item<F>(self, init: F) -> Self
        where F: FnOnce(BValueBuilder) -> BValueBuilder
    {
        let BValueBuilder(try_value) = self;
        let value = if let Some(BendyValue::List(mut list)) = try_value {
            let BValue(item) = init(BValue::builder()).build();
            list.push(item);
            BendyValue::List(list)
        } else {
            panic!("expected list BValue");
        };
        BValueBuilder(Some(value))
    }

    /// Add dict entry (panics if current value is not a dict)
    pub fn add_dict_entry<K, F>(self, key: K, init: F) -> Self
        where F: FnOnce(BValueBuilder) -> BValueBuilder,
              K: Into<String>
    {
        let BValueBuilder(try_value) = self;
        let value = if let Some(BendyValue::Dict(mut dict)) = try_value {
            let key = Cow::Owned(key.into().into_boxed_str().into_boxed_bytes().into_vec());
            let BValue(value) = init(BValue::builder()).build();
            dict.insert(key, value);
            BendyValue::Dict(dict)
        } else {
            panic!("expected dict BValue");
        };
        BValueBuilder(Some(value))
    }

    /// Add optional dict entry (panics if current value is not a dict)
    pub fn add_dict_entry_opt<K: Into<String>>(self, key: K, value_opt: Option<BValue>) -> Self {
        let BValueBuilder(try_value) = self;
        let value = if let Some(BendyValue::Dict(mut dict)) = try_value {
            if let Some(BValue(value)) = value_opt {
                let key = Cow::Owned(key.into().into_boxed_str().into_boxed_bytes().into_vec());
                dict.insert(key, value);
            }
            BendyValue::Dict(dict)
        } else {
            panic!("expected dict BValue");
        };
        BValueBuilder(Some(value))
    }
}

mod debug {
    use std::borrow::Cow;
    use std::collections::BTreeMap;
    use std::fmt;

    use bendy::value::Value as BendyValue;

    use super::BValue;

    impl fmt::Debug for BValue {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let BValue(bv) = self;
            dump_value(f, bv)?;
            Ok(())
        }
    }

    fn dump_value(f: &mut fmt::Formatter, value: &BendyValue) -> fmt::Result {
        match value {
            BendyValue::Integer(v) => write!(f, "{}", v)?,
            BendyValue::Bytes(v) if is_ascii(v) => write!(f, "'{}'", String::from_utf8_lossy(v))?,
            BendyValue::Bytes(v) => write!(f, "0x{}", hex::encode(v))?,
            BendyValue::Dict(v) => {
                f.write_str("{")?;
                dump_dict(f, v)?;
                f.write_str("}")?;
            },
            BendyValue::List(v) => {
                f.write_str("[")?;
                dump_list(f, v)?;
                f.write_str("]")?;
            },
        }
        Ok(())
    }

    fn dump_dict(f: &mut fmt::Formatter, dict: &BTreeMap<Cow<[u8]>, BendyValue>) -> fmt::Result {
        for (key, value) in dict {
            if is_ascii(key) {
                write!(f, "{}", String::from_utf8_lossy(key))?;
            } else {
                write!(f, "0x{}", hex::encode(key))?;
            }
            f.write_str(":")?;
            dump_value(f, value)?;
            f.write_str(",")?;
        }
        Ok(())
    }

    fn dump_list(f: &mut fmt::Formatter, list: &[BendyValue]) -> fmt::Result {
        for item in list {
            dump_value(f, item)?;
            f.write_str(",")?;
        }
        Ok(())
    }

    fn is_ascii(bytes: &[u8]) -> bool {
        bytes.iter().all(|&v| v >= 32 && v <= 127)
    }
}