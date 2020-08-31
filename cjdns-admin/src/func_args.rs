//! Remote function argument list.

use std::collections::BTreeMap;

use serde::{Serialize, Serializer};
use serde::ser::SerializeMap;

/// Argument name (alias to `String`).
pub type ArgName = String;

/// Argument value (either integer or string).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ArgValue {
    /// Integer argument value.
    Int(i64),
    /// String argument value.
    String(String),
}

/// Remote function argument values.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct ArgValues(BTreeMap<ArgName, ArgValue>);

impl ArgValues {
    /// New empty instance.
    #[inline]
    pub fn new() -> Self {
        ArgValues(BTreeMap::new())
    }

    /// Add argument value to list.
    #[inline]
    pub fn add(&mut self, name: ArgName, value: ArgValue) -> &mut Self {
        let ArgValues(map) = self;
        map.insert(name, value);
        self
    }
}

impl Serialize for ArgValues {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ArgValues(map) = self;
        let mut encoder = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            match v {
                ArgValue::Int(int_val) => encoder.serialize_entry(k, int_val)?,
                ArgValue::String(str_val) => encoder.serialize_entry(k, str_val)?,
            }
        }
        encoder.end()
    }
}

#[test]
fn test_args_ser() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = ArgValues::new();
    args.add("foo".to_string(), ArgValue::String("bar".to_string()));
    args.add("boo".to_string(), ArgValue::Int(42));
    args.add("zoo".to_string(), ArgValue::Int(-42));

    let benc = String::from_utf8(bendy::serde::to_bytes(&args)?)?;
    assert_eq!(benc, "d3:booi42e3:foo3:bar3:zooi-42ee");

    Ok(())
}
