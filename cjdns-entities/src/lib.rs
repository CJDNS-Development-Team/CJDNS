#[macro_use]
extern crate lazy_static;
extern crate regex;

use core::slice;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::iter::IntoIterator;
use std::mem::size_of;
use std::ops::{Add, BitAnd, BitOr, BitXor, Shl, Shr, Sub};
use std::string::ToString;
use std::u64;
use std::vec::Vec;

use regex::Regex;

/// Describes types which can act as labels in generic label manipulation fns.
pub trait LabelT:
    Sized
    + Copy
    + Shl<u32, Output = Self>
    + Shr<u32, Output = Self>
    + BitXor<Output = Self>
    + BitOr<Output = Self>
    + BitAnd<Output = Self>
    + Add<u32, Output = Self>
    + Sub<u32, Output = Self>
    + Eq
    + PartialEq
    + ToString // should output user-friendly hex label
{
    /// outputs user-friendly binary string representation
    fn to_bit_string(&self) -> String;

    // Mostly internal usage:

    /// constructs a label from some predefined value
    fn from_u32(v: u32) -> Self;

    /// bit size of the underlying integer type
    fn type_bit_size() -> u32;

    /// maximum number of bits a label payload can occupy
    fn max_bit_size() -> u32;

    /// index of highest set bit in binary representation
    fn highest_set_bit(&self) -> Option<u32>;
}

/// 64 bit labels are used by default.
pub type Label = Label64;

/// 64 bit label.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Label64(u64);

/// 128 bit label.
//pub struct Label128(u128);

/// Form used in an encoding scheme.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EncodingSchemeForm {
    pub bit_count: u8, // bit_count going first is important for EncodingScheme ordering
    pub prefix_len: u8,
    pub prefix: u32,
}

/// Encoding scheme.
/// Schemes are comparable for equality, immutable, opaque and iterable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodingScheme(Vec<EncodingSchemeForm>);

// todo #1
#[derive(Debug, PartialEq, Eq)]
pub struct Hop<'a, L: LabelT> {
    pub label_p: Option<L>,
    pub label_n: Option<L>,
    pub encoding_scheme: &'a EncodingScheme,
}

lazy_static! {
    pub static ref SCHEMES: HashMap<&'static str, EncodingScheme> = {
        let mut m = HashMap::new();

        m.insert(
            "f4",
            EncodingScheme::new(&[EncodingSchemeForm {
                bit_count: 4,
                prefix_len: 0,
                prefix: 0,
            }]),
        );

        m.insert(
            "f8",
            EncodingScheme::new(&[EncodingSchemeForm {
                bit_count: 8,
                prefix_len: 0,
                prefix: 0,
            }]),
        );

        m.insert(
            "v48",
            EncodingScheme::new(&[
                EncodingSchemeForm {
                    bit_count: 4,
                    prefix_len: 1,
                    prefix: 0b01,
                },
                EncodingSchemeForm {
                    bit_count: 8,
                    prefix_len: 1,
                    prefix: 0b00,
                },
            ]),
        );

        m.insert(
            "v358",
            EncodingScheme::new(&[
                EncodingSchemeForm {
                    bit_count: 3,
                    prefix_len: 1,
                    prefix: 0b01,
                },
                EncodingSchemeForm {
                    bit_count: 5,
                    prefix_len: 2,
                    prefix: 0b10,
                },
                EncodingSchemeForm {
                    bit_count: 8,
                    prefix_len: 2,
                    prefix: 0b00,
                },
            ]),
        );

        m.insert(
            "v37",
            EncodingScheme::new(&[
                EncodingSchemeForm {
                    bit_count: 3,
                    prefix_len: 1,
                    prefix: 0b01,
                },
                EncodingSchemeForm {
                    bit_count: 7,
                    prefix_len: 1,
                    prefix: 0b00,
                },
            ]),
        );

        m
    };
}

impl Label64 {
    pub fn new(v: u64) -> Self {
        Self(v)
    }
}

impl fmt::Display for Label64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04x}.{:04x}.{:04x}.{:04x}",
            (self.0 >> 48) & 0xFFFFu64,
            (self.0 >> 32) & 0xFFFFu64,
            (self.0 >> 16) & 0xFFFFu64,
            self.0 & 0xFFFFu64
        )
    }
}

fn capture2u64(c: &regex::Captures, group_num: usize) -> u64 {
    u64::from_str_radix(c.get(group_num).unwrap().as_str(), 16).unwrap()
}

impl TryFrom<&str> for Label64 {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        lazy_static! {
            static ref RE: Regex = Regex::new(
                "^([[:xdigit:]]{4})\\.([[:xdigit:]]{4})\\.([[:xdigit:]]{4})\\.([[:xdigit:]]{4})$"
            )
            .unwrap();
        }

        if let Some(c) = RE.captures(value) {
            Ok(Self(
                (capture2u64(&c, 1) << 48)
                    | (capture2u64(&c, 2) << 32)
                    | (capture2u64(&c, 3) << 16)
                    | capture2u64(&c, 4),
            ))
        } else {
            Err("Malformed 64-bit label string")
        }
    }
}

impl Shl<u32> for Label64 {
    type Output = Self;
    fn shl(self, rhs: u32) -> Self {
        Self(self.0 << rhs)
    }
}

impl Shr<u32> for Label64 {
    type Output = Self;
    fn shr(self, rhs: u32) -> Self {
        Self(self.0 >> rhs)
    }
}

impl BitAnd for Label64 {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitOr for Label64 {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitXor for Label64 {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl Add<u32> for Label64 {
    type Output = Self;
    fn add(self, rhs: u32) -> Self {
        Self(self.0.checked_add(rhs as u64).unwrap())
    }
}

impl Sub<u32> for Label64 {
    type Output = Self;
    fn sub(self, rhs: u32) -> Self {
        Self(self.0.checked_sub(rhs as u64).unwrap())
    }
}

impl LabelT for Label64 {
    fn to_bit_string(&self) -> String {
        format!(
            "{:016b}.{:016b}.{:016b}.{:016b}",
            (self.0 >> 48) & 0xFFFFu64,
            (self.0 >> 32) & 0xFFFFu64,
            (self.0 >> 16) & 0xFFFFu64,
            self.0 & 0xFFFFu64
        )
    }

    fn from_u32(v: u32) -> Self {
        Self(v as u64)
    }

    fn type_bit_size() -> u32 {
        size_of::<u64>() as u32 * 8
    }

    fn max_bit_size() -> u32 {
        size_of::<u64>() as u32 * 8 - 4
    }

    fn highest_set_bit(&self) -> Option<u32> {
        if 0 == self.0 {
            None
        } else {
            Some(size_of::<u64>() as u32 * 8 - 1 - self.0.leading_zeros() as u32)
        }
    }
}

impl EncodingScheme {
    pub fn new(forms: &[EncodingSchemeForm]) -> Self {
        let mut v = forms.to_vec();
        v.sort(); // schemes are comparable; order of forms doesn't matter
        v.dedup();
        Self(v)
    }

    pub fn forms(&self) -> &Vec<EncodingSchemeForm> {
        &self.0
    }
}

impl<'a> IntoIterator for &'a EncodingScheme {
    type Item = &'a EncodingSchemeForm;
    type IntoIter = slice::Iter<'a, EncodingSchemeForm>;

    fn into_iter(self) -> Self::IntoIter {
        (&self.0).into_iter()
    }
}

impl<'a, L: LabelT> Hop<'a, L> {
    pub fn new(label_p: L, label_n: L, encoding_scheme: &'a EncodingScheme) -> Self {
        let label_p = label_p.highest_set_bit().and_then(|_| { Some(label_p) });
        let label_n = label_n.highest_set_bit().and_then(|_| { Some(label_n) });
        Hop {
            label_p,
            label_n,
            encoding_scheme
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;

    use super::*;

    use rand::rngs::SmallRng;
    use rand::{RngCore, SeedableRng};

    fn l64(v: u64) -> Label64 {
        Label64::new(v)
    }

    fn eform(bit_count: u8, prefix_len: u8, prefix: u32) -> EncodingSchemeForm {
        EncodingSchemeForm {
            bit_count,
            prefix_len,
            prefix,
        }
    }

    #[test]
    fn l64_to_string() {
        assert_eq!(l64(0).to_string(), "0000.0000.0000.0000");
        assert_eq!(l64(1).to_string(), "0000.0000.0000.0001");
        assert_eq!(l64(14574489829).to_string(), "0000.0003.64b5.10e5");
    }

    #[test]
    fn l64_from_string() {
        assert_eq!(Label64::try_from("0000.0000.0000.0000").unwrap(), l64(0));
        assert_eq!(Label64::try_from("0000.0000.0000.0001").unwrap(), l64(1));
        assert_eq!(
            Label64::try_from("0000.0003.64b5.10e5").unwrap(),
            l64(14574489829)
        );
        assert_eq!(
            Label64::try_from("0002.0003.64b5.10e5").unwrap(),
            l64(562964527911141u64)
        );

        assert!(Label64::try_from("0000.0000.0000.001").is_err());
        assert!(Label64::try_from("0000.0003.64b5.k0e5").is_err());
        assert!(Label64::try_from("0000.0003.64b510e5").is_err());
        assert!(Label64::try_from("0000.0003.64b5.10e5555").is_err());
        assert!(Label64::try_from("0000.0003.64b5.10e5.10e5").is_err());
        assert!(Label64::try_from("0000000364b510e5").is_err());
        assert!(Label64::try_from("foo").is_err());
        assert!(Label64::try_from("").is_err());
    }

    #[test]
    fn l64_string_io() {
        let mut rng = SmallRng::seed_from_u64(4914925427922294426u64);
        for _ in 0..10000 {
            let label = l64(rng.next_u64());
            assert_eq!(
                Label64::try_from(label.to_string().as_str()).unwrap(),
                label
            );
        }
    }

    #[test]
    fn l64_highest_set_bit() {
        assert!(l64(0).highest_set_bit().is_none());

        assert_eq!(l64(1).highest_set_bit().unwrap(), 0u32);
        assert_eq!(l64(2).highest_set_bit().unwrap(), 1u32);
        assert_eq!(l64(14574489829).highest_set_bit().unwrap(), 33u32);
        assert_eq!(l64(1u64 << 63).highest_set_bit().unwrap(), 63u32);
    }

    #[test]
    fn encoding_scheme_comparison() {
        assert_eq!(
            EncodingScheme::new(&[eform(4, 2, 0b00)]),
            EncodingScheme::new(&[eform(4, 2, 0b00)])
        );
        assert_eq!(
            EncodingScheme::new(&[eform(4, 2, 0b00)]),
            EncodingScheme::new(&[eform(4, 2, 0b00), eform(4, 2, 0b00)])
        );
        assert_eq!(
            EncodingScheme::new(&[eform(4, 2, 0b00), eform(4, 2, 0b01)]),
            EncodingScheme::new(&[eform(4, 2, 0b00), eform(4, 2, 0b01), eform(4, 2, 0b00)])
        );

        assert_ne!(
            EncodingScheme::new(&[eform(4, 2, 0b00)]),
            EncodingScheme::new(&[eform(4, 2, 0b01)])
        );
        assert_ne!(
            EncodingScheme::new(&[eform(4, 2, 0b00)]),
            EncodingScheme::new(&[eform(4, 2, 0b10)])
        );
        assert_ne!(
            EncodingScheme::new(&[eform(4, 2, 0b00)]),
            EncodingScheme::new(&[eform(3, 2, 0b00)])
        );
        assert_ne!(
            EncodingScheme::new(&[eform(4, 2, 0b00)]),
            EncodingScheme::new(&[eform(4, 2, 0b00), eform(4, 2, 0b01)])
        );
    }

    #[test]
    fn encoding_scheme_iteration() {
        assert_eq!(
            EncodingScheme::new(&[eform(4, 2, 0b00), eform(4, 2, 0b01)])
                .into_iter()
                .cloned()
                .collect::<Vec<EncodingSchemeForm>>(),
            vec![eform(4, 2, 0b00), eform(4, 2, 0b01)]
        );
    }

    #[test]
    fn schemes() {
        assert_eq!(SCHEMES["f8"].forms(), &vec![eform(8, 0, 0)]);

        // smallest to biggest
        assert_eq!(SCHEMES["v358"].forms()[0].bit_count, 3);
        assert_eq!(SCHEMES["v358"].forms()[2].bit_count, 8);
    }
}
