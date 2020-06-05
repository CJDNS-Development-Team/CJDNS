#[macro_use]
extern crate lazy_static;
extern crate regex;

use std::convert::TryFrom;
use std::fmt;
use std::mem::size_of;
use std::ops::{BitAnd, BitOr, BitXor, Shl, Shr};
use std::string::ToString;
use std::u64;

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
    + ToString // should output user-friendly hex label
{
    /// outputs user-friendly binary string representation
    fn to_bit_string(&self) -> String;

    // Mostly internal usage:

    /// constructs a label from some predefined value
    fn from_u32(v: u32) -> Self;

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

#[cfg(test)]
mod tests {
    extern crate rand;

    use super::*;

    use rand::rngs::SmallRng;
    use rand::{RngCore, SeedableRng};

    fn l64(v: u64) -> Label64 {
        Label64::new(v)
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
}
