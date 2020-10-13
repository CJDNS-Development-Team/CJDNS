//! From/to string conversion routines for routing labels.
//!
//! RoutingLabel supports default formatting `format!("{}", routing_label)` (in hex form)
//! and binary formatting `format!("{:b}", routing_label)`.

use std::convert::TryFrom;
use std::fmt;

use regex::Regex;
use thiserror::Error;

use super::RoutingLabel;

#[derive(Error, Copy, Clone, PartialEq, Eq, Debug)]
pub enum LabelError {
    #[error("Malformed routing label string")]
    MalformedRoutingLabelStringValue,
    #[error("Routing label is all-zeroes")]
    ZeroRoutingLabel,
}

impl fmt::Display for RoutingLabel<u32> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <RoutingLabel<u32> as fmt::LowerHex>::fmt(self, f)
    }
}

impl fmt::Display for RoutingLabel<u64> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <RoutingLabel<u64> as fmt::LowerHex>::fmt(self, f)
    }
}

impl fmt::Display for RoutingLabel<u128> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <RoutingLabel<u128> as fmt::LowerHex>::fmt(self, f)
    }
}

impl fmt::LowerHex for RoutingLabel<u32> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.bits();
        write!(
            f,
            "{:04x}.{:04x}",
            (bits >> 16) & 0xFFFFu32,
            bits & 0xFFFFu32
        )
    }
}

impl fmt::LowerHex for RoutingLabel<u64> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.bits();
        write!(
            f,
            "{:04x}.{:04x}.{:04x}.{:04x}",
            (bits >> 48) & 0xFFFFu64,
            (bits >> 32) & 0xFFFFu64,
            (bits >> 16) & 0xFFFFu64,
            bits & 0xFFFFu64
        )
    }
}

impl fmt::LowerHex for RoutingLabel<u128> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.bits();
        write!(
            f,
            "{:04x}.{:04x}.{:04x}.{:04x}.{:04x}.{:04x}.{:04x}.{:04x}",
            (bits >> 112) & 0xFFFFu128,
            (bits >> 96) & 0xFFFFu128,
            (bits >> 80) & 0xFFFFu128,
            (bits >> 64) & 0xFFFFu128,
            (bits >> 48) & 0xFFFFu128,
            (bits >> 32) & 0xFFFFu128,
            (bits >> 16) & 0xFFFFu128,
            bits & 0xFFFFu128
        )
    }
}

impl fmt::UpperHex for RoutingLabel<u32> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.bits();
        write!(
            f,
            "{:04X}.{:04X}",
            (bits >> 16) & 0xFFFFu32,
            bits & 0xFFFFu32
        )
    }
}

impl fmt::UpperHex for RoutingLabel<u64> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.bits();
        write!(
            f,
            "{:04X}.{:04X}.{:04X}.{:04X}",
            (bits >> 48) & 0xFFFFu64,
            (bits >> 32) & 0xFFFFu64,
            (bits >> 16) & 0xFFFFu64,
            bits & 0xFFFFu64
        )
    }
}

impl fmt::UpperHex for RoutingLabel<u128> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.bits();
        write!(
            f,
            "{:04X}.{:04X}.{:04X}.{:04X}.{:04X}.{:04X}.{:04X}.{:04X}",
            (bits >> 112) & 0xFFFFu128,
            (bits >> 96) & 0xFFFFu128,
            (bits >> 80) & 0xFFFFu128,
            (bits >> 64) & 0xFFFFu128,
            (bits >> 48) & 0xFFFFu128,
            (bits >> 32) & 0xFFFFu128,
            (bits >> 16) & 0xFFFFu128,
            bits & 0xFFFFu128
        )
    }
}

impl fmt::Binary for RoutingLabel<u32> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.bits();
        write!(
            f,
            "{:016b}.{:016b}",
            (bits >> 16) & 0xFFFFu32,
            bits & 0xFFFFu32
        )
    }
}

impl fmt::Binary for RoutingLabel<u64> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.bits();
        write!(
            f,
            "{:016b}.{:016b}.{:016b}.{:016b}",
            (bits >> 48) & 0xFFFFu64,
            (bits >> 32) & 0xFFFFu64,
            (bits >> 16) & 0xFFFFu64,
            bits & 0xFFFFu64
        )
    }
}

impl fmt::Binary for RoutingLabel<u128> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.bits();
        write!(
            f,
            "{:016b}.{:016b}.{:016b}.{:016b}.{:016b}.{:016b}.{:016b}.{:016b}",
            (bits >> 112) & 0xFFFFu128,
            (bits >> 96) & 0xFFFFu128,
            (bits >> 80) & 0xFFFFu128,
            (bits >> 64) & 0xFFFFu128,
            (bits >> 48) & 0xFFFFu128,
            (bits >> 32) & 0xFFFFu128,
            (bits >> 16) & 0xFFFFu128,
            bits & 0xFFFFu128
        )
    }
}

impl TryFrom<&str> for RoutingLabel<u32> {
    type Error = LabelError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        lazy_static! {
            static ref RE: Regex = Regex::new(
                "^([[:xdigit:]]{4})\\.([[:xdigit:]]{4})$"
            ).expect("inavlid regexp");
        }

        fn capture2u32(c: &regex::Captures, group_num: usize) -> u32 {
            let s = c.get(group_num).expect("bad group index").as_str();
            u32::from_str_radix(s, 16).expect("broken regexp matched non-number")
        }

        if let Some(c) = RE.captures(value) {
            Self::try_new(
                (capture2u32(&c, 1) << 16)
                    | capture2u32(&c, 2),
            ).ok_or(LabelError::ZeroRoutingLabel)
        } else {
            Err(LabelError::MalformedRoutingLabelStringValue)
        }
    }
}

impl TryFrom<&str> for RoutingLabel<u64> {
    type Error = LabelError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        lazy_static! {
            static ref RE: Regex = Regex::new(
                "^([[:xdigit:]]{4})\\.([[:xdigit:]]{4})\\.([[:xdigit:]]{4})\\.([[:xdigit:]]{4})$"
            ).expect("inavlid regexp");
        }

        fn capture2u64(c: &regex::Captures, group_num: usize) -> u64 {
            let s = c.get(group_num).expect("bad group index").as_str();
            u64::from_str_radix(s, 16).expect("broken regexp matched non-number")
        }

        if let Some(c) = RE.captures(value) {
            Self::try_new(
                (capture2u64(&c, 1) << 48)
                    | (capture2u64(&c, 2) << 32)
                    | (capture2u64(&c, 3) << 16)
                    | capture2u64(&c, 4),
            ).ok_or(LabelError::ZeroRoutingLabel)
        } else {
            Err(LabelError::MalformedRoutingLabelStringValue)
        }
    }
}

impl TryFrom<&str> for RoutingLabel<u128> {
    type Error = LabelError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        lazy_static! {
            static ref RE: Regex = Regex::new(
                "\
                (?x)\
                ^([[:xdigit:]]{4})\\.\
                ([[:xdigit:]]{4})\\.\
                ([[:xdigit:]]{4})\\.\
                ([[:xdigit:]]{4})\\.\
                ([[:xdigit:]]{4})\\.\
                ([[:xdigit:]]{4})\\.\
                ([[:xdigit:]]{4})\\.\
                ([[:xdigit:]]{4})$"
            ).expect("inavlid regexp");
        }

        fn capture2u128(c: &regex::Captures, group_num: usize) -> u128 {
            let s = c.get(group_num).expect("bad group index").as_str();
            u128::from_str_radix(s, 16).expect("broken regexp matched non-number")
        }

        if let Some(c) = RE.captures(value) {
            Self::try_new(
                (capture2u128(&c, 1) << 112)
                    | (capture2u128(&c, 2) << 96)
                    | (capture2u128(&c, 3) << 80)
                    | (capture2u128(&c, 4) << 64)
                    | (capture2u128(&c, 5) << 48)
                    | (capture2u128(&c, 6) << 32)
                    | (capture2u128(&c, 7) << 16)
                    | capture2u128(&c, 8),
            ).ok_or(LabelError::ZeroRoutingLabel)
        } else {
            Err(LabelError::MalformedRoutingLabelStringValue)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;

    use std::convert::TryFrom;

    use rand::{RngCore, SeedableRng};
    use rand::rngs::SmallRng;

    use crate::RoutingLabel;

    use super::LabelError;

    fn l64(v: u64) -> RoutingLabel<u64> {
        RoutingLabel::try_new(v).expect("bad test data")
    }

    fn l128(v: u128) -> RoutingLabel<u128> {
        RoutingLabel::try_new(v).expect("bad test data")
    }

    #[test]
    fn label_formatting() {
        let label = l64(14574489829);
        assert_eq!(format!("{}", label), "0000.0003.64b5.10e5"); // Default format is lower-hex
        assert_eq!(format!("{:x}", label), "0000.0003.64b5.10e5");
        assert_eq!(format!("{:X}", label), "0000.0003.64B5.10E5");
        assert_eq!(format!("{:b}", label), "0000000000000000.0000000000000011.0110010010110101.0001000011100101");
    }

    #[test]
    fn label_to_string() {
        assert_eq!(l64(1).to_string(), "0000.0000.0000.0001");
        assert_eq!(l64(14574489829).to_string(), "0000.0003.64b5.10e5");

        assert_eq!(
            l128(1).to_string(),
            "0000.0000.0000.0000.0000.0000.0000.0001"
        );
        assert_eq!(
            l128(14574489829).to_string(),
            "0000.0000.0000.0000.0000.0003.64b5.10e5"
        );
    }

    #[test]
    fn label_from_string() {
        assert_eq!(RoutingLabel::<u64>::try_from("0000.0000.0000.0000"), Err(LabelError::ZeroRoutingLabel));
        assert_eq!(RoutingLabel::<u64>::try_from("0000.0000.0000.0001"), Ok(l64(1)));
        assert_eq!(RoutingLabel::<u128>::try_from("0000.0000.0000.0000.0000.0000.0000.0000"), Err(LabelError::ZeroRoutingLabel));
        assert_eq!(RoutingLabel::<u128>::try_from("0000.0000.0000.0000.0000.0000.0000.0001"), Ok(l128(1)));
        assert_eq!(RoutingLabel::<u64>::try_from("0000.0003.64b5.10e5"), Ok(l64(14574489829)));
        assert_eq!(RoutingLabel::<u64>::try_from("0002.0003.64b5.10e5"), Ok(l64(562964527911141u64)));
        assert_eq!(RoutingLabel::<u128>::try_from("0000.0000.0000.0000.0002.0003.64b5.10e5"), Ok(l128(562964527911141u128)));

        assert!(RoutingLabel::<u64>::try_from("0000.0000.0000.001").is_err());
        assert!(RoutingLabel::<u64>::try_from("0000.0003.64b5.k0e5").is_err());
        assert!(RoutingLabel::<u128>::try_from("0000.0000.0000.0000.0000.0003.64b5.k0e5").is_err());
        assert!(RoutingLabel::<u64>::try_from("0000.0003.64b510e5").is_err());
        assert!(RoutingLabel::<u64>::try_from("0000.0003.64b5.10e5555").is_err());
        assert!(RoutingLabel::<u64>::try_from("0000.0003.64b5.10e5.10e5").is_err());
        assert!(RoutingLabel::<u64>::try_from("0000000364b510e5").is_err());
        assert!(RoutingLabel::<u64>::try_from("foo").is_err());
        assert!(RoutingLabel::<u64>::try_from("").is_err());
    }

    #[test]
    fn l64_string_io() {
        let mut rng = SmallRng::seed_from_u64(4914925427922294426u64);
        for _ in 0..10000 {
            let label = l64(rng.next_u64());
            assert_eq!(RoutingLabel::<u64>::try_from(label.to_string().as_str()), Ok(label));
        }
    }
}
