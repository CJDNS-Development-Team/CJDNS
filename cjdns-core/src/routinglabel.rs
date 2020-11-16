//! Routing label bit operations.

use std::fmt;
use std::mem::size_of;
use std::ops::{Add, BitAnd, BitOr, BitXor, Shl, Shr, Sub};
use std::u64;

/// Routing label (a sequence of encoded **Directors**).
///
/// For more information on labels please refer to
/// [the whitepaper](https://github.com/cjdelisle/cjdns/blob/master/doc/Whitepaper.md#definitions).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RoutingLabel<L: LabelBits>(L);

/// A 64 bit routing label.
///
/// 64 bit labels are used by default.
pub type DefaultRoutingLabel = RoutingLabel<u64>;

/// Describes types which can act as routing label's underlying data type.
///
/// Routing labels itself are opaque, so this trait is required for internal data manipulations.
///
/// The following parent traits of `LabelBits` are considered public: `Sized`, `Copy`, `From<u32>`, `Eq`, `Display`.
///
/// For label manipulation routines please see the [cjdns-splice](../cjdns-splice) crate.
///
/// This trait is implemented for `u64` and `u128`.
pub trait LabelBits:
    Sized
    + Copy
    + From<u32>
    + Shl<u32, Output = Self>
    + Shr<u32, Output = Self>
    + BitXor<Output = Self>
    + BitOr<Output = Self>
    + BitAnd<Output = Self>
    + Add<Output = Self>
    + Sub<Output = Self>
    + Eq
    + fmt::Display // should output user-friendly hex label
{
    /// Zero value for this data type.
    const ZERO: Self;
    /// One (1) value for this data type.
    const ONE: Self;
    /// Bit size of the this data type.
    const BIT_SIZE: u32;
    /// Maximum number of bits a label payload can occupy.
    const MAX_PAYLOAD_BITS: u32;

    /// Index of highest set bit in binary representation.
    fn highest_set_bit(&self) -> Option<u32>;
}

impl<L: LabelBits> RoutingLabel<L> {
    /// Create new non-zero routing label. Returns `None` if `bits` is zero.
    pub fn try_new(bits: L) -> Option<Self> {
        if bits != L::ZERO {
            Some(RoutingLabel(bits))
        } else {
            None
        }
    }

    /// Create a new label which is a self-reference.
    /// Corresponds to director with value of `1`.
    pub fn self_reference() -> Self {
        let bits = L::ONE;
        RoutingLabel(bits)
    }

    /// Raw data of this routing label. Always non-zero.
    #[inline]
    pub fn bits(&self) -> L {
        let RoutingLabel(bits) = *self;
        debug_assert!(bits != L::ZERO, "invariant broken");
        bits
    }

    /// Size in bytes of this routing label
    #[inline]
    pub fn size(&self) -> usize {
        L::BIT_SIZE as usize / 8
    }
}

impl LabelBits for u32 {
    const ZERO: Self = 0;
    const ONE: Self = 1;
    const BIT_SIZE: u32 = size_of::<Self>() as u32 * 8;
    const MAX_PAYLOAD_BITS: u32 = Self::BIT_SIZE - 4;

    fn highest_set_bit(&self) -> Option<u32> {
        if Self::ZERO == *self {
            None
        } else {
            Some(Self::BIT_SIZE - 1 - self.leading_zeros() as u32)
        }
    }
}

impl LabelBits for u64 {
    const ZERO: Self = 0;
    const ONE: Self = 1;
    const BIT_SIZE: u32 = size_of::<Self>() as u32 * 8;
    const MAX_PAYLOAD_BITS: u32 = Self::BIT_SIZE - 4;

    fn highest_set_bit(&self) -> Option<u32> {
        if Self::ZERO == *self {
            None
        } else {
            Some(Self::BIT_SIZE - 1 - self.leading_zeros() as u32)
        }
    }
}

impl LabelBits for u128 {
    const ZERO: Self = 0;
    const ONE: Self = 1;
    const BIT_SIZE: u32 = size_of::<Self>() as u32 * 8;
    const MAX_PAYLOAD_BITS: u32 = Self::BIT_SIZE - 4;

    fn highest_set_bit(&self) -> Option<u32> {
        if Self::ZERO == *self {
            None
        } else {
            Some(Self::BIT_SIZE - 1 - self.leading_zeros() as u32)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_size() {
        assert_eq!(<u64 as LabelBits>::BIT_SIZE, 64);
        assert_eq!(<u128 as LabelBits>::BIT_SIZE, 128);
    }

    #[test]
    fn label_bits_highest_set_bit() {
        assert!(<u64 as LabelBits>::highest_set_bit(&0).is_none());
        assert_eq!(<u64 as LabelBits>::highest_set_bit(&1), Some(0));
        assert_eq!(<u64 as LabelBits>::highest_set_bit(&2), Some(1));
        assert_eq!(<u64 as LabelBits>::highest_set_bit(&14574489829), Some(33));
        assert_eq!(<u128 as LabelBits>::highest_set_bit(&14574489829), Some(33));
        assert_eq!(<u64 as LabelBits>::highest_set_bit(&(1 << 63)), Some(63));
        assert_eq!(<u128 as LabelBits>::highest_set_bit(&(1 << 100)), Some(100));
    }

    #[test]
    fn test_self_reference() {
        assert_eq!("0000.0001", RoutingLabel::<u32>::self_reference().to_string());
        assert_eq!("0000.0000.0000.0001", RoutingLabel::<u64>::self_reference().to_string());
        assert_eq!("0000.0000.0000.0000.0000.0000.0000.0001", RoutingLabel::<u128>::self_reference().to_string());
    }
}
