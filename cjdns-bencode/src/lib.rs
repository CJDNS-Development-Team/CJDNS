//! CJDNS Bencode library.

pub use bendy::serde::Error;
pub use bendy::serde::from_bytes;
pub use bendy::serde::to_bytes;

pub use crate::value::{BencodeError, BValue, AsBValue};

mod value;

#[cfg(test)]
mod tests {
    use bendy::decoding::FromBencode;

    #[test]
    fn test_bencode_leading_zeroes() {
        /*
         * Bencode does not allow leading zeroes in encoded integers.
         * Alas, cjdns' original implementation violates this rule,
         * and sometimes encodes ints with leading zeroes.
         * To work around this, bencode library (bendy) should be patched
         * to support this.
         * This test checks that we use correct (patched) library.
         */
        assert_eq!(u8::from_bencode("i042e".as_bytes()).ok(), Some(42_u8));
    }
}