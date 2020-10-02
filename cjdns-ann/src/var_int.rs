//! VarInt
//! The same idea as here https://learnmeabitcoin.com/technical/varint, but we parse big endian bytes.
use std::convert::TryFrom;

use cjdns_bytes::{ExpectedSize, Reader};

use crate::errors::VarIntError;

pub(crate) trait VarInt where Self: Sized + TryFrom<u8> + TryFrom<u16> + TryFrom<u32> + TryFrom<u64> {}

impl VarInt for u8 {}
impl VarInt for u16 {}
impl VarInt for u32 {}
impl VarInt for u64 {}

/// C impl https://github.com/cjdelisle/cjdns/blob/d832e26951a2af083b4defb576fe1f0beeef6327/util/VarInt.h#L65
pub(crate) fn read_var_int<T: VarInt>(reader: &mut Reader) -> Result<T, VarIntError> {
    let byte = reader.read_u8().map_err(|_| VarIntError::InsufficientData)?;
    match byte {
        0xff => {
            let output = reader.read(ExpectedSize::NotLessThan(8), |r| {
                let output = r.read_u64_be()?;
                Ok(output)
            }).map_err(|_| VarIntError::MalformedVarIntEncoding)?;
            T::try_from(output).map_err(|_| VarIntError::VarIntValueTooBig)
        }
        0xfe => {
            let output = reader.read(ExpectedSize::NotLessThan(4), |r| {
                let output = r.read_u32_be()?;
                Ok(output)
            }).map_err(|_| VarIntError::MalformedVarIntEncoding)?;
            T::try_from(output).map_err(|_| VarIntError::VarIntValueTooBig)
        }
        0xfd => {
            let output = reader.read(ExpectedSize::NotLessThan(2), |r| {
                let output = r.read_u16_be()?;
                Ok(output)
            }).map_err(|_| VarIntError::MalformedVarIntEncoding)?;
            T::try_from(output).map_err(|_| VarIntError::VarIntValueTooBig)
        }
        _ => T::try_from(byte).map_err(|_| unreachable!()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("invalid hex string")
    }

    #[test]
    fn test_base() {
        let buf = decode_hex("01fd0203fe04050607ff08090a0b0c0d0e0f");
        let mut reader = Reader::new(&buf);

        let num1 = read_var_int::<u8>(&mut reader).expect("not enough data");
        assert_eq!(num1, 1);
        let num2 = read_var_int::<u16>(&mut reader).expect("not enough data");
        assert_eq!(num2, 0x0203);
        let num3 = read_var_int::<u32>(&mut reader).expect("not enough data");
        assert_eq!(num3, 0x04050607);
        let num4 = read_var_int::<u64>(&mut reader).expect("not enough data");
        assert_eq!(num4, 0x08090a0b0c0d0e0f);
        let err = read_var_int::<u8>(&mut reader).expect_err("buffer isn't empty");
        assert_eq!(err, VarIntError::InsufficientData)
    }

    #[test]
    fn test_miscellaneous() {
        let buf = decode_hex("01fd0203fe04050607ff08090a0b0c0d0e0f");
        let mut reader = Reader::new(&buf);

        // creating u16 from 1 byte
        let num1 = read_var_int::<u16>(&mut reader).expect("not enough data");
        assert_eq!(num1, 1);
        let err1 = read_var_int::<u8>(&mut reader).expect_err("read value < u8::MAX()");
        assert_eq!(err1, VarIntError::VarIntValueTooBig);
        let err2 = read_var_int::<u16>(&mut reader).expect_err("read value < u16::MAX()");
        assert_eq!(err2, VarIntError::VarIntValueTooBig);
        let err3 = read_var_int::<u32>(&mut reader).expect_err("read value < u32::MAX()");
        assert_eq!(err3, VarIntError::VarIntValueTooBig);
        let err = read_var_int::<u8>(&mut reader).expect_err("buffer isn't empty");
        assert_eq!(err, VarIntError::InsufficientData)
    }

    #[test]
    fn test_malformed_var_int() {
        let buf = decode_hex("ff11223344556677");
        let mut reader = Reader::new(&buf);

        assert_eq!(read_var_int::<u64>(&mut reader), Err(VarIntError::MalformedVarIntEncoding));
    }
}