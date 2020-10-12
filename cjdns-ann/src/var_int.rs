//! Viriable-length integer encoding implementation.
//! Based on [https://learnmeabitcoin.com/technical/varint](), but uses big-endian byte order.

use std::convert::TryFrom;
use std::mem;

use thiserror::Error;

use cjdns_bytes::{ExpectedSize, Reader};

pub(crate) trait VarInt: Sized + TryFrom<u8> + TryFrom<u16> + TryFrom<u32> + TryFrom<u64> {}

impl VarInt for u8 {}
impl VarInt for u16 {}
impl VarInt for u32 {}
impl VarInt for u64 {}

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum VarIntError {
    #[error("Can't read varint: at least 1 byte expected")]
    UnexpectedEndOfData,

    #[error("Malformed varint: expected at least {0} bytes after 0x{1:X} marker byte")]
    MalformedEncoding(usize, u8),

    #[error("Can't cast value {0} to {1}-bit data type: at least {2} bits required")]
    ValueTooBig(u64, usize, usize),
}

/// C impl https://github.com/cjdelisle/cjdns/blob/d832e26951a2af083b4defb576fe1f0beeef6327/util/VarInt.h#L65
pub(crate) fn read_var_int<T: VarInt>(reader: &mut Reader) -> Result<T, VarIntError> {
    let byte = reader.read_u8().map_err(|_| VarIntError::UnexpectedEndOfData)?;
    match byte {
        // Marker byte `0xFF` following 64-bit integer
        0xff => {
            let value = reader.read(ExpectedSize::NotLessThan(8), |r| r.read_u64_be()).map_err(|_| VarIntError::MalformedEncoding(8, byte))?;
            <T as TryFrom<u64>>::try_from(value).map_err(|_| VarIntError::ValueTooBig(value, mem::size_of::<T>()*8, 64))
        }

        // Marker byte `0xFE` following 32-bit integer
        0xfe => {
            let value = reader.read(ExpectedSize::NotLessThan(4), |r| r.read_u32_be()).map_err(|_| VarIntError::MalformedEncoding(4, byte))?;
            <T as TryFrom<u32>>::try_from(value).map_err(|_| VarIntError::ValueTooBig(value as u64, mem::size_of::<T>()*8, 32))
        }

        // Marker byte `0xFD` following 16-bit integer
        0xfd => {
            let value = reader.read(ExpectedSize::NotLessThan(2), |r| r.read_u16_be()).map_err(|_| VarIntError::MalformedEncoding(2, byte))?;
            <T as TryFrom<u16>>::try_from(value).map_err(|_| VarIntError::ValueTooBig(value as u64, mem::size_of::<T>()*8, 16))
        }

        // Otherwise this is a 8-bit integer in range `0x00..0xFC`
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
    fn test_exact_size_match() {
        let buf = decode_hex("01fd0203fe04050607ff08090a0b0c0d0e0f");
        let mut reader = Reader::new(&buf);
        assert_eq!(read_var_int::<u8>(&mut reader), Ok(1));
        assert_eq!(read_var_int::<u16>(&mut reader), Ok(0x0203));
        assert_eq!(read_var_int::<u32>(&mut reader), Ok(0x04050607));
        assert_eq!(read_var_int::<u64>(&mut reader), Ok(0x08090a0b0c0d0e0f));
        assert_eq!(read_var_int::<u8>(&mut reader), Err(VarIntError::UnexpectedEndOfData));
    }

    #[test]
    fn test_bigger_size() {
        let buf = decode_hex("01020304");
        let mut reader = Reader::new(&buf);
        assert_eq!(read_var_int::<u8>(&mut reader), Ok(1));
        assert_eq!(read_var_int::<u16>(&mut reader), Ok(2));
        assert_eq!(read_var_int::<u32>(&mut reader), Ok(3));
        assert_eq!(read_var_int::<u64>(&mut reader), Ok(4));
    }

    #[test]
    fn test_error_value_too_big() {
        let buf = decode_hex("fd0203fe04050607ff08090a0b0c0d0e0f");
        let mut reader = Reader::new(&buf);
        assert_eq!(read_var_int::<u8>(&mut reader), Err(VarIntError::ValueTooBig(0x0203, 8, 16)));
        assert_eq!(read_var_int::<u16>(&mut reader), Err(VarIntError::ValueTooBig(0x04050607, 16, 32)));
        assert_eq!(read_var_int::<u32>(&mut reader), Err(VarIntError::ValueTooBig(0x08090a0b0c0d0e0f, 32, 64)));
    }

    #[test]
    fn test_error_bad_encoding() {
        let buf = decode_hex("ff11223344556677");
        let mut reader = Reader::new(&buf);
        assert_eq!(read_var_int::<u64>(&mut reader), Err(VarIntError::MalformedEncoding(8, 0xFF)));
    }
}