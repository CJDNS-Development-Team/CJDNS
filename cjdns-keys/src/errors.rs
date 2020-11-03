use thiserror::Error;

#[derive(Error, Copy, Clone, PartialEq, Eq, Debug)]
pub enum KeyCreationError {
    #[error("Base32 string must encode exactly 255 bits integer in little-endian")]
    NotDecodableString,

    #[error("Wrong string format")]
    BadString,

    #[error("Resulting IP6 address must start with 0xFC byte")]
    ResultingIp6OutOfValidRange,

    #[error("Byte array must be exactly 16 bytes long")]
    InvalidLength,
}

pub type Result<T> = std::result::Result<T, KeyCreationError>;
