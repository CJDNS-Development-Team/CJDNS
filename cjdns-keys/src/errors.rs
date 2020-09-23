use thiserror::Error;

#[derive(Error, Copy, Clone, PartialEq, Eq, Debug)]
pub enum KeyCreationError {
    #[error("Strings with non-zero trailing bit are not decodable")]
    NotDecodableString,

    #[error("String doesn't apply keys regex")]
    BadString,

    #[error("Resulting ip6 doesn't apply start with 'fc' hex byte value")]
    ResultingIp6OutOfValidRange,

    #[error("Bytes array has invalid length for key creation")]
    InvalidLength,
}

pub type Result<T> = std::result::Result<T, KeyCreationError>;
