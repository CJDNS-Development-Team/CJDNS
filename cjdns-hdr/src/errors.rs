use thiserror::Error;

#[derive(Error, Copy, Clone, PartialEq, Eq, Debug)]
pub enum ParseError {
    #[error("Received data doesn't suit header size")]
    InvalidPacketSize,

    #[error("Received invalid data: {0}")]
    InvalidData(&'static str),

    #[error("Invariant not met: {0}")]
    InvalidInvariant(&'static str),
}

#[derive(Error, Copy, Clone, PartialEq, Eq, Debug)]
pub enum SerializeError {
    #[error("Serializing header with unrecognized values")]
    UnrecognizedData,

    #[error("Invariant not met: {0}")]
    InvalidInvariant(&'static str),

    #[error("Content type can't be serialized into bytes slice with respected length")]
    InvalidContentType, // todo variant which is used once?
}

pub(crate) type ParseResult<T> = std::result::Result<T, ParseError>;
pub(crate) type SerializeResult<T> = std::result::Result<T, SerializeError>;
