use thiserror::Error;

#[derive(Error, Copy, Clone, PartialEq, Eq, Debug)]
pub enum ParseError {
    #[error("Received data doesn't suit header size")]
    InvalidPacketSize,

    #[error("Invariant not met: {0}")]
    InvalidInvariant(&'static str),

    #[error("Received invalid data: {0}")]
    InvalidData(&'static str),
}

#[derive(Error, Copy, Clone, PartialEq, Eq, Debug)]
pub enum SerializeError {
    #[error("Serializing header with unrecognized values")]
    UnrecognizedData,

    #[error("Invariant not met: {0}")]
    InvalidInvariant(&'static str),

    #[error("Received invalid data: {0}")]
    InvalidData(&'static str),
}