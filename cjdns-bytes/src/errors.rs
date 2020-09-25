//! Parsing and serialization errors.

use thiserror::Error;

/// Errors returned when parsing message or its parts (for example, message header) failed
#[derive(Error, Copy, Clone, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// Data with wrong size received to parser
    #[error("Received data doesn't suit header size")]
    InvalidPacketSize,

    /// Message (or its parts) invariants are not met. Description message can be provided.
    #[error("Invariant not met: {0}")]
    InvalidInvariant(&'static str),

    /// Received unusable data. Description message can be provided.
    #[error("Received invalid data: {0}")]
    InvalidData(&'static str),

    /// Checksum match failed. Matching checksum values can be provided.
    #[error("Checksum mismatch: 0x{0:x} vs 0x{1:x}")]
    InvalidChecksum(u16, u16),
}

/// Errors returned when serializing message or its parts (for example, message header) failed
#[derive(Error, Copy, Clone, PartialEq, Eq, Debug)]
pub enum SerializeError {
    /// Trying to serialize data with values unintended to be present in the wild.
    #[error("Serializing header with unrecognized values")]
    UnrecognizedData,

    /// Message (or its parts) invariants are not met. Description message can be provided.
    #[error("Invariant not met: {0}")]
    InvalidInvariant(&'static str),

    /// Trying to serialize unusable data. Description message can be provided.
    #[error("Received invalid data: {0}")]
    InvalidData(&'static str),
}