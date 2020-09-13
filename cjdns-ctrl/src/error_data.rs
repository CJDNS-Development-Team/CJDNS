use cjdns_bytes::{ParseError, Reader};
use cjdns_hdr::SwitchHeader;

/// Data for error type messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorData {
    err_type: ErrorMessageType,
    switch_header: Option<SwitchHeader>,
    nonce: Option<u32>,
    additional: Vec<u8>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ErrorMessageType {
    /// No error, everything is ok.
    ErrorNone = 0,
    /// The switch label was malformed.
    ErrorMalformedAddress,
    /// Packet dropped because link is congested.
    ErrorFlood,
    /// Packet dropped because node has oversent its limit.
    ErrorLinkLimitExceeded,
    /// Message too big to send.
    ErrorOversizeMessage,
    /// Message smaller than expected headers.
    ErrorUndersizedMessage,
    /// Authentication failed.
    ErrorAuthentication,
    /// Header is invalid or checksum failed.
    ErrorInvalid,
    /// Message could not be sent to its destination through no fault of the sender.
    ErrorUndeliverable,
    /// The route enters and leaves through the same interface in one switch.
    ErrorLoopRoute,
    /// The switch is unable to represent the return path.
    ErrorReturnPathInvalid,
}

impl ErrorData {
    pub fn parse(_bytes: &[u8]) -> Result<Self, ParseError> {
        // mock
        Ok(ErrorData {
            err_type: ErrorMessageType::ErrorNone,
            switch_header: None,
            nonce: None,
            additional: vec![0],
        })
    }
}
