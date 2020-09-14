use num_enum::FromPrimitive;

use cjdns_bytes::{ParseError, Reader, SerializeError};
use cjdns_hdr::SwitchHeader;

/// Data for error type messages
///
/// `additional` field states for raw data, that is allowed not to be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorData {
    pub err_type: ErrorMessageType,
    pub switch_header: SwitchHeader,
    pub additional: Vec<u8>,
}

/// Concrete types of error for control error message
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[repr(u32)]
pub enum ErrorMessageType {
    /// No error, everything is ok.
    None = 0, // todo discuss
    /// The switch label was malformed.
    MalformedAddress,
    /// Packet dropped because link is congested.
    Flood,
    /// Packet dropped because node has oversent its limit.
    LinkLimitExceeded,
    /// Message too big to send.
    OversizeMessage,
    /// Message smaller than expected headers.
    UndersizedMessage,
    /// Authentication failed.
    Authentication,
    /// Header is invalid or checksum failed.
    Invalid,
    /// Message could not be sent to its destination through no fault of the sender.
    Undeliverable,
    /// The route enters and leaves through the same interface in one switch.
    LoopRoute,
    /// The switch is unable to represent the return path.
    ReturnPathInvalid,

    #[num_enum(default)]
    Other,
}

impl ErrorData {
    /// `ErrorData` minimum size. First 4 bytes are for error type code.
    pub const MIN_SIZE: usize = 4 + SwitchHeader::SIZE;

    /// Parses raw bytes into `ErrorData`
    ///
    /// Result in error in several situations:
    /// * input bytes length is less than `ErrorData::MIN_SIZE`
    /// * switch header parsing failed
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < Self::MIN_SIZE {
            return Err(ParseError::InvalidPacketSize);
        }
        let mut reader = Reader::new(bytes);
        let err_type = {
            let error_type_code = reader.read_u32_be().expect("invalid message size");
            ErrorMessageType::from_u32(error_type_code)
        };
        let switch_header = {
            let switch_header_bytes = reader.take_bytes(SwitchHeader::SIZE).expect("invalid message size");
            SwitchHeader::parse(switch_header_bytes)?
        };
        // Originally nonce was parsed after switch header, but some protocol changes were applied in 2014.
        // We live additional as raw data to be parsed into nonce or other stuff later.
        let additional = reader.read_all_mut().to_vec();
        Ok(ErrorData {
            err_type,
            switch_header,
            additional,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        todo!()
    }
}

impl ErrorMessageType {
    fn from_u32(code: u32) -> ErrorMessageType {
        ErrorMessageType::from_primitive(code)
    }
}

#[cfg(test)]
mod tests {
    use hex;

    use super::{ErrorData, ErrorMessageType};
    use cjdns_hdr::SwitchHeader;

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("invalid hex string")
    }

    #[test]
    fn test_base() {
        let test_bytes = decode_hex("0000000a62c1d23a648114010379000000012d7c000006c378e071c46aefad3aa295fff396371d10678e9833807de083a4a40da39bf0f68f15c4380afbe92405196242a74bb304a8285088579f94fb01867be2171aa8d2c7b54198a89bbdb80c668e9c05");
        let parsed_err = ErrorData::parse(&test_bytes).expect("invalid error data");
        assert_eq!(parsed_err.err_type, ErrorMessageType::ReturnPathInvalid);
    }
}
