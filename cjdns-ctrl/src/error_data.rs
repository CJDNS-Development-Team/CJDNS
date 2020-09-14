use num_enum::FromPrimitive;

use cjdns_bytes::{ParseError, Reader};
use cjdns_hdr::SwitchHeader;

/// Data for error type messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorData {
    pub err_type: ErrorMessageType,
    pub switch_header: Option<SwitchHeader>,
    pub nonce: Option<u32>,
    pub additional: Vec<u8>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
#[repr(u32)]
pub enum ErrorMessageType {
    /// No error, everything is ok.
    None = 0,
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
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        // todo 1 check length?
        let mut reader = Reader::new(bytes);
        let err_type = {
            let error_type_code = reader.read_u32_be().expect("invalid message size");
            ErrorMessageType::from_u32(error_type_code)
        };
        let switch_header = if let Some(bytes) = reader.take_bytes(SwitchHeader::SIZE).ok() {
            Some(SwitchHeader::parse(bytes)?)
        } else {
            None
        };
        // todo 2 https://github.com/cjdelisle/cjdnsctrl/blob/ec6c8b68aac6cd4fde3011ef1321f776f76d03d0/ErrMsg.js#L96
        let nonce = reader.read_u32_be().ok();
        let additional = reader.read_all_mut().to_vec();
        Ok(ErrorData {
            err_type,
            switch_header,
            nonce,
            additional,
        })
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
        // parsed additional bytes
        // vec![0u8, 0, 6, 195, 120, 224, 113, 196, 106, 239, 173, 58, 162, 149, 255, 243, 150, 55, 29, 16, 103, 142, 152, 51, 128, 125, 224, 131, 164, 164, 13, 163, 155, 240, 246, 143, 21, 196, 56, 10, 251, 233, 36, 5, 25, 98, 66, 167, 75, 179, 4, 168, 40, 80, 136, 87, 159, 148, 251, 1, 134, 123, 226, 23, 26, 168, 210, 199, 181, 65, 152, 168, 155, 189, 184, 12, 102, 142, 156, 5];
        assert_eq!(parsed_err.err_type, ErrorMessageType::ReturnPathInvalid);
        assert_eq!(parsed_err.nonce, Some(77180));
    }
}
