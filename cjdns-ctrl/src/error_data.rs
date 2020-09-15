use std::mem::size_of_val;

use num_enum::{FromPrimitive, IntoPrimitive};

use cjdns_bytes::{ParseError, Reader, SerializeError, Writer};
use cjdns_hdr::SwitchHeader;

/// Body data for error type messages
///
/// `additional` field states for raw data, that is allowed not to be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorData {
    pub err_type: ErrorMessageType,
    pub switch_header: SwitchHeader,
    pub additional: Vec<u8>,
}

/// Concrete types of error for control error message
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
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
    Unrecognized,
}

impl ErrorData {
    /// `ErrorData` minimum size. First 4 bytes are reserved for error type code.
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

    /// Serializes `ErrorData` instance.
    ///
    /// `ErrorData` type can be instantiated directly, without using `parse` method.
    /// That's why serialization can result in errors in several situations:
    /// * instance error type is unrecognized
    /// * switch header serialization failed
    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        if self.err_type == ErrorMessageType::Unrecognized {
            return Err(SerializeError::InvalidData("unrecognized error type"));
        }
        let err_type_code = self.err_type.to_u32();
        let switch_header_bytes = self.switch_header.serialize()?;

        let mut writer = Writer::with_capacity(size_of_val(&err_type_code) + SwitchHeader::SIZE + self.additional.len());
        writer.write_u32_be(err_type_code);
        writer.write_slice(&switch_header_bytes);
        writer.write_slice(&self.additional);

        Ok(writer.into_vec())
    }
}

impl ErrorMessageType {
    fn from_u32(code: u32) -> ErrorMessageType {
        ErrorMessageType::from_primitive(code)
    }

    fn to_u32(self) -> u32 {
        u32::from(self)
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
        let serialized_err = parsed_err.serialize().expect("invalid error data");
        assert_eq!(parsed_err.err_type, ErrorMessageType::ReturnPathInvalid);
        assert_eq!(serialized_err, test_bytes);
    }
}
