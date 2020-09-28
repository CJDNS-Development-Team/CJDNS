use std::mem::size_of_val;

use num_enum::{FromPrimitive, IntoPrimitive};

use cjdns_bytes::{ParseError, Reader, SerializeError, ExpectedSize, Writer};
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
    /// * received error type has zero code, which is considered as `None` error.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let mut reader = Reader::new(bytes);
        let (err_type_code, header_bytes, additional) = reader
            .read(ExpectedSize::NotLessThan(Self::MIN_SIZE), |r| {
                let err_type_code = r.read_u32_be()?;
                let header_bytes = r.read_slice(SwitchHeader::SIZE)?;
                // Originally nonce was parsed after switch header, but some protocol changes were applied in 2014.
                // We leave additional as raw data to be parsed into nonce or other stuff later.
                let additional = r.read_remainder().to_vec();
                Ok((err_type_code, header_bytes, additional))
            })
            .map_err(|_| ParseError::InvalidPacketSize)?;

        let err_type = ErrorMessageType::from_u32(err_type_code);
        if err_type == ErrorMessageType::None {
            return Err(ParseError::InvalidData("control message has None body error type"));
        }
        let switch_header = SwitchHeader::parse(header_bytes)?;
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
    /// * instance error type has a `Unrecognized` or `None` type
    /// * switch header serialization failed
    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        if self.err_type == ErrorMessageType::Unrecognized || self.err_type == ErrorMessageType::None {
            return Err(SerializeError::InvalidData("Unrecognized or None error type"));
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
    use std::convert::TryFrom;

    use cjdns_core::RoutingLabel;

    use super::*;

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("invalid hex string")
    }

    fn instantiate_err_data(err_type: ErrorMessageType) -> ErrorData {
        ErrorData {
            err_type,
            switch_header: SwitchHeader::parse(&decode_hex("000000000000001300480000")).expect("invalid header data"),
            additional: vec![],
        }
    }

    #[test]
    fn test_base() {
        let test_bytes = decode_hex("0000000a62c1d23a648114010379000000012d7c000006c378e071c46aefad3aa295fff396371d10678e9833807de083a4a40da39bf0f68f15c4380afbe92405196242a74bb304a8285088579f94fb01867be2171aa8d2c7b54198a89bbdb80c668e9c05");
        let parsed_additional = vec![
            0u8, 1, 45, 124, 0, 0, 6, 195, 120, 224, 113, 196, 106, 239, 173, 58, 162, 149, 255, 243, 150, 55, 29, 16, 103, 142, 152, 51, 128, 125, 224, 131,
            164, 164, 13, 163, 155, 240, 246, 143, 21, 196, 56, 10, 251, 233, 36, 5, 25, 98, 66, 167, 75, 179, 4, 168, 40, 80, 136, 87, 159, 148, 251, 1, 134,
            123, 226, 23, 26, 168, 210, 199, 181, 65, 152, 168, 155, 189, 184, 12, 102, 142, 156, 5,
        ];
        let parsed_err = ErrorData::parse(&test_bytes).expect("invalid error data");
        let serialized_err = parsed_err.serialize().expect("invalid error data");
        assert_eq!(
            parsed_err,
            ErrorData {
                err_type: ErrorMessageType::ReturnPathInvalid,
                switch_header: SwitchHeader {
                    label: RoutingLabel::<u64>::try_from("62c1.d23a.6481.1401").expect("invalid routing label string"),
                    congestion: 1,
                    suppress_errors: true,
                    version: 1,
                    label_shift: 57,
                    penalty: 0,
                },
                additional: parsed_additional
            }
        );
        assert_eq!(serialized_err, test_bytes);
    }

    #[test]
    fn test_parse_unrecognized() {
        // parsing message with unrecognized error type
        let error_codes = ["0000000b", "000000ff", "ef0020ab"];
        let rest_error_data = "0000000000000013004800001122bbccdd";
        let unrecognized_error_data = error_codes.iter().map(|&e| format!("{}{}", e, rest_error_data));
        for data_hex in unrecognized_error_data {
            let test_bytes = decode_hex(data_hex.as_str());
            let parsed_data = ErrorData::parse(&test_bytes).expect("invalid message data");
            assert_eq!(parsed_data.err_type, ErrorMessageType::Unrecognized);
        }
    }

    #[test]
    fn test_parse_invalid() {
        let invalid_data = [
            // wrong len - less than 16 bytes
            "00112233445566778899aabbccddee",
            // none error type
            "000000000000000000000013004800001122bbccdd",
            // invalid switch header
            "00000002000000000000001300c800001122bbccdd",
        ];
        for data in invalid_data.iter() {
            let invalid_bytes = decode_hex(data);
            assert!(ErrorData::parse(&invalid_bytes).is_err())
        }
    }

    #[test]
    fn test_serialize_invalid() {
        let invalid_err_data_inst = [
            // None error type can't be in control error header
            instantiate_err_data(ErrorMessageType::None),
            // Can't serialized unrecognized error
            instantiate_err_data(ErrorMessageType::Unrecognized),
        ];
        for err_data in invalid_err_data_inst.iter() {
            assert!(err_data.serialize().is_err());
        }
    }
}
