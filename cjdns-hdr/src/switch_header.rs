//! Logic for cjdns switch header parsing and serialization

use cjdns_core::RoutingLabel;

use crate::{
    errors::{ParseError, ParseResult, SerializeError, SerializeResult},
    utils::{Reader, Writer},
};

/// Deserialized switch header struct.
///
/// `congestion` and `suppress_errors` are encoded in 1 byte. The same is with `version` and `label_shift`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchHeader {
    pub label: RoutingLabel<u64>,
    pub congestion: u8,
    pub suppress_errors: bool,
    pub version: u8,
    pub label_shift: u8,
    pub penalty: u16,
}

impl SwitchHeader {
    pub const SIZE: usize = 12;
    pub const CURRENT_VERSION: u8 = 1;

    /// Parses bytes into `SwitchHeader` struct. Used as a constructor.
    ///
    /// Results in error if parsed [version]() value is not either 0, nor [current version](). This method also ends up with error
    /// if parsed label number is 0.
    ///
    /// `SwitchHeader` bytes have a following structure: 8 bytes for routing label, one byte for congestion value and suppress error flag, also a byte
    /// for version and label shift values and 2 bytes for penalty value. Congestion value always takes 7 bits. Last bit of congestion byte is suppress error flag.
    /// Version value takes last 2 bits of a sharing with label shift value byte. First 6 bits of the byte "belong" to [label_shift]().
    pub fn parse(data: &[u8]) -> ParseResult<Self> {
        if data.len() != Self::SIZE {
            return Err(ParseError::InvalidPacketSize);
        }
        let mut data_reader = Reader::new(data);
        let label = {
            let label_num = data_reader.read_u64_be().expect("invalid header data size");
            RoutingLabel::<u64>::try_new(label_num).ok_or(ParseError::InvalidData("zero label bytes"))?
        };
        let (congestion, suppress_errors) = {
            let congestion_and_suppress_errors = data_reader.read_u8().expect("invalid header data size");
            (congestion_and_suppress_errors >> 1, (congestion_and_suppress_errors & 1) == 1)
        };
        let (version, label_shift) = {
            let version_and_label_shift = data_reader.read_u8().expect("invalid header data size");
            // version in encoded in last 2 bits, label shift is encoded in first 6 bits
            (version_and_label_shift >> 6, version_and_label_shift & 0x3f)
        };
        // version parsed is either `Self::CURRENT_VERSION` or 0
        if version != Self::CURRENT_VERSION && version != 0 {
            return Err(ParseError::InvalidData("unrecognized version"));
        }
        let penalty = data_reader.read_u16_be().expect("invalid header data size");
        Ok(SwitchHeader {
            label,
            congestion,
            suppress_errors,
            version,
            label_shift,
            penalty,
        })
    }

    /// Serializes `SwitchHeader` instance.
    ///
    /// `SwitchHeader` type can be instantiated roughly, without using [parse]() method as a constructor.
    /// That's why serialization can result in errors. If header [version]() isn't equal to 0 or to [current version](), then serialization fails.
    /// Also serialization fails if [label_shift]() value takes more than 6 bits (which is 63u8), or if congestion value takes more than 7 bits (127u8).
    ///
    /// If `SwitchHeader` was instantiated with 0 `version`, header will be parsed with version equal to [current version](todo).
    pub fn serialize(&self) -> SerializeResult<Vec<u8>> {
        // All these checks are required, because it's possible to instantiate `SwitchHeader` without constructor function
        if self.version != Self::CURRENT_VERSION && self.version != 0 {
            return Err(SerializeError::UnrecognizedData);
        }
        // invariant checks
        if self.label_shift > 63 {
            return Err(SerializeError::InvalidInvariant("label_shift value can't take more than 6 bits"));
        }
        if self.congestion > 127 {
            return Err(SerializeError::InvalidInvariant("congestion value can't take more than 7 bits"));
        }
        let congestion_and_suppress_errors = self.congestion << 1 | self.suppress_errors as u8;
        // during serialization version could only be equal to `Self::CURRENT_VERSION`
        let version_and_label_shift = if self.version == 0 {
            Self::CURRENT_VERSION << 6 | self.label_shift
        } else {
            self.version << 6 | self.label_shift
        };

        let mut data_writer = Writer::with_capacity(Self::SIZE);
        data_writer.write_u64_be(self.label.bits());
        data_writer.write_u8(congestion_and_suppress_errors);
        data_writer.write_u8(version_and_label_shift);
        data_writer.write_u16_be(self.penalty);

        Ok(data_writer.into_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use cjdns_core::RoutingLabel;
    use hex;

    use super::SwitchHeader;

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("invalid hex string")
    }

    fn instantiate_header(label: RoutingLabel<u64>, congestion: u8, version: u8, label_shift: u8) -> SwitchHeader {
        SwitchHeader {
            label,
            congestion,
            suppress_errors: true,
            version,
            label_shift,
            penalty: 0
        }
    }

    #[test]
    fn test_base() {
        let test_data = decode_hex("000000000000001300480000");
        let parsed_header = SwitchHeader::parse(&test_data).expect("invalid header bytes");
        let serialized_header = parsed_header.serialize().expect("invalid header");
        assert_eq!(
            parsed_header,
            SwitchHeader {
                label: RoutingLabel::try_from("0000.0000.0000.0013").expect("invalid label string"),
                congestion: 0,
                suppress_errors: false,
                version: 1,
                label_shift: 8,
                penalty: 0
            }
        );
        assert_eq!(serialized_header, test_data)
    }

    #[test]
    fn test_parse_invalid() {
        let invalid_hex_data = [
            // invalid length
            "000000000000",
            "00000000000000000000000000",
            // zero label
            "000000000000000012341234",
            // wrong version -> 3
            "000000000000001300c80000"
        ];
        for hex_header in invalid_hex_data.iter() {
            let invalid_bytes = decode_hex(hex_header);
            assert!(SwitchHeader::parse(&invalid_bytes).is_err());
        }
    }

    #[test]
    fn test_serialize() {
        let invalid_headers = [
            // invalid congestion value
            instantiate_header(RoutingLabel::try_new(10).expect("zero label"), 200, 1, 1),
            // invalid version value
            instantiate_header(RoutingLabel::try_new(10).expect("zero label"), 120, 5, 1),
            // invalid label shift value
            instantiate_header(RoutingLabel::try_new(10).expect("zero label"), 127, 1, 64),
        ];
        for header in invalid_headers.iter() {
            assert!(header.serialize().is_err());
        }

        let valid_headers = [
            instantiate_header(RoutingLabel::try_new(10).expect("zero label"), 0, 0, 0),
            instantiate_header(RoutingLabel::try_new(10).expect("zero label"), 0, 1, 0),
            instantiate_header(RoutingLabel::try_new(10).expect("zero label"), 127, 1, 63),
        ];
        for header in valid_headers.iter() {
            assert!(header.serialize().is_ok());
        }
    }
}
