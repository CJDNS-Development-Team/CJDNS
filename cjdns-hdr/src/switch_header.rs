//! Logic for cjdns switch header parsing and serialization

use cjdns_core::RoutingLabel;

use crate::{
    errors::{ParseError, ParseResult, SerializeError, SerializeResult},
    utils::{Reader, Writer},
};

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

    pub fn parse(data: &[u8]) -> ParseResult<Self> {
        if data.len() != Self::SIZE {
            return Err(ParseError::InvalidPacketSize);
        }
        let mut data_reader = Reader::new(data);
        let label = {
            let label_bytes = data_reader.read_u64_be().expect("invalid header data size");
            RoutingLabel::<u64>::try_new(label_bytes).ok_or(ParseError::InvalidData("zero label bytes"))?
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

    #[test]
    fn test_switch_header_parse() {
        let test_data = hex::decode("000000000000001300480000").expect("invalid hex string");
        let parsed_header = SwitchHeader::parse(&test_data).expect("invalid header bytes");
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
        )
    }

    #[test]
    fn test_switch_header_serialize() {
        let switch_header = SwitchHeader {
            label: RoutingLabel::try_from("0000.0000.0000.0013").expect("invalid label string"),
            congestion: 0,
            suppress_errors: false,
            version: 1,
            label_shift: 8,
            penalty: 0,
        };
        let header_bytes = hex::decode("000000000000001300480000").expect("invalid hex string");
        let serialized_header = switch_header.serialize().expect("invalid header");
        assert_eq!(header_bytes, serialized_header);
    }
}
