//! Logic for cjdns switch header parsing and serialization
// todo design question to CJ: it is possible to have a type with different field values during parse and serialization

use cjdns_core::RoutingLabel;

use crate::{
    errors::{Result, HeaderError},
    utils::{Reader, Writer},
};

const SWITCH_HEADER_SIZE: usize = 12;
const HEADER_CURRENT_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchHeader {
    pub label: RoutingLabel<u64>,
    pub congestion: u8,
    pub suppress_errors: bool,
    pub version: u8, // todo could not be gt 3? shall we make strict check?
    pub label_shift: u8,
    pub penalty: u16,
}

impl SwitchHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != SWITCH_HEADER_SIZE {
            return Err(HeaderError::CannotParse("invalid header data size"));
        }
        let mut data_reader = Reader::new(data);
        let label = {
            let label_bytes = data_reader.read_u64_be().expect("wrong header bytes size");
            RoutingLabel::<u64>::try_new(label_bytes).ok_or(HeaderError::CannotParse("invalid label bytes"))?
        };
        let (congestion, suppress_errors) = {
            let congestion_and_suppress_errors = data_reader.read_u8().expect("wrong header bytes size");
            // TODO ask Alex if check for shift op is needed
            (congestion_and_suppress_errors >> 1, (congestion_and_suppress_errors & 1) == 1)
        };
        let (version, label_shift) = {
            let version_and_label_shift = data_reader.read_u8().expect("wrong header bytes size");
            // version in encoded in last 2 bits, label shift is encoded in first 6 bits
            // TODO ask Alex if check for shift op is needed
            (version_and_label_shift >> 6, version_and_label_shift & 0x3f)
        };
        // version is either `HEADER_CURRENT_VERSION` or 0
        if version != HEADER_CURRENT_VERSION && version != 0 {
            return Err(HeaderError::CannotParse("invalid header version"));
        }
        let penalty = data_reader.read_u16_be().expect("wrong header bytes size");
        Ok(SwitchHeader {
            label,
            congestion,
            suppress_errors,
            version,
            label_shift,
            penalty,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        // All these checks are required, because it's possible to instantiate `SwitchHeader` without constructor function
        if self.version != HEADER_CURRENT_VERSION && self.version != 0 {
            return Err(HeaderError::CannotSerialize("invalid header version"));
        }
        if self.label_shift > 63 {
            return Err(HeaderError::CannotSerialize("label shift value takes more than 6 bits"));
        }
        // todo no penalty check. right?
        if self.congestion > 127 {
            return Err(HeaderError::CannotSerialize("congestion value takes more than 7 bits"));
        }
        let congestion_and_suppress_errors = self.congestion << 1 | self.suppress_errors as u8;
        // during serialization version could only ve equal to `HEADER_CURRENT_VERSION`
        let version_and_label_shift = if self.version == 0 {
            HEADER_CURRENT_VERSION << 6 | self.label_shift
        } else {
            self.version << 6 | self.label_shift
        };

        let mut data_writer = Writer::with_capacity(SWITCH_HEADER_SIZE);
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
        let parsed_header = SwitchHeader::parse(&test_data).expect("invalid header data length");
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
