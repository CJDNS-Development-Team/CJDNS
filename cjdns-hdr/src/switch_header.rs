//! Logic for cjdns switch header parsing and serialization

use cjdns_core::RoutingLabel;

use super::{errors::HeaderError, utils::{Reader, Writer}};

type Result<T> = std::result::Result<T, HeaderError>;

const SWITCH_HEADER_SIZE: usize = 12;
const HEADER_CURRENT_VERSION: u8 = 1;

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
        if version != HEADER_CURRENT_VERSION && version != 0 {
            return Err(HeaderError::CannotParse("invalid header version"))
        }
        let penalty = data_reader.read_u16_be().expect("wrong header bytes size");
        Ok(SwitchHeader{
            label,
            congestion,
            suppress_errors,
            version,
            label_shift,
            penalty
        })
    }
}

#[cfg(test)]
mod tests {
    use hex;

    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn test_data_header_parse() {
        let test_data = hex::decode("000000000000001300480000").expect("invalid hex string");
        let parsed_header = SwitchHeader::parse(&test_data).expect("invalid header data length");
        assert_eq!(
            parsed_header,
            SwitchHeader {
                label: super::RoutingLabel::try_from("0000.0000.0000.0013").expect("invalid label string"),
                congestion: 0,
                suppress_errors: false,
                version: 1,
                label_shift: 8,
                penalty: 0
            }
        )
    }

}
