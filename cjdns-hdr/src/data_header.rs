//! Logic for a simple data header, providing type of content

use super::{header_bytes_reader::HeaderBytesReader, errors::HeaderError};

type Result<T> = std::result::Result<T, HeaderError>;

const DATA_HEADER_SIZE: usize = 4usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataHeader {
    version: u8,
    content_type: Option<&'static str> // todo 1 - waiting for Alex comment on C impl of content type get
}

impl DataHeader {

    /// Parses bytes into `DataHeader` struct.
    ///
    /// Results in error if bytes length doesn't equal to 4
    pub fn parse(mut header_bytes_iter: HeaderBytesReader) -> Result<Self> {
        if header_bytes_iter.len() != DATA_HEADER_SIZE {
            return Err(HeaderError::CannotParse("invalid header data size"));
        }
        let version = {
            let version_with_flags = header_bytes_iter.read_be_u8().expect("wrong header bytes size");
            let version = version_with_flags >> 4;
            if version > 15 {
                return Err(HeaderError::CannotParse("invalid version number"));
            }
            version
        };
        // unused
        let _pad = header_bytes_iter.read_be_u8().expect("wrong header bytes size");

        let content_type = {
            let content_number = header_bytes_iter.read_be_u16().expect("wrong header bytes size");
            content_type::as_string(content_number)
        };
        Ok(DataHeader{
            version,
            content_type
        })
    }

    /// Serializes `DataHeader` instance.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        // todo 1 No need for content type validity check if we have parsed &str content type, but not an Option
        if self.content_type.is_none() {
            return Err(HeaderError::CannotSerialize("content type not found"));
        }
        let mut serialized_header = Vec::with_capacity(4);
        let version_with_flags_bytes = {
            // `parse` fails `DataHeader` initialization if `self.version`
            let version_with_flags = self.version << 4; // todo 4 & 0xff? https://github.com/cjdelisle/cjdnshdr/blob/a2c4cda8234ec5d635f8a60d37992ead4cdbc689/DataHeader.js#L56
            version_with_flags.to_be_bytes()
        };
        // unused
        let pad = 0u8.to_be_bytes();
        let content_type_number_bytes = {
            let content_type = self.content_type.expect("content type not found");
            let &content_type_num = content_type::to_num(content_type).expect("content num not found");
            content_type_num.to_be_bytes()
        };

        serialized_header.extend_from_slice(version_with_flags_bytes.as_ref());
        serialized_header.extend_from_slice(pad.as_ref());
        serialized_header.extend_from_slice(content_type_number_bytes.as_ref());

        Ok(serialized_header)
    }
}



mod content_type {
    use std::collections::HashMap;

    lazy_static! {
        static ref CONTENT_TYPE: HashMap<&'static str, u16> = {
            let mut m = HashMap::new();

            let type_num_array = [
                ("IP6_HOP", 0u16),
                ("IP6_ICMP", 1),
                ("IP6_IGMP", 2),
                ("IP6_IPV4", 4),
                ("IP6_TCP", 6),
                ("IP6_EGP", 8),
                ("IP6_PUP", 12),
                ("IP6_UDP", 17),
                ("IP6_IDP", 22),
                ("IP6_TP", 29),
                ("IP6_DCCP", 33),
                ("IP6_IPV6", 41),
                ("IP6_RSVP", 46),
                ("IP6_GRE", 47),
                ("IP6_ESP", 50),
                ("IP6_AH", 51),
                ("IP6_ICMPV6", 58),
                ("IP6_MTP", 92),
                ("IP6_BEETPH", 94),
                ("IP6_ENCAP", 98),
                ("IP6_PIM", 103),
                ("IP6_COMP", 108),
                ("IP6_SCTP", 132),
                ("IP6_UDPLITE", 136),
                ("IP6_MAX", 255),
                ("CJDHT", 256),
                ("IPTUN", 257)
                // todo 3 discuss with Alex
            ];

            for &(content_type, content_type_num) in type_num_array.iter() {
                m.insert(content_type, content_type_num);
            }
            m
        };
    }

    pub(super) fn as_string(content_number: u16) -> Option<&'static str> {
        CONTENT_TYPE.iter().find_map(|(&content_type, &val)| {
            if content_number == val {
                return Some(content_type);
            }
            None
        })
    }

    pub(super) fn to_num(content_type: &str) -> Option<&u16> {
        CONTENT_TYPE.get(content_type)
    }

    #[cfg(test)]
    mod tests {

    }
}

#[cfg(test)]
mod tests {
    use hex;
    use crate::data_header::{DataHeader, HeaderBytesReader};

    #[test]
    fn test_data_header_parse() {
        let test_data = hex::decode("10000100").expect("invalid hex string");
        let header_bytes_reader = HeaderBytesReader::from(test_data.iter());
        let parsed_header = DataHeader::parse(header_bytes_reader).expect("invalid header data length");
        assert_eq!(parsed_header.version, 1);
        assert_eq!(parsed_header.content_type, Some("CJDHT"))
    }

    #[test]
    fn test_data_header_serialize() {
        let header_bytes = hex::decode("10000100").expect("invalid hex string");
        let data_header = DataHeader { version: 1, content_type: Some("CJDHT") };
        let serialized_header = data_header.serialize().expect("invalid content type");
        assert_eq!(header_bytes, serialized_header);
    }
}
