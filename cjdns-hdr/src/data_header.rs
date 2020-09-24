//! Logic for parsing and serializing the data header, providing type of content

use cjdns_bytes::{ParseError, SerializeError, SizePredicate};
use cjdns_bytes::{Reader, Writer};

use crate::content_type::ContentType;

/// Deserialized data header struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataHeader {
    pub version: u8,
    pub content_type: ContentType,
}

impl DataHeader {
    /// Size of serialized `DataHeader`
    pub const SIZE: usize = 4;

    /// Current version of `DataHeader` which is automatically set, if version is not specified during serialization.
    pub const CURRENT_VERSION: u8 = 1;

    /// Parses raw bytes into `DataHeader` struct.
    ///
    /// Results in error if input bytes length isn't equal to 4, which is current size of serialized header.
    ///
    /// `DataHeader` bytes have a following structure : one byte each for version and padding, two bytes for content number.
    /// Content number is a u16 number which is a numerical representation of `ContentType`.
    /// If content number is not defined in `ContentType`, default `ContentType` variant will be used.
    /// *Note*: default `ContentType` variant is a temporary solution.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let mut data_reader = Reader::new(data);
        let (version_with_flags, pad, content_type_code) = data_reader
            .read(SizePredicate::Exact(Self::SIZE), |r| {
                let version_with_flags = r.read_u8()?;
                let pad = r.read_u8()?;
                let content_type_code = r.read_u16_be()?;
                Ok((version_with_flags, pad, content_type_code))
            })
            .map_err(|_| ParseError::InvalidPacketSize)?;

        let version = version_with_flags >> 4;
        // Zero-padding
        if pad != 0 {
            return Err(ParseError::InvalidData("non-zero padding"));
        }
        let content_type = ContentType::from_u16(content_type_code);
        Ok(DataHeader { version, content_type })
    }

    /// Serializes `DataHeader` instance.
    ///
    /// `DataHeader` type can be instantiated directly, without using `parse` method.
    /// That's why serialization can result in errors. If header `version` is greater than 15, then serialization fails,
    /// because `version` is only a 4-bit field in `DataHeader`.
    /// Also serialization fails if no suitable 16-bit content type code was found.
    ///
    /// If `DataHeader` was instantiated with 0 `version`, header will be parsed with version equal to [current version](struct.DataHeader.html#associatedconstant.CURRENT_VERSION).
    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        if self.version > 15 {
            return Err(SerializeError::InvalidInvariant("version value can't take more than 4 bits"));
        }
        let mut data_writer = Writer::with_capacity(Self::SIZE);
        let version_with_flags = if self.version == 0 { Self::CURRENT_VERSION << 4 } else { self.version << 4 };
        if self.content_type == ContentType::Other {
            return Err(SerializeError::InvalidData("content type is not recognized or not preserved"));
        }
        let content_type_code = self.content_type.try_to_u16().ok_or(SerializeError::InvalidData(
            "content type can't be serialized into bytes slice with respected length",
        ))?;

        data_writer.write_u8(version_with_flags);
        data_writer.write_u8(0); // zero-padding
        data_writer.write_u16_be(content_type_code);

        Ok(data_writer.into_vec())
    }
}

impl Default for DataHeader {
    fn default() -> Self {
        DataHeader {
            version: Self::CURRENT_VERSION,
            content_type: ContentType::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ContentType, DataHeader};

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("invalid hex string")
    }

    fn instantiate_header(version: u8, content_type: ContentType) -> DataHeader {
        DataHeader { version, content_type }
    }

    #[test]
    fn test_base() {
        let test_data = decode_hex("10000100");

        let parsed_header = DataHeader::parse(&test_data).expect("invalid header data length");
        let serialized_header = parsed_header.serialize().expect("invalid header");

        assert_eq!(parsed_header.version, 1);
        assert_eq!(parsed_header.content_type, ContentType::Cjdht);
        assert_eq!(serialized_header, test_data);
    }

    #[test]
    fn test_parse_invalid_length() {
        let invalid_hex_data = [
            // invalid length
            "1000",
            "000110",
            "1010101010",
        ];
        for hex_header in invalid_hex_data.iter() {
            let invalid_bytes = decode_hex(hex_header);
            assert!(DataHeader::parse(&invalid_bytes).is_err());
        }
    }

    #[test]
    fn test_parse_unknown_content_type() {
        let hex_data = [
            // content type number out of IP6 range - 32000
            "10007d00", // content type number in IP6 range - 100
            "10000064", // content type out of available range (greater than 0x8000)
            "10008001", "1000fff0",
        ];
        for data in hex_data.iter() {
            let bytes_data = decode_hex(data);
            let data_header = DataHeader::parse(&bytes_data).expect("invalid header data");
            // read comment at the beginning of the module
            assert_eq!(data_header.content_type, ContentType::Other);
        }
    }

    #[test]
    fn test_serialize() {
        let valid_headers = [
            instantiate_header(10, ContentType::Ip6Ah),
            instantiate_header(15, ContentType::Cjdht),
            instantiate_header(0, ContentType::Iptun),
        ];
        for header in valid_headers.iter() {
            assert!(header.serialize().is_ok());
        }

        let invalid_headers = [
            // invalid version
            instantiate_header(16, ContentType::Ip6Encap),
            // content type number > u16
            instantiate_header(0, ContentType::Ctrl),
            // even default fails. Read comment at the beginning of the module
            instantiate_header(10, ContentType::Other),
        ];
        for header in invalid_headers.iter() {
            assert!(header.serialize().is_err());
        }
    }
}
