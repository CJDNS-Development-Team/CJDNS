//! Parsing and serialization logic for cjdns route header, which is sent from the cjdns engine lower half.

use std::convert::TryFrom;

use cjdns_bytes::{ParseError, SerializeError};
use cjdns_bytes::{Reader, Writer};
use cjdns_keys::{CJDNSPublicKey, CJDNS_IP6};

use crate::switch_header::SwitchHeader;

const ZERO_PUBLIC_KEY_BYTES: [u8; 32] = [0; 32];
const ZERO_IP6_BYTES: [u8; 16] = [0; 16];
const INCOMING_FRAME: u8 = 1;
const CONTROL_FRAME: u8 = 2;

/// Deserialized route header struct.
///
/// `public_key` and `ip6` are optional. That is because route header has same structure for both control and incoming frames.
/// So if it is a control frame, then `public_key` and `ip6` fields should both have None value. Sometimes `public_key` can be None for
/// incoming frames, but in that case ip6 will always have some value. Otherwise, header is considered invalid and won't be serialized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHeader {
    pub public_key: Option<CJDNSPublicKey>,
    pub ip6: Option<CJDNS_IP6>,
    pub version: u32,
    pub switch_header: SwitchHeader,
    pub is_incoming: bool,
    pub is_ctrl: bool,
}

impl RouteHeader {
    /// Size of serialized `RouteHeader`
    pub const SIZE: usize = 68;

    /// Parses raw bytes into `RouteHeader` struct.
    ///
    /// Result in error in several situations:
    /// * if input byte length isn't equal to [RouteHeader::SIZE](struct.RouteHeader.html#associatedconstant.SIZE);
    /// * if parsing provided switch header bytes ended up with an error;
    /// * if ip6 bytes or public key bytes are invalid for ip6 initialization;
    /// * if ip6 derived from public key isn't equal to ip6 created from input bytes;
    /// * if "[is_ctrl](struct.RouteHeader.html#structfield.is_ctrl) - [public_key](struct.RouteHeader.html#structfield.public_key) - [ip6](struct.RouteHeader.html#structfield.ip6)" invariant is not met;
    /// * if flag for message type states not control, nor incoming frame.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let mut data_reader = Reader::new(data);
        let (pk_bytes, header_bytes, version, flags, _zeroes, ip6_bytes) = data_reader
            .read(Self::SIZE, |r| {
                let pk_bytes = r.read_array_32()?;
                let header_bytes = r.read_slice(SwitchHeader::SIZE)?;
                let version = r.read_u32_be()?;
                let flags = r.read_u8()?;
                // padding
                let zeroes = r.read_slice(3)?;
                let ip6_bytes = r.read_slice(16)?;
                Ok((pk_bytes, header_bytes, version, flags, zeroes, ip6_bytes))
            })
            .map_err(|_| ParseError::InvalidPacketSize)?;

        let public_key = if ZERO_PUBLIC_KEY_BYTES == pk_bytes {
            None
        } else {
            Some(CJDNSPublicKey::from(pk_bytes))
        };
        let switch_header = SwitchHeader::parse(header_bytes)?;
        let is_ctrl = flags & CONTROL_FRAME != 0;
        let is_incoming = flags & INCOMING_FRAME != 0;
        let ip6_from_bytes = if ip6_bytes == &ZERO_IP6_BYTES {
            None
        } else {
            let ip6 = CJDNS_IP6::try_from(ip6_bytes).map_err(|_| ParseError::InvalidData("can't create ip6 from received bytes"))?;
            Some(ip6)
        };
        // checking invariants
        if is_ctrl && public_key.is_some() {
            return Err(ParseError::InvalidInvariant("public key can not be defined in control frame"));
        }
        if is_ctrl && ip6_from_bytes.is_some() {
            return Err(ParseError::InvalidInvariant("ip6 is defined for control frame"));
        }
        if !is_ctrl && ip6_from_bytes.is_none() {
            return Err(ParseError::InvalidInvariant("ip6 is not defined for non-control frame"));
        }
        if let Some(public_key) = public_key.as_ref() {
            if let Some(ip6_from_bytes) = ip6_from_bytes.as_ref() {
                let ip6_from_key = CJDNS_IP6::try_from(public_key).map_err(|_| ParseError::InvalidData("can't create ip6 from public key"))?;
                if ip6_from_key != *ip6_from_bytes {
                    return Err(ParseError::InvalidData("ip6 derived from public key is not equal to ip6 from header bytes"));
                }
            }
        }
        Ok(RouteHeader {
            public_key,
            ip6: ip6_from_bytes,
            version,
            switch_header,
            is_incoming,
            is_ctrl,
        })
    }

    /// Serialized `RouteHeader` instance.
    ///
    /// `RouteHeader` type can be instantiated directly, without using [parse](struct.RouteHeader.html#method.parse) method.
    /// That's why serialization can result in errors. For example, if invariants stated in [parse](struct.RouteHeader.html#method.parse) method are not met or
    /// switch header serialization failed, then route header serialization ends up with an error.
    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        // checking invariants, because `RouteHeader` can be instantiated directly
        if self.is_ctrl && self.public_key.is_some() {
            return Err(SerializeError::InvalidInvariant("public key can not be defined in control frame"));
        }
        if self.is_ctrl && self.ip6.is_some() {
            return Err(SerializeError::InvalidInvariant("ip6 is defined for control frame"));
        }
        if !self.is_ctrl && self.ip6.is_none() {
            return Err(SerializeError::InvalidInvariant("ip6 is not defined for non-control frame"));
        }
        if let Some(public_key) = self.public_key.as_ref() {
            if let Some(ip6) = self.ip6.as_ref() {
                let ip6_from_key = CJDNS_IP6::try_from(public_key).or(Err(SerializeError::InvalidData("can't create ip6 from public key")))?;
                if ip6_from_key != *ip6 {
                    return Err(SerializeError::InvalidData("ip6 derived from public key is not equal to ip6 from header bytes"));
                }
            }
        }
        let public_key_bytes = self.public_key.as_ref().map(|key| &*(*key)).unwrap_or_else(|| ZERO_PUBLIC_KEY_BYTES.as_ref());
        let switch_header_bytes = self.switch_header.serialize()?;
        let flags = {
            let mut ret_flag = 0;
            if self.is_ctrl {
                ret_flag += CONTROL_FRAME;
            }
            if self.is_incoming {
                ret_flag += INCOMING_FRAME;
            }
            ret_flag
        };
        let pad_bytes = &[0u8; 3];
        let ip6_bytes = self.ip6.as_ref().map(|ip6| &*(*ip6)).unwrap_or_else(|| ZERO_IP6_BYTES.as_ref());

        let mut data_writer = Writer::with_capacity(Self::SIZE);
        data_writer.write_slice(public_key_bytes);
        data_writer.write_slice(&switch_header_bytes);
        data_writer.write_u32_be(self.version);
        data_writer.write_u8(flags);
        data_writer.write_slice(pad_bytes);
        data_writer.write_slice(ip6_bytes);

        Ok(data_writer.into_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use cjdns_core::RoutingLabel;
    use cjdns_keys::{CJDNSPublicKey, CJDNS_IP6};

    use crate::route_header::{CONTROL_FRAME, INCOMING_FRAME};
    use crate::switch_header::SwitchHeader;

    use super::RouteHeader;

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("invalid hex string")
    }

    fn instantiate_header(pk: Option<CJDNSPublicKey>, ip: Option<CJDNS_IP6>, is_ctrl: bool, is_incoming: bool) -> RouteHeader {
        RouteHeader {
            public_key: pk,
            ip6: ip,
            version: 0,
            switch_header: SwitchHeader {
                label: RoutingLabel::try_from("0000.0000.0000.0013").expect("invalid label string"),
                congestion: 0,
                suppress_errors: false,
                version: 1,
                label_shift: 8,
                penalty: 0,
            },
            is_ctrl,
            is_incoming,
        }
    }

    #[test]
    fn test_route_header_parse() {
        let test_data = decode_hex(
            "a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f0000000000000013004800000000000001000000fc928136dc1fe6e04ef6a6dd7187b85f",
        );
        let parsed_header = RouteHeader::parse(&test_data).expect("invalid header bytes");
        let serialized_header = parsed_header.serialize().expect("invalid header");
        assert_eq!(
            parsed_header,
            RouteHeader {
                public_key: CJDNSPublicKey::try_from("3fdqgz2vtqb0wx02hhvx3wjmjqktyt567fcuvj3m72vw5u6ubu70.k").ok(),
                ip6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f").ok(),
                version: 0,
                switch_header: SwitchHeader {
                    label: RoutingLabel::try_from("0000.0000.0000.0013").expect("invalid label string"),
                    congestion: 0,
                    suppress_errors: false,
                    version: 1,
                    label_shift: 8,
                    penalty: 0,
                },
                is_incoming: true,
                is_ctrl: false,
            }
        );
        assert_eq!(serialized_header, test_data);
    }

    #[test]
    fn test_parse_invalid() {
        let invalid_hex_data = [
            // invalid len
            "ff00112233445566778899aabbccddee",
            "a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f0000000000000013004800000000000001000000fc928136dc1fe6e04ef6a6dd7187b85f000111",
            // invalid switch header
            "a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f000000000000001300c800000000000001000000fc928136dc1fe6e04ef6a6dd7187b85f",
            // invalid invariants
            // public key is some, but the message is "control"
            "a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f0000000000000013004800000000000002000000fc928136dc1fe6e04ef6a6dd7187b85f",
            // message is "control", but ip6 is some
            "00000000000000000000000000000000000000000000000000000000000000000000000000000013004800000000000002000000fc928136dc1fe6e04ef6a6dd7187b85f",
            // message is not "control", but ip6 is none
            "a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f000000000000001300480000000000000100000000000000000000000000000000000000",
            // ip6 from public key is not equal to ip6 from bytes
            "bd5ef1051e8f5e607f8d420711b4853b14b6c628bb90ba9695169a552a22c07b0000000000000013004800000000000001000000fcf5c1ecbe679ad51f6cf31b5d7437b0",
        ];
        for hex_header in invalid_hex_data.iter() {
            let invalid_bytes = decode_hex(hex_header);
            assert!(RouteHeader::parse(&invalid_bytes).is_err());
        }
    }

    #[test]
    fn test_serialize() {
        let invalid_headers = [
            // public key is some, but message is control
            instantiate_header(
                CJDNSPublicKey::try_from("3fdqgz2vtqb0wx02hhvx3wjmjqktyt567fcuvj3m72vw5u6ubu70.k").ok(),
                CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f").ok(),
                true,
                false,
            ),
            // ip6 is some but message is control
            instantiate_header(None, CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f").ok(), true, false),
            // message is incoming, but ip6 is none
            instantiate_header(
                CJDNSPublicKey::try_from("3fdqgz2vtqb0wx02hhvx3wjmjqktyt567fcuvj3m72vw5u6ubu70.k").ok(),
                None,
                false,
                true,
            ),
            // ip6 from public_key != ip6 from bytes
            instantiate_header(
                CJDNSPublicKey::try_from("xpr2z2s3hnr0qzpk2u121uqjv15dc335v54pccqlqj6c5p840yy0.k").ok(),
                CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f").ok(),
                false,
                true,
            ),
        ];
        for header in invalid_headers.iter() {
            assert!(header.serialize().is_err());
        }

        // is_ctrl == is_incoming
        let valid_cases = [
            instantiate_header(None, CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f").ok(), false, false),
            instantiate_header(None, None, true, true),
        ];
        for valid_header in valid_cases.iter() {
            assert!(valid_header.serialize().is_ok());
        }
    }

    #[test]
    fn test_flag_checks() {
        let flag_idx = 48;
        let test_data = [
            (
                "a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f0000000000000013004800000000000001000000fc928136dc1fe6e04ef6a6dd7187b85f",
                false,
                true,
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000000000000000001300480000000000000200000000000000000000000000000000000000",
                true,
                false,
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000000000000000001300480000000000000300000000000000000000000000000000000000",
                true,
                true,
            ),
            (
                "a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f0000000000000013004800000000000000000000fc928136dc1fe6e04ef6a6dd7187b85f",
                false,
                false,
            ),
        ];
        for &(hex_data, is_ctrl, is_incoming) in test_data.iter() {
            // parse test
            let test_bytes = decode_hex(hex_data);
            let parsed_header = RouteHeader::parse(&test_bytes).expect("invalid header");
            assert_eq!(parsed_header.is_incoming, is_incoming);
            assert_eq!(parsed_header.is_ctrl, is_ctrl);
            // serialize test
            let serialized_header = parsed_header.serialize().expect("invalid header");
            let serialized_flag_byte = serialized_header[flag_idx];
            let test_flag_byte = {
                let mut byte = 0;
                if is_ctrl {
                    byte += CONTROL_FRAME;
                }
                if is_incoming {
                    byte += INCOMING_FRAME;
                }
                byte
            };
            assert_eq!(serialized_flag_byte, test_flag_byte);
        }
    }
}
