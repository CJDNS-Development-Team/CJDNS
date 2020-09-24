use cjdns_bytes::{ParseError, Reader, SerializeError, Writer};
use cjdns_keys::CJDNSPublicKey;

use crate::CtrlMessageType;

/// Body data for ping type control messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingData {
    pub version: u32,
    pub key: Option<CJDNSPublicKey>,
    pub content: Vec<u8>,
}

impl PingData {
    /// Minimum ping data size
    pub const MIN_SIZE: usize = 8;

    /// Parses raw bytes into `PingData`.
    ///
    /// Result in error in several situations:
    /// * input bytes length is less than `PingData::MIN_SIZE`
    /// * encoded ping magic is not equal to magic defined for the inputted `ping`
    /// * if input `ping` is sort of key pings, but bytes data size is too small to create cjdns public key from it
    pub fn parse(bytes: &[u8], ping: CtrlMessageType) -> Result<Self, ParseError> {
        if bytes.len() < Self::MIN_SIZE {
            return Err(ParseError::InvalidPacketSize);
        }
        let mut reader = Reader::new(bytes);
        // Validating ping data magic
        {
            let encoded_magic = reader.read_u32_be().expect("invalid message size");
            let original_magic = Self::ping_to_magic(ping);
            if encoded_magic != original_magic {
                return Err(ParseError::InvalidData("invalid encoded connection magic"));
            }
        }
        let version = reader.read_u32_be().expect("invalid message size");
        let key = match ping {
            CtrlMessageType::KeyPing | CtrlMessageType::KeyPong => {
                let key_bytes = reader.read_array_32().or(Err(ParseError::InvalidPacketSize))?;
                Some(CJDNSPublicKey::from(key_bytes))
            }
            _ => None,
        };
        let content = reader.read_remainder().to_vec();
        Ok(PingData { version, key, content })
    }

    /// Serialized `PingData` instance.
    ///
    /// `PingData` type can be instantiated directly, without using `parse` method.
    /// That's why serialization can result in errors in several situations:
    /// * instance has version of 0
    /// * `ping` variable, which is defined by control message [serialize](struct.CtrlMessage.html#method.serialize) method, has key ping/pong type, but `key` is not specified in the data instance
    pub fn serialize(&self, ping: CtrlMessageType) -> Result<Vec<u8>, SerializeError> {
        if self.version == 0 {
            return Err(SerializeError::InvalidData("version should be greater than 0"));
        }
        if (ping == CtrlMessageType::KeyPing || ping == CtrlMessageType::KeyPong) && self.key.is_none() {
            return Err(SerializeError::InvalidInvariant("key should be specified for key ping/pong messages"));
        }
        let ping_magic = Self::ping_to_magic(ping);

        // either min size or min size plus cjdns public key size
        let writer_size = self.key.as_ref().map_or(Self::MIN_SIZE, |_| Self::MIN_SIZE + 32);
        let mut writer = Writer::with_capacity(writer_size);
        writer.write_u32_be(ping_magic);
        writer.write_u32_be(self.version);
        if let Some(key) = &self.key {
            writer.write_slice(key);
        }
        writer.write_slice(&self.content);

        Ok(writer.into_vec())
    }

    fn ping_to_magic(ping: CtrlMessageType) -> u32 {
        match ping {
            CtrlMessageType::Ping => 0x09f91102,
            CtrlMessageType::Pong => 0x9d74e35b,
            CtrlMessageType::KeyPing => 0x01234567,
            CtrlMessageType::KeyPong => 0x89abcdef,
            _ => unreachable!("provided non ping message type"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use cjdns_keys::CJDNSPublicKey;

    use super::PingData;
    use crate::control_message::CtrlMessageType;

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("invalid hex string")
    }

    fn instantiate_ping_data(version: u32, key: Option<CJDNSPublicKey>) -> PingData {
        PingData { version, key, content: vec![] }
    }

    #[test]
    fn test_ping() {
        let test_bytes = decode_hex("09f91102000000124d160b1eee2929e12e19a3b1");
        let parsed_ping = PingData::parse(&test_bytes, CtrlMessageType::Ping).expect("invalid ping data");
        let serialized_ping = parsed_ping.serialize(CtrlMessageType::Ping).expect("invalid ping data");
        assert_eq!(
            parsed_ping,
            PingData {
                version: 18,
                key: None,
                content: decode_hex("4d160b1eee2929e12e19a3b1")
            }
        );
        assert_eq!(serialized_ping, test_bytes);
    }

    #[test]
    fn test_pong() {
        let test_bytes = decode_hex("9d74e35b0000001280534c66df69e44b496d5bc8");
        let parsed_ping = PingData::parse(&test_bytes, CtrlMessageType::Pong).expect("invalid ping data");
        let serialized_ping = parsed_ping.serialize(CtrlMessageType::Pong).expect("invalid ping data");
        assert_eq!(
            parsed_ping,
            PingData {
                version: 18,
                key: None,
                content: decode_hex("80534c66df69e44b496d5bc8")
            }
        );
        assert_eq!(serialized_ping, test_bytes);
    }

    #[test]
    fn test_key_ping() {
        let test_bytes = decode_hex("0123456700000012a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f02e29842b42aedb6bce2ead3");
        let parsed_ping = PingData::parse(&test_bytes, CtrlMessageType::KeyPing).expect("invalid ping data");
        let serialized_ping = parsed_ping.serialize(CtrlMessageType::KeyPing).expect("invalid ping data");
        assert_eq!(
            parsed_ping,
            PingData {
                version: 18,
                key: CJDNSPublicKey::try_from("3fdqgz2vtqb0wx02hhvx3wjmjqktyt567fcuvj3m72vw5u6ubu70.k").ok(),
                content: decode_hex("02e29842b42aedb6bce2ead3")
            }
        );
        assert_eq!(serialized_ping, test_bytes);
    }

    #[test]
    fn test_key_pong() {
        let test_bytes = decode_hex("89abcdef000000126bd2e8e50faca3d987623d6a043c17c0d9e9004e145f8dd90615d34edbb36d6a02e29842b42aedb6bce2ead3");
        let parsed_ping = PingData::parse(&test_bytes, CtrlMessageType::KeyPong).expect("invalid ping data");
        let serialized_ping = parsed_ping.serialize(CtrlMessageType::KeyPong).expect("invalid ping data");
        assert_eq!(
            parsed_ping,
            PingData {
                version: 18,
                key: CJDNSPublicKey::try_from("cmnkylz1dx8mx3bdxku80yw20gqmg0s9nsrusdv0psnxnfhqfmu0.k").ok(),
                content: decode_hex("02e29842b42aedb6bce2ead3")
            }
        );
        assert_eq!(serialized_ping, test_bytes);
    }

    #[test]
    fn test_parse_invalid() {
        let invalid_data = [
            // invalid length for non key ping messages
            ("1122334455", CtrlMessageType::Ping),
            // invalid magic
            ("9d74e35b00000001", CtrlMessageType::KeyPong),
            ("89abcdef000000aa", CtrlMessageType::Ping),
            // invalid length for key ping messages
            ("0123456700aabb03a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde19847", CtrlMessageType::KeyPing),
            ("89abcdef700aabb03a331ebbed8d92ac03b10efed3e389", CtrlMessageType::KeyPong),
        ];
        for &(bytes, ping) in invalid_data.iter() {
            let test_bytes = decode_hex(bytes);
            assert!(PingData::parse(&test_bytes, ping).is_err());
        }
    }

    #[test]
    fn test_serialize_invalid() {
        let invalid_data = [
            // zero version
            (instantiate_ping_data(0, None), CtrlMessageType::Ping),
            // zero key for key ping type message
            (instantiate_ping_data(1, None), CtrlMessageType::KeyPing),
            (instantiate_ping_data(1, None), CtrlMessageType::KeyPong),
        ];
        for (ping_instance, ping_type) in invalid_data.iter() {
            assert!(ping_instance.serialize(*ping_type).is_err());
        }
    }
}
