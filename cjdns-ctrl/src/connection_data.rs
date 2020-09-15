use std::collections::HashMap;

use cjdns_bytes::{ParseError, Reader, SerializeError, Writer};
use cjdns_core::keys::{BytesRepr, CJDNSPublicKey};

use crate::control_message::CtrlMessageType;

/// Body data for ping type control messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingData {
    pub version: u32,
    pub key: Option<CJDNSPublicKey>,
    pub content: Vec<u8>,
}

// Todo check of CtrlMessageType being Error required?
impl PingData {
    /// Minimum ping data size
    pub const MIN_SIZE: usize = 8;

    /// Parses raw bytes into `PingData`.
    ///
    /// Result in error in several situations:
    /// * input bytes length is less than `PingData::MIN_SIZE`
    /// * encoded ping magic is not equal to magic defined for the inputted `ping`
    /// * if input `ping` is sort of key pings, but bytes size is too small to create cjdns public key from them
    pub fn parse(bytes: &[u8], ping: CtrlMessageType) -> Result<Self, ParseError> {
        if bytes.len() < Self::MIN_SIZE {
            return Err(ParseError::InvalidPacketSize);
        }
        let mut reader = Reader::new(bytes);
        let encoded_magic = reader.read_u32_be().expect("invalid message size");
        let original_magic = Self::ping_to_magic(ping);
        if encoded_magic != original_magic {
            return Err(ParseError::InvalidData("invalid encoded connection magic"));
        }
        let version = reader.read_u32_be().expect("invalid message size");
        let (key, content) = {
            let key = match ping {
                CtrlMessageType::KeyPing | CtrlMessageType::KeyPong => {
                    let key_bytes = reader.read_array_32().or(Err(ParseError::InvalidPacketSize))?;
                    Some(CJDNSPublicKey::from(key_bytes))
                }
                _ => None,
            };
            let content = reader.read_all_mut().to_vec();
            (key, content)
        };
        Ok(PingData { version, key, content })
    }

    // todo 2 ask alex if it is ok not to check conn type? More strict use `&CtrlMessage{ msg_type, ..}: &CtrlMessage` instead of `CtrlMessageType`?
    // todo 1 enough invariant checks?
    pub fn serialize(&self, ping: CtrlMessageType) -> Result<Vec<u8>, SerializeError> {
        if self.version == 0 {
            return Err(SerializeError::InvalidData("version should be greater than 0"));
        }
        let ping_magic = Self::ping_to_magic(ping);

        // either min size or min size plus size of cjdns public key
        let writer_size = self.key.as_ref().map_or(Self::MIN_SIZE, |_| Self::MIN_SIZE + 32);
        let mut writer = Writer::with_capacity(writer_size);
        writer.write_u32_be(ping_magic);
        writer.write_u32_be(self.version);
        if let Some(key) = &self.key {
            writer.write_slice(&key.bytes());
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

    use hex;

    use cjdns_core::keys::CJDNSPublicKey;

    use super::PingData;
    use crate::control_message::CtrlMessageType;

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("invalid hex string")
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
    fn test_key_ping() {
        let test_bytes = decode_hex("0123456700000012a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f02e29842b42aedb6bce2ead3");
        let parsed_ping = PingData::parse(&test_bytes, CtrlMessageType::KeyPing).expect("invalid ping data");
        let serialized_ping = parsed_ping.serialize(CtrlMessageType::KeyPing).expect("invalid ping data");
        assert_eq!(
            parsed_ping,
            PingData {
                version: 18,
                key: CJDNSPublicKey::try_from("3fdqgz2vtqb0wx02hhvx3wjmjqktyt567fcuvj3m72vw5u6ubu70.k".to_string()).ok(),
                content: decode_hex("02e29842b42aedb6bce2ead3")
            }
        );
        assert_eq!(serialized_ping, test_bytes);
    }
}
