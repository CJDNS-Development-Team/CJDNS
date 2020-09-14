use std::collections::HashMap;

use cjdns_bytes::{ParseError, Reader};
use cjdns_core::keys::CJDNSPublicKey;

use crate::control_message::CtrlMessageType;

/// Data for connection type messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionData {
    pub version: u32,
    pub key: Option<CJDNSPublicKey>,
    pub content: Vec<u8>,
}

lazy_static! {
    static ref TYPE_TO_META: HashMap<CtrlMessageType, ConnectionMessageMeta> = {
        let mut m = HashMap::new();
        m.insert(
            CtrlMessageType::Ping,
            ConnectionMessageMeta {
                magic: 0x09f91102,
                min_size: 8,
                max_size: 256,
                header_size: 8,
            },
        );
        m.insert(
            CtrlMessageType::Pong,
            ConnectionMessageMeta {
                magic: 0x9d74e35b,
                min_size: 8,
                max_size: 256,
                header_size: 8,
            },
        );
        m.insert(
            CtrlMessageType::KeyPing,
            ConnectionMessageMeta {
                magic: 0x01234567,
                min_size: 40,
                max_size: 104,
                header_size: 40,
            },
        );
        m.insert(
            CtrlMessageType::KeyPong,
            ConnectionMessageMeta {
                magic: 0x89abcdef,
                min_size: 40,
                max_size: 104,
                header_size: 40,
            },
        );
        m
    };
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct ConnectionMessageMeta {
    magic: u32,
    // Todo unused in js
    min_size: u8,
    max_size: u16,
    header_size: u8,
}

impl ConnectionData {
    pub fn parse(bytes: &[u8], conn_type: CtrlMessageType) -> Result<Self, ParseError> {
        // todo 1 length min?
        let mut reader = Reader::new(bytes);
        let encoded_magic = reader.read_u32_be().expect("invalid message size");
        let original_magic = TYPE_TO_META.get(&conn_type).expect("unknown connection type").magic;
        if encoded_magic != original_magic {
            return Err(ParseError::InvalidData("invalid encoded connection magic"));
        }
        let version = reader.read_u32_be().expect("invalid message size");
        let (key, content) = {
            // todo 3. Which style is better: if/ if let / match
            let key = match conn_type {
                CtrlMessageType::KeyPing | CtrlMessageType::KeyPong => {
                    let key_bytes = reader.read_array_32().expect("invalid message size");
                    Some(CJDNSPublicKey::from(key_bytes))
                },
                _ => None
            };
            let content = reader.read_all_mut().to_vec();
            (key, content)
        };
        Ok(ConnectionData { version, key, content })
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use hex;

    use cjdns_core::keys::CJDNSPublicKey;

    use super::ConnectionData;
    use crate::control_message::CtrlMessageType;

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("invalid hex string")
    }

    #[test]
    fn test_ping() {
        let test_bytes = decode_hex("09f91102000000124d160b1eee2929e12e19a3b1");
        let parsed_conn = ConnectionData::parse(&test_bytes, CtrlMessageType::Ping).expect("invalid conn data");
        assert_eq!(
            parsed_conn,
            ConnectionData {
                version: 18,
                key: None,
                content: decode_hex("4d160b1eee2929e12e19a3b1")
            }
        )
    }

    #[test]
    fn test_key_ping() {
        let test_bytes = decode_hex("0123456700000012a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f02e29842b42aedb6bce2ead3");
        let parsed_conn = ConnectionData::parse(&test_bytes, CtrlMessageType::KeyPing).expect("invalid conn data");
        assert_eq!(
            parsed_conn,
            ConnectionData {
                version: 18,
                key: CJDNSPublicKey::try_from("3fdqgz2vtqb0wx02hhvx3wjmjqktyt567fcuvj3m72vw5u6ubu70.k".to_string()).ok(),
                content: decode_hex("02e29842b42aedb6bce2ead3")
            }
        )
    }
}
