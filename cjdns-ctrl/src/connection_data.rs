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
    min_size: u8,
    max_size: u16,
    header_size: u8,
}

impl ConnectionData {
    pub fn parse(bytes: &[u8], conn_type: CtrlMessageType) -> Result<Self, ParseError> {
        // todo length min 40?
        let mut reader = Reader::new(bytes);
        let encoded_magic = reader.read_u32_be().expect("invalid message size");
        let original_magic = TYPE_TO_META.get(&conn_type).expect("unknown connection type").magic;
        if encoded_magic != original_magic {
            return Err(ParseError::InvalidData("invalid encoded connection magic"));
        }
        let version = reader.read_u32_be().expect("invalid message size");
        let (key, content) = {
            let key = if conn_type == CtrlMessageType::KeyPing || conn_type == CtrlMessageType::KeyPong {
                let key_bytes = reader.read_array_32().expect("invalid message size");
                Some(CJDNSPublicKey::from(key_bytes))
            } else {
                None
            };
            let content = reader.read_all_mut().expect("broken reader indexing").to_vec();
            (key, content)
        };
        Ok(ConnectionData { version, key, content })
    }
}
