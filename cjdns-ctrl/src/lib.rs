//! Parsing/serializing CTRL messages

pub use cjdns_bytes::{ParseError, SerializeError};
use cjdns_hdr::SwitchHeader;

#[derive(Clone, Debug)]
pub struct CtrlMessage {
    pub msg_type: CtrlMessageType,
    pub version: u8,
    pub key: Option<String>, //TODO put proper type here instead of `String`
    pub err_type: Option<String>, //TODO put proper type here instead of `String`
    pub switch_header: Option<SwitchHeader>,
    pub nonce: Option<String>, //TODO put proper type here instead of `String`
    pub additional: Vec<u8>, //TODO is it proper type?
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CtrlMessageType {
    Error, Ping, Pong, KeyPing, KeyPong
}

impl CtrlMessage {
    pub fn parse(_bytes: &[u8]) -> Result<Self, ParseError> {
        todo!()
    }

    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        todo!()
    }
}